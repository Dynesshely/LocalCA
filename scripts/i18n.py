#!/usr/bin/env python3
"""
Message catalogues without GNU gettext.

LocalCA commits both its ``.po`` sources and the compiled ``.mo`` files the
runtime reads, and the machines that build it (the python:3.12-slim image, this
workstation) do not ship ``msgfmt``. Rather than add gettext to every build
environment, this script does the three things the workflow actually needs:

    extract   list every `_('...')` msgid in the Python sources
    compile   turn locale/<locale>/LC_MESSAGES/django.po into django.mo
    check     fail if a msgid in the code has no translation

The `.po` stays the source of truth and stays hand-editable, and it keeps the
standard format, so `django-admin makemessages` / `compilemessages` remain a
drop-in replacement wherever GNU gettext *is* available.
"""

from __future__ import annotations

import argparse
import ast
import re
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCALE_DIR = PROJECT_ROOT / 'localca_project' / 'locale'

#: Directories holding Python that may contain translatable strings.
SOURCE_DIRS = [PROJECT_ROOT / 'localca_project']

#: Suffixes that are not application code.
SKIP_PARTS = {'migrations', '__pycache__', 'venv', '.venv', 'tests', 'tests_import',
              'tests_api', 'tests_vault', 'tests_revocation'}

#: Calls whose first argument is a *user-visible* message. Anything a developer
#: reads (log records, docstrings, internal ValueErrors) is deliberately absent.
TRANSLATABLE_CALLS = {
    # Both the plain name and every alias the codebase imports it under: a
    # module-level lookup table has to use `gettext_lazy`, and it is usually
    # imported as `_lazy` to say so at the call site.
    '_', 'gettext', 'gettext_lazy', '_lazy',
    'ValidationError', 'PlanError', 'KeyUnavailable', 'VaultLocked',
    'VaultPasswordError', 'VaultError', 'BadPassword', 'UnusableUpload',
    'UploadTooLarge',
}


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------

def _iter_sources():
    for base in SOURCE_DIRS:
        for path in sorted(base.rglob('*.py')):
            if SKIP_PARTS & set(path.parts):
                continue
            yield path


def extract_msgids():
    """Every literal msgid passed to a translatable call, plus formatted ones."""
    found = {}
    for path in _iter_sources():
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, 'id', None) or getattr(func, 'attr', None)
            if name not in TRANSLATABLE_CALLS or not node.args:
                continue
            first = node.args[0]
            # `_('a ' 'b')` is one Constant after the parser folds the
            # implicit concatenation; an f-string or a `%` mapping is not.
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.setdefault(first.value, []).append(path)
            elif isinstance(first, ast.JoinedStr):
                raise SystemExit(
                    f'{path}:{node.lineno}: an f-string reaches a translatable call; '
                    'convert it to a named-placeholder msgid')
    return found


# ---------------------------------------------------------------------------
# .po parsing
# ---------------------------------------------------------------------------

class Catalog:
    """A parsed .po file: msgid -> msgstr, plus the header."""

    def __init__(self, header='', entries=None):
        self.header = header
        self.entries = entries or {}

    @classmethod
    def parse(cls, text):
        header = ''
        entries = {}
        msgid = msgstr = None
        mode = None

        def flush():
            # `header` has to be in this list: it is assigned here (the empty
            # msgid is the metadata entry) and read by `parse` afterwards.
            # Without `nonlocal` the assignment would create a local and the
            # metadata — including Content-Type/charset — would be dropped, which
            # makes the compiled catalog undecodable rather than merely wrong.
            nonlocal msgid, msgstr, header
            if msgid is not None:
                value = ''.join(msgstr or [])
                if msgid == '':
                    header = value
                else:
                    entries[msgid] = value
            msgid, msgstr, mode = None, None, None

        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('msgid '):
                if msgid is not None:
                    flush()
                msgid = _unquote(line[6:])
                msgstr = []
                mode = 'id'
            elif line.startswith('msgstr '):
                msgstr = [_unquote(line[7:])]
                mode = 'str'
            elif line.startswith('"'):
                if mode == 'id':
                    msgid += _unquote(line)
                elif mode == 'str':
                    msgstr.append(_unquote(line))
        flush()
        return cls(header, entries)

    def render(self):
        out = ['# LocalCA message catalogue.',
               '# Compiled with scripts/i18n.py (GNU gettext is not required).',
               '#',
               '# msgid is the English source string, so an untranslated entry',
               '# degrades to English rather than to an empty label.',
               'msgid ""',
               'msgstr ""']
        for line in self.header.splitlines():
            out.append(f'"{_escape(line)}\\n"')
        for msgid in sorted(self.entries):
            out.append('')
            out.append(f'msgid "{_escape(msgid)}"')
            if '\n' in self.entries[msgid]:
                out.append('msgstr ""')
                for line in self.entries[msgid].split('\n'):
                    out.append(f'"{_escape(line)}\\n"')
            else:
                out.append(f'msgstr "{_escape(self.entries[msgid])}"')
        return '\n'.join(out) + '\n'


def _unquote(part):
    part = part.strip()
    if not part.startswith('"'):
        return ''
    body = part[1:-1] if part.endswith('"') else part[1:]
    return (body.replace('\\n', '\n').replace('\\t', '\t')
            .replace('\\"', '"').replace('\\\\', '\\'))


def _escape(text):
    return (text.replace('\\', '\\\\').replace('"', '\\"')
            .replace('\n', '\\n').replace('\t', '\\t'))


# ---------------------------------------------------------------------------
# .mo writer
# ---------------------------------------------------------------------------

def write_mo(catalog: Catalog, target: Path):
    """
    Write the GNU MO binary format.

    Layout: a 7-word header, then two parallel tables of (length, offset) pairs
    -- one for the msgids, one for the msgstrs -- then the NUL-terminated string
    data both tables point into. The header's third and fourth words are the
    offsets of the two *tables*, which sit immediately after the header, while
    each table entry's offset is absolute and points at the data. Getting those
    two kinds of offset backwards produces a file CPython rejects with
    "File is corrupt". Entries are sorted by msgid, which is what the C
    implementation's binary search assumes (Python's gettext builds a dict and
    would not care).
    """
    items = sorted(catalog.entries.items())
    items.insert(0, ('', catalog.header))

    count = len(items)
    encoded = [(msgid.encode('utf-8'), msgstr.encode('utf-8'))
               for msgid, msgstr in items]
    # The two data blobs are laid out one after the other, so every offset can
    # only be computed once both lengths are known: the translation blob starts
    # after the *whole* msgid blob, not after the header.
    ids = b''.join(msgid + b'\x00' for msgid, _ in encoded)
    strs = b''.join(msgstr + b'\x00' for _, msgstr in encoded)

    ids_table_offset = 7 * 4
    strs_table_offset = ids_table_offset + count * 8
    data_offset = strs_table_offset + count * 8
    strs_data_offset = data_offset + len(ids)

    id_table = []
    offset = data_offset
    for msgid, _ in encoded:
        id_table.append((len(msgid), offset))
        offset += len(msgid) + 1

    str_table = []
    offset = strs_data_offset
    for _, msgstr in encoded:
        str_table.append((len(msgstr), offset))
        offset += len(msgstr) + 1

    with target.open('wb') as handle:
        handle.write(struct.pack('<7I', 0x950412DE, 0, count, ids_table_offset,
                                 strs_table_offset, 0, 0))
        for length, offset in id_table:
            handle.write(struct.pack('<2I', length, offset))
        for length, offset in str_table:
            handle.write(struct.pack('<2I', length, offset))
        handle.write(ids)
        handle.write(strs)
    return count


def po_paths():
    return sorted(LOCALE_DIR.glob('*/LC_MESSAGES/django.po'))


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_extract(args):
    msgids = extract_msgids()
    if args.json:
        import json
        print(json.dumps(sorted(msgids), ensure_ascii=False, indent=2))
    else:
        for msgid in sorted(msgids):
            print(msgid)
    print(f'# {len(msgids)} distinct msgid(s)', file=sys.stderr)
    return 0


def cmd_compile(args):
    total = 0
    for po in po_paths():
        catalog = Catalog.parse(po.read_text(encoding='utf-8'))
        mo = po.with_suffix('.mo')
        count = write_mo(catalog, mo)
        total += count
        print(f'{po.relative_to(PROJECT_ROOT)} -> {mo.name}  ({count} entries)')
    if not total:
        print('no .po files found', file=sys.stderr)
        return 1
    return 0


def coverage():
    """
    Per catalogue: how many msgids exist, which are missing, which are stale.

    Returned as plain data so both the CLI and the test suite can use it — the
    suite asserts the lists are empty, which is what stops a translation from
    silently falling behind the code it belongs to.
    """
    msgids = set(extract_msgids())
    report = {}
    for po in po_paths():
        catalog = Catalog.parse(po.read_text(encoding='utf-8'))
        translated = {k for k, v in catalog.entries.items() if v}
        report[po] = {
            'total': len(msgids),
            'missing': sorted(msgids - translated),
            'stale': sorted(set(catalog.entries) - msgids),
        }
    return report


def cmd_check(args):
    """
    Fail when a translated string is missing.

    Only the source language is complete by construction (msgid == English), so
    every non-English catalogue must translate every msgid the code uses. An
    entry that is present but empty counts as missing: it would silently render
    the English text inside a Chinese page.
    """
    msgids = set(extract_msgids())
    failed = False
    for po, result in coverage().items():
        print(f'{po.relative_to(PROJECT_ROOT)}: '
              f'{result["total"] - len(result["missing"])}/{result["total"]} translated')
        if result['missing']:
            failed = True
            print(f'  MISSING ({len(result["missing"])}):')
            for msgid in result['missing']:
                print(f'    {msgid!r}')
        if result['stale']:
            failed = True
            print(f'  STALE, no longer in the code ({len(result["stale"])}):')
            for msgid in result['stale']:
                print(f'    {msgid!r}')
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    p_extract = sub.add_parser('extract', help='list translatable msgids from the sources')
    p_extract.add_argument('--json', action='store_true')
    p_extract.set_defaults(func=cmd_extract)

    sub.add_parser('compile', help='compile every .po into a .mo').set_defaults(func=cmd_compile)
    sub.add_parser('check', help='verify every msgid is translated').set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
