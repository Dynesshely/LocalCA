/**
 * Downloading a certificate in any format.
 *
 * One composable rather than the same twenty lines in the hierarchy page and
 * both creation pages. It owns the three decisions a download involves:
 *
 *   * public format  -> fetch it now;
 *   * needs a password -> ask for one, then fetch;
 *   * unprotected    -> ask for an explicit confirmation first, then fetch.
 *
 * A locked vault is a normal, expected answer from the server, not an error: it
 * comes back as 409 + `vault_locked`, and this offers to unlock and then retries
 * the very download that was refused.
 */
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { files } from '@/api'
import { ApiError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useVaultStore } from '@/stores/vault'
import { useToastStore } from '@/stores/toasts'

/** How each format is fetched, keyed by the ids the server advertises. */
const NEEDS = {
  pkcs12: 'password',
  key: 'password',
  'key-plain': 'confirm',
  'pair-zip': 'confirm',
}

export const DOWNLOAD_FALLBACK_NAMES = {
  pem: '.pem',
  der: '.der',
  chain: '-chain.pem',
  p7b: '-chain.p7b',
  pkcs12: '.p12',
  key: '.key',
  'key-plain': '.key',
  'pair-zip': '-pair.zip',
}

export function useCertificateDownload() {
  const { t } = useI18n()
  const auth = useAuthStore()
  const vault = useVaultStore()
  const toasts = useToastStore()

  /** The format whose dialog is open, or null. */
  const pendingFormat = ref(null)
  const pendingCertificate = ref(null)
  const busy = ref(false)

  const formats = () => (auth.downloadFormats.length
    ? auth.downloadFormats
    : Object.keys(NEEDS).map((id) => ({ id, access: id === 'pem' ? 'public' : 'private' })))

  /** What this format asks of the caller: 'password', 'confirm', or ''. */
  function requires(formatId) {
    const spec = formats().find((entry) => entry.id === formatId)
    return spec?.requires || NEEDS[formatId] || ''
  }

  function certificateName(certificate) {
    return certificate.name || certificate.common_name
  }

  async function fetchFormat(certificate, formatId, body) {
    const name = certificateName(certificate)
    return files.format(certificate.serial_number, formatId,
                        `${name}${DOWNLOAD_FALLBACK_NAMES[formatId] || ''}`, body)
  }

  /**
   * Download, or open the dialog that has to come first.
   *
   * @param {object} certificate  a node from the certificate tree
   * @param {string} formatId     an id from /api/meta/
   * @param {object} [body]       answers from the dialog, on the retry path
   */
  async function run(certificate, formatId, body) {
    const requirement = requires(formatId)

    if (requirement && !body) {
      pendingCertificate.value = certificate
      pendingFormat.value = formatId
      return
    }

    busy.value = true
    try {
      const filename = await fetchFormat(certificate, formatId, body)
      toasts.success(t('home.download.success', { name: filename }))
      pendingFormat.value = null
      pendingCertificate.value = null
    } catch (err) {
      if (err instanceof ApiError && err.vaultLocked) {
        // Close this dialog before raising the unlock one. The operator has
        // already answered it -- the password or the confirmation is in `body` --
        // and two stacked dialogs is a worse question than one.
        pendingFormat.value = null
        const target = certificate
        vault.requestUnlock(
          t('home.download.unlockReason', { name: certificateName(certificate) }),
          () => run(target, formatId, body))
        return
      }
      // A refusal the dialog cannot answer -- not your certificate, no vault, no
      // key -- leaves it open over the page with nothing to correct, so it is
      // closed. A 400 is different: the server rejected the password, and the
      // dialog is exactly where that gets fixed.
      if (!(err instanceof ApiError) || err.status !== 400) {
        pendingFormat.value = null
        pendingCertificate.value = null
      }
      toasts.error(err instanceof ApiError ? err.message : String(err))
    } finally {
      busy.value = false
    }
  }

  /** Called by the dialog with whatever it collected. */
  function submit(answers) {
    const certificate = pendingCertificate.value
    const formatId = pendingFormat.value
    if (!certificate || !formatId) {
      return
    }
    return run(certificate, formatId, answers)
  }

  function cancel() {
    pendingFormat.value = null
    pendingCertificate.value = null
  }

  return { pendingFormat, pendingCertificate, busy, submit, cancel, run, requires }
}
