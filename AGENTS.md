# LocalCA 项目指引

本文件只放**项目专属**的开发环境约定；技术概览见 `README.md`，架构与开发流程见
`docs/DEVELOPMENT.md`，设计取舍见 `DECISIONS.md`。跨项目通用规则见全局 `~/.dsh/AGENTS.md`。

## 一、开发服务器

本项目开发服务器是 **systemd 用户服务**：

| 项 | 值 |
| --- | --- |
| 端口 | `18001` |
| unit | `devhub-localca-dev.service` |
| 启动 | `systemctl --user enable --now devhub-localca-dev.service` |
| 重启 | `systemctl --user restart devhub-localca-dev.service` —— **仅用户明确要求时** |
| 日志 | `journalctl --user -u devhub-localca-dev.service -f` |

## 二、访问信息事实源

规则见全局 `~/.dsh/AGENTS.md`。本项目取值来源：

| 事实 | 来源 |
| --- | --- |
| 局域网 IP | `hostname -I \| awk '{print $1}'` |
| 服务端口 / unit | `18001` / `devhub-localca-dev.service` |
| 账号列表 | `admin`（staff）、`alice`、`bob` |
| 账号口令 | `.scratch/seed_dev.py` 的 `PASSWORD`（gitignored） |
| 密钥库凭证口令 | 创建凭证的脚本常量（`.scratch/`）；与账号口令一致时写"同账号口令" |

## 三、常用命令

```bash
# 后端测试（DJANGO_SECRET_KEY 等从 gitignored 的 dev.env 取）
set -a; . ./.scratch/dev.env; set +a
./venv/bin/python localca_project/manage.py test LocalCA

# 模型/数据变更后必须确认 migration 已生成（CI 同样会跑）
DJANGO_TESTING=true ./venv/bin/python localca_project/manage.py makemigrations --check --dry-run

# 应用已提交的 migration（有 pending 时先自动备份 SQLite）
./venv/bin/python localca_project/manage.py upgrade

# 前端构建
cd frontend && pnpm build

# 翻译目录一致性
python3 scripts/i18n.py check
```

> **构建后必须重启服务**：`start.sh` / 登记命令用的是
> `runserver --noreload`，Django 会缓存解析过的模板，不重启会继续发旧资源名。

## 四、迁移纪律（所有变更）

- **模型/数据/默认值/配置存储的任何变化，都必须在同一个改动里附带 migration**；不得只改
  `models.py` 就提交。schema 变更用 `makemigrations LocalCA` 生成并评审；纯数据变更用空 migration
  里的 `RunPython`，且必须幂等。
- **已发布的 migration 不得编辑**，出错就再加一个 migration 修。
- **生产启动只跑 `manage.py upgrade`**：它先检测 pending、写 SQLite 备份，再 `migrate`；容器/CI
  不跑 `makemigrations`。开发环境同样使用 `upgrade`，不要用裸 `migrate` 绕过备份。
- **CI 门禁**：`manage.py test LocalCA` + `manage.py makemigrations --check --dry-run`；模型变更
  没有 migration 时 PR 直接失败。
- **配置是公开契约**：环境变量改名要保留旧名 fallback；不得重写/删除用户的 `.env`；卷路径不得
  无迁移地变更。数据迁移不得依赖网络或主机特定值。
- 细节、备份路径/恢复步骤和兼容性规则见 [`docs/MIGRATIONS.md`](docs/MIGRATIONS.md)。
