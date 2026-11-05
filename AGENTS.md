# LocalCA 项目指引

本文件只放**项目专属**的开发环境约定；代码规范、架构与取舍见 `README.md` 与
`DECISIONS.md`。通用规则（`.meta` 归置、隐私、dsh 禁重启等）见工作区与全局
`AGENTS.md`。

## 一、开发服务器（遵守 DevHub 新规）

`devctl` 自 2026-11-03 起**只做端口登记，不再管理进程**。本项目的开发服务器是
**systemd 用户服务**：

| 项 | 值 |
| --- | --- |
| 端口 | `18001`（已登记：`project=localca`、`command=dev`） |
| unit | `devhub-localca-dev.service` |
| 启动 | `systemctl --user enable --now devhub-localca-dev.service` |
| 重启 | `systemctl --user restart devhub-localca-dev.service` —— **仅用户明确要求时** |
| 日志 | `journalctl --user -u devhub-localca-dev.service -f` |
| 状态 | `devctl check 18001` |

- 禁止 `devctl start / stop`（子命令已移除）、禁止裸跑 `runserver`、禁止
  `nohup` / `setsid` / `pkill` / `killall`。
- 改端口或改启动命令：`devctl update 18001 …` → `devctl unit render 18001 >
  ~/.config/systemd/user/devhub-localca-dev.service` → `systemctl --user
  daemon-reload` → `restart`。
- **会话结束、任务完成都不停服务**（DevHub R3 / R10）。

## 二、每轮对话结束必须打印访问地址与账密

每次回复的**最后**固定输出这四项。值要现取（下面的来源），不要凭记忆抄：

1. **访问地址**：`http://<局域网IP>:18001/`
2. **账号 / 口令**：`admin` 与普通账号 `alice`、`bob` 的口令
3. **密钥库凭证**：当前账号有哪些凭证、各自口令；**与账号口令不同时必须分开列出**，
   否则第一次签发/导出会卡在解锁上
4. **服务状态**：`systemctl --user is-active devhub-localca-dev.service` 与
   `devctl check 18001` 的结论（一行）

取值来源：

| 事实 | 来源 |
| --- | --- |
| 局域网 IP | `hostname -I \| awk '{print $1}'`（本机真实值记在 `.meta`，不入仓库） |
| 账号口令 | `.scratch/seed_dev.py` 的 `PASSWORD`（gitignored） |
| 账号列表 | `admin`（staff）、`alice`、`bob` |
| 密钥库凭证口令 | 创建凭证的脚本常量（`.scratch/`）；与账号口令一致时写"同账号口令" |
| 端口 / unit | 见上表 |

## 三、隐私

真实内网 IP、口令、`/home/...` 绝对路径、`.scratch/` 内的值**不得写进仓库文件**
（代码、文档、测试、提交信息）。环境事实只写
`~/dsh-workspaces/tools/.meta/dynesshely/localca/ENVIRONMENT.md`；本文件只写规则与
占位符。提交前自查：

```bash
# 排除本文件，否则规则里的占位符会自匹配
git grep -nE '10\.[0-9]+\.[0-9]+\.[0-9]+|/home/|dev-pass' -- . ':(exclude)AGENTS.md'
```

## 四、常用命令

```bash
# 后端测试（DJANGO_SECRET_KEY 等从 gitignored 的 dev.env 取）
set -a; . ./.scratch/dev.env; set +a
./venv/bin/python localca_project/manage.py test LocalCA

# 前端构建
cd frontend && pnpm build

# 翻译目录一致性
python3 scripts/i18n.py check
```

> **构建后必须重启服务**：`start.sh` / 登记命令用的是
> `runserver --noreload`，Django 会缓存解析过的模板，不重启会继续发旧资源名。
