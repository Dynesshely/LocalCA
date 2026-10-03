# 决策记录（DECISIONS）

本文件记录**已经拍板的取舍**及其理由，避免同一问题反复讨论。按时间倒序。

> 约定：每条决策注明「谁定的」与「怎么改」。由 AI 按报批默认值执行、用户尚未逐条确认的，
> 明确标注为「agent 默认」，方便你随时推翻。

---

## 2026-09-28 · 证书导入功能

| # | 决策 | 谁定的 | 理由 / 怎么改 |
| --- | --- | --- | --- |
| D1 | **不做旧布局兼容代码**，一切以当前基准（镜像布局 `/app/localca_project`、密钥库、Vue SPA）为准 | 用户明确指示 | 旧部署走 README「Upgrading from an earlier version」的一次性升级路径，不在代码里长期背兼容分支 |
| D2 | 新增**导入证书**能力，尽可能多的格式 | 用户明确要求 | 见 README「Importing certificates」与 `SECURITY_AUDIT.md` 第 13 节 |
| D3 | **支持无密钥证书导入**（仅登记/吊销管理），代价是无密钥 CA 必须从签发菜单排除 | agent 默认 | 这是「尽可能多格式」的自然推论（PKCS#7 链本来就只有证书）。若要收紧，把 `import_service` 里无密钥的根/中间判为 `unsupported` 即可 |
| D4 | 查重：同指纹 → 跳过；同序列号不同证书 → 报冲突不导入；已有证书缺密钥而批次带密钥 → 补上 | agent 默认 | `serial_number` 在模型里全表唯一，无法自动解决，只能人工 |
| D5 | 格式范围：PEM / DER / PKCS#7(P7B,P7C) / PKCS#12 / ZIP；私钥含加密 PKCS#8 与传统 OpenSSL 加密 PEM | agent 默认 | 全部用既有依赖 `cryptography`，不新增依赖 |
| D6 | **JKS/JCEKS 不支持**，不引入 `pyjks` | agent 默认 | 本项目一直坚持「零新增依赖」；UI/README 给 `keytool -importkeystore` 转换指引。要原生支持就得接受一个新依赖 |
| D7 | **不加 schema 列**（不记「导入来源」，不出迁移 `0004`） | agent 默认 | 来源只进审计日志；若将来要按来源筛选，再加列 |
| D8 | 导入只能归自己名下，不能代他人导入；staff 仍可管理/扩展任意 CA | agent 默认 | 与既有 `can_manage_certificate` 语义一致；也堵住「往别人层级塞行」 |
| D9 | 导入是**两段式**（先解析出计划、再提交同一批文件），服务端不暂存上传物 | agent 默认 | 密钥材料不落盘、不跨请求存活 |

## 2026-09-28 · 部署与运行

| # | 决策 | 谁定的 | 理由 |
| --- | --- | --- | --- |
| D10 | 修复四个 compose 的卷挂载到新镜像布局（`/app/localca_project/{db,staticfiles}`），并让镜像 uid 可用 `--build-arg APP_UID/APP_GID` 覆盖 | 用户问题驱动（"换镜像能不能读旧数据"） | 旧挂载点会让容器**静默新建空库**且静态资源 404；实测证据见 `SECURITY_AUDIT.md` 12.2 |
| D11 | 回滚不承诺向后兼容：迁移只加列/加表，升级前必须先备份库 | agent 默认 | 未实测旧镜像读新 schema，不做没有证据的承诺 |
| D12 | 重启此前由已死会话 `session-a6520f68…` 持有的 `localca dev`（:18001）实例 | 用户明确点名授权 | 该实例加载的是改动前的代码，`/api/import/` 不存在；重启不影响任何活跃会话 |

## 2026-09-28 · 品牌标识（Logo）

| # | 决策 | 谁定的 | 理由 |
| --- | --- | --- | --- |
| D13 | mark = **盾牌内嵌「根 → 子节点」层级图** | 用户要求绘制，agent 设计 | 图形象征的正是本应用本身：信任锚（盾）+ 证书层级（根/中间/叶）。配色直接用既有 token：盾 `--color-brand-50`、图形 `--color-moss-600`，不引入新颜色 |
| D14 | 顶栏用**内联 SVG 组件**（`BrandMark.vue`）而非图片文件 | agent 默认 | 跟随 CSS 变量（改 token 即改色）、不额外发请求、任意尺寸都清晰 |
| D15 | favicon 提供 **SVG 主用 + ICO 回退**（16/32 两尺寸，PNG 载荷） | agent 默认 | 现代浏览器用 SVG，ICO 给只认 `/favicon.ico` 的客户端；ICO 内图形笔画**比顶栏版更粗**，否则 16px 下会消失 |
| D16 | 未采纳的候选：V 形三点（小尺寸读成笑脸）、空心节点、三子节点（16px 糊成一团）、纯锁孔（只说"锁"不说"CA"）、描边盾（浅底消失） | agent 设计过程 | 对比图 `.scratch/takeover/logo-candidates*.png`，最终验收图 `.scratch/takeover/logo-acceptance.png` |

> 顺带修掉一个真实缺陷：新建的 `frontend/public/favicon.svg` 继承了工具默认的 `600`
> 权限，而 Docker 部署里 nginx 以另一个 uid 读共享静态卷 —— 那份 favicon 会读不到。
> 已改为 `644`。**凡是被静态服务直接读出的文件都要注意权限**，`git` 不跟踪 644/600 的差异。

## 2026-10-03 · 前端缓存与 README 配图

| # | 决策 | 谁定的 | 理由 |
| --- | --- | --- | --- |
| D17 | Vite 产物改为**内容哈希**命名（`assets/[name]-[hash].js|css`） | 用户要求 | 此前产物名固定为 `app.js`，重建后浏览器仍用缓存，新界面必须硬刷新才出现；哈希后旧 URL 直接 404，不可能再命中陈旧缓存（`index.html` 由 Vite 生成并带哈希名，Django 的 `spa_index` 直接渲染它，所以不需要 manifest） |
| D18 | README 配图全部换成 fork 后的真实界面：无头 Chrome 截取、**1920×1080**、存 `screenshots/`，并删除 4 张上游旧图 | 用户要求 | 旧图是上游 django+bootstrap 模板时代的界面，其中一张还是与本项目无关的 Safari/AdGuard 截图。新图为 `hierarchy-light`（首图）、`create-ca`、`create-leaf`、`import`、`hierarchy-dark` |
| D19 | 截图用的演示数据建在 dev 库里：`bob` 用户 + `Homelab Root CA` → `Homelab Services Intermediate CA` → 3 张叶证书（`grafana` 已吊销）；`bob` 的密钥库口令按脚本里的常量设置（见下） | agent | 需要「私钥已加密」的真实观感；`bob` 原本没有密钥库，解锁时按设计自动创建。这批数据可以用 UI 的 Delete 清掉，不影响 `admin` 原有证书 |

> 本轮发现一个真实的**开发流程陷阱**（已写进 README 的开发步骤）：Django 5.2 默认使用
> **cached template loader**，依赖 autoreload 在模板文件变化时清缓存；而本项目的 devctl 命令是
> `runserver --noreload`，所以**每次 `pnpm build` 之后必须重启 dev server**，否则它继续发出上一次
> 构建的资源名（表现为浏览器 404 `app.js`、页面只剩顶栏底栏）。这与"浏览器缓存旧 `app.js`"是两个
> 独立原因，D17 只根治了后者。

> 截图生成脚本在 `.scratch/takeover/shoot_pages.py`（`.scratch/` 不入库，避免给 CI 的 pylint 添负担）。
> 需要纳入仓库的话说一声。

## 待你决定

* D6：要不要原生支持 JKS（需要新增依赖）。
* D3：无密钥证书是保留（现状）还是收紧为不支持。
* `rewrap_keys --password` 是否改为从 stdin/环境变量读取（目前会进 shell 历史）。
