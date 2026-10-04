# 决策记录（DECISIONS）

本文件记录**已经拍板的取舍**及其理由，避免同一问题反复讨论。按时间倒序。

> 约定：每条决策注明「谁定的」与「怎么改」。由 AI 按报批默认值执行、用户尚未逐条确认的，
> 明确标注为「agent 默认」，方便你随时推翻。

---

## 2026-10-04 · 下载格式与语言选择控件

| # | 决策 | 谁定的 | 理由 / 怎么改 |
| --- | --- | --- | --- |
| D31 | **推翻「私钥只走 PKCS12」的旧决定**：新增 8 种下载格式，含**未加密 PKCS#8 私钥**与 `.crt`+`.key`+`chain.pem` 的 ZIP | 用户明确要求 | 旧决定（api.py 里有注释）是为了让「静态加密」有意义。但真实运维需要裸 `.key`（nginx 根本读不了带口令的私钥），不给的结果是运维在自己机器上跑 `openssl pkcs12 -nodes`——**没有审计、没有归属校验**。现在改为：明文导出必须**显式确认**（`confirm=true`，UI 是勾选框）、需登录、需本人证书、需密钥库已解锁、并写入审计日志。要回退就删 `DOWNLOAD_FORMATS` 里 `requires: 'confirm'` 的两项 |
| D32 | 下载格式表放在**服务端** `api.DOWNLOAD_FORMATS`，经 `/api/meta/` 下发，前端照它渲染菜单 | agent 默认 | 否则「菜单里有、后端没有」这类漂移只能靠人盯。测试里有一条断言每个格式都能 `reverse()`，另一条断言 `/api/meta/` 与表逐项一致 |
| D33 | `/api/download/<serial>/<format>/` **一个路由**同时服务公开与私有格式，公开格式仍**免登录**（原样保留） | agent 默认 | 公开证书本来就是给客户端取信用的；把 format 写进 URL 而不是一格式一路由，避免两处维护「哪些格式是公开的」 |
| D34 | 语言选择控件**先试原生 `<select>`，验收时被否，改为自绘 listbox**（小地球图标保留） | 用户要求 | 原生 select 的平台弹层既不跟随深色主题（`<option>` 上的类名只是给平台的建议），也吃不到圆角/border，与全站设计语言不一致。改成自绘后按 ARIA「select-only combobox」接线：焦点**始终留在按钮**上（`role=combobox` + `aria-expanded`/`aria-activedescendant`/`aria-controls`），弹层是 `role=listbox`，方向键/Home/End/Enter/Esc/Tab 自己实现。焦点不进弹层还有个好处：弹层周围不会出现浏览器默认焦点环（实测会盖在 border 上） |
| D35 | 顶层 shell 挂**唯一一个**「密钥库解锁」对话框，由 vault store 驱动；各视图不再各带一份 | agent | 签名、导出、轮换都会撞上锁定状态，原来每个视图都复制一遍 open/retry 逻辑。现在 `vault.requestUnlock(reason, retry)` 一处收口，`ApiError.vaultLocked` 一处识别 |
| D36 | 下载菜单用 **Teleport + fixed 定位**，不用 `absolute` | agent | 它所在的卡片有 `overflow-hidden`（为了圆角标题条），表格又 `overflow-auto`——`absolute` 菜单只显示第一行就被裁掉（截图已证实）。`:style` 在这里只传几何坐标，与「配色不许走 style」的约定不冲突 |
| D37 | **管理员也导不出别人的私钥**，且这个拒绝要有自己的文案 | agent 默认 | 密钥库根密钥是**按账号**包裹的，没有托管/代管一说，用调用者自己的根密钥去解别人的密文必然失败。改之前它撞成 `Ciphertext failed authentication: wrong key or tampered data.`（409）——听起来像数据损坏，实际是权限边界。现在只对 `is_wrapped` 的证书先判归属并返回「属于其他账号」；`can_manage`（吊销/删除）保持原样，legacy 明文密钥也不受影响 |

> 顺带修掉一个真 bug：`api/client.js` 的 `download()` 只接受 `FormData`，传普通对象时请求体变成字符串 `"[object Object]"`，后端一律 400——**未加密私钥导出在浏览器里其实是失败的**，只有把文件真的落到磁盘才发现。现在 `download()` 与 `request()` 用同一套 body 规则。
>
> 验收：无头浏览器 **28/28**，其中包含一次真实下载落地——菜单 8 项、分组正确、未确认时按钮禁用、勾选后拿到 `BEGIN PRIVATE KEY` 的明文 PKCS#8、改用口令后同一文件变成 `BEGIN ENCRYPTED PRIVATE KEY`。后端 211 项测试（下载相关 20 项）。
>
> 语言弹层那一版回归过一次：原作者用原生 `<select>` 换来「白送的键盘可达性」，结果平台弹层在深色主题下仍是浅色、且没有圆角/border。重写成自绘 listbox 后，验收脚本里与之对应的三条也换成了真实交互（点开→点选项；再用 `KeyboardEvent` 走一遍方向键 + Enter），另加两条断言弹层的 `border-radius`/`border` 非零、以及深色页面上弹层背景确实变暗（用 canvas 取像素判断——Chrome 会把 `oklch()` 原样返回，字符串解析会读错）。

---

## 2026-10-04 · 界面改版与全站中英双语

| # | 决策 | 谁定的 | 理由 / 怎么改 |
| --- | --- | --- | --- |
| D22 | 前端 i18n 引入 **vue-i18n 11**（本项目第一个前端运行时依赖，除 vue/pinia/vue-router 外） | agent 默认 | 需求就是「全站 i18n」；vue-i18n 是 Vue 生态标准解，自带插值/复数/日期格式，自研等价物只会更差。要退回零依赖，就得自己实现 `t()` + 复数 + 日期格式化 |
| D23 | 词条**按命名空间拆成一文件一命名空间**（`messages/<locale>/leaf.json` 里最外层是 `{"leaf": {...}}`），由 `import.meta.glob` 自动合并 | agent | 让改动可以按功能并行、互不冲突；加功能 = 加文件，不用动任何索引。代价：命名空间写在文件里而非用文件名，**同名命名空间会被两个文件声明**，故 dev 构建会 warn |
| D24 | **服务端文案也用 gettext 翻译**，前端把当前语言放进 `Accept-Language` | agent 默认 | 否则「界面中文、报错英文」；Django 自带这条链路（`LocaleMiddleware` + `.po`），不引额外机制 |
| D25 | 后端词条**只翻译面向用户的文案**，`logger.*`、docstring、内部 `ValueError` 不译；**审计日志的 `details` 列不译** | agent 默认 | `details` 是动作发生时**写进数据库的散文**，不是渲染期文案；要译就得改存储结构（加迁移），不属于首批范围。代价：中文界面下审计详情仍是英文——见下方「待你决定」 |
| D26 | 表单校验错误新增 **`field_errors`（按字段名 keyed）**，`errors` 保留其「标签: 消息」给人看 | agent 默认 | 前端原先靠**匹配英文标签前缀** `"Common name: ..."` 把错误挂到输入框上——标签一翻译就失效。按字段名 keyed 后，语言与摆放彻底解耦。`errors` 保持原样，老调用方不受影响 |
| D27 | 全站**不再用 CSS 变量间接层**（`--surface-*` / `--text-*` / `--border-*` 全部删除），一律 Tailwind 工具类 + `dark:` 成对写 | 用户要求 | 原来 `style="background: var(--surface-card)"` 把真实颜色藏在标记之外，明暗两套主题无法在 diff 里对比。`@theme` 只保留 brand（深藏青）与 moss（苔绿）两个品牌色 |
| D28 | 布局改为**全高左侧栏 + 顶栏 + 独立滚动内容区**，`<h1>` 由顶栏统一承担，页面内不再重复 | 用户要求 | 侧栏与顶栏固定、只有内容滚动，长证书树才好读；路由的 `meta.titleKey` 变成 i18n key，顶栏与 `document.title` 同步 |
| D29 | SAN 输入改为**多行文本框**，服务端按 `[\s,]+` 切分 | 用户要求 | 一行一个域名是粘贴进来的天然形态。切分放宽到任意空白是**安全**的：合法 DNS 名与 IP 里都不含空白，所以更宽的切分不可能切断一个合法条目 |
| D30 | 站点标语在侧栏**折成两行而不截断** | agent | 截断后只剩 "Your own internal certificate ..."，等于没说 |

> 验收方式（`16/16` 通过，脚本在 `.scratch/takeover/verify_ui.py`，不入库）：无头 Chrome 实测——侧栏高度 == 视口高度、`main` 是唯一滚动容器、<lg 时侧栏收起并出现汉堡按钮、切中文后 `<html lang>`/顶栏标题/`document.title` 同步且写入 localStorage、6 个页面**没有任何 i18n key 漏成原文**；再真的用「第一行一个域名 + 第二行逗号分隔」提交一张叶证书，从 API 读回 SAN 为 4 项后删除。
>
> 界面截图已按新布局重拍（`screenshots/*.png`），并新增 `hierarchy-zh.png` 展示中文。中文截图需要 CJK 字体：本机与 CI 镜像都没有，截图时用 `.scratch/fonts/` 里的 Noto Sans SC + 自定义 `FONTCONFIG_FILE`（不入库）。

---

## 2026-10-03 · 部署时挂载目录的属主

| # | 决策 | 谁定的 | 理由 / 怎么改 |
| --- | --- | --- | --- |
| D20 | `start.sh` 在启动 Django 前**预检 `db/`、`db.sqlite3`、`staticfiles/` 是否可写**，不可写就打印路径 + 属主 + 运行 uid 并退出 | agent 默认 | 此前这类故障表现为六十行 Django traceback 被重启策略反复刷屏，而 SQLite 的措辞会把人引偏：**目录**不可写报 `unable to open database file`，**已存在的文件**不可写报 `attempt to write a readonly database`。用户送来的日志正是前者，而 README 旧文把两者都写成后者，属于文档错误。要回退就删掉 `check_writable` 那几处调用 |
| D21 | **不引入 root 入口脚本**（不采用「root 启动 → chown 挂载点 → su-exec 降权」这一通行做法） | agent 默认 | 那样任何挂载都能开箱即用，代价是容器以 root 启动。对签发私钥的 CA 来说方向反了（Dockerfile 里明确写了不为 root 设计）。宁可要求宿主上执行一次 `chown`。若将来明确要求免配置，再改这条 |

> 四种情形都用 Harbor 上那个 `latest`（`sha256:7cb353a0…`）在本机逐一实测过：
>
> | 环境 | 结果 |
> | --- | --- |
> | 具名卷（`docker-compose-harbor.yml`），全新 | ✅ 迁移、建库、collectstatic、gunicorn、HTTP 200 全通 |
> | 绑定挂载 `./db`，宿主目录不存在（docker 建为 root:root 0755） | ❌ `unable to open database file`、容器 restarting、nginx 502 |
> | 绑定挂载 `./db`，属主是操作者本人（1000:1000） | ❌ 同上 —— 所以问题不是「属主是 root」，而是「属主不是 10001」 |
> | 绑定挂载 `./db`，`chown -R 10001:10001` | ✅ 全通 |
>
> 也就是说：**镜像和具名卷都没问题**，只有「全新环境 + 绑定挂载」这个组合会踩。
> 预检已用重新构建的镜像复验：失败路径零 traceback，成功路径不受影响。

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
* D20 的预检要生效必须**重建并推送新镜像**（现有 `latest` 里没有这段）。要现在推就说一声。
* D25 的后果：中文界面下**审计日志的 `details` 列仍是英文**（它是入库时的散文）。要一并本地化，
  需要给 `AuditLog` 存「模板 key + 参数」而不是渲染后的句子，要迁移 `0004`；说一声我就做。
* 前端目前**没有测试框架**（无 vitest），i18n 一致性只能靠 `.scratch/audit_frontend_i18n.py` 手动跑。
  要不要引入 vitest 把这套检查变成 CI 的一部分？
