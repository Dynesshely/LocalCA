# LocalCA 源码安全审计报告

| 项目 | 值 |
| --- | --- |
| 仓库 | https://github.com/Dynesshely/LocalCA （上游 README/徽章指向 `tgangte/LocalCA`） |
| 审计对象 | `main` 分支，HEAD = `08db7042efae88458b4def37e519200c3fca0932`（2026-04-13） |
| 代码规模 | 约 3.6k 行（Python / 模板 / 部署配置） |
| 审计方式 | 全量源码走读 + 本地可复现漏洞利用验证（Django 5.2.11 + cryptography 44.0.1，隔离测试库） |
| 审计日期 | 2026-09-18 |
| 修复状态 | **P0 全部已修复**，部分 P1/P2 已修复；详见第 9 节 |

## 0. 结论摘要

这是一个**面向内网/自托管的私有 CA（PKI）Web 应用**，Django + SQLite + gunicorn + nginx，
Docker 部署。它的核心资产是**能够签发任意证书的 CA 私钥**，因此它的安全等级要求等同于
「内网根 CA 的签发控制台」。

审计时的结论：**原始 `main` 分支不适合直接部署到任何多用户、可被非完全可信设备访问的环境。**
（第 9 节记录了随后在同一工作区内完成的修复与验证结果。）

- 未发现命令注入、路径穿越、反序列化、模板注入类漏洞（`eval`/`exec`/`subprocess`/`pickle`/`yaml.load` 均无命中）。
- 但存在 **3 个可直接利用的访问控制缺陷**，其中 2 个已用本地 PoC 复现：
  **任意已登录用户可以用别人的 Root CA 私钥签发中间 CA**，以及**任意已登录用户可以吊销任意证书**。
- 存在 1 处**未加认证装饰器**的私钥导出视图（靠副作用才没直接泄露）。
- 存在 **DEBUG=True + 硬编码 SECRET_KEY + 默认口令 admin/password** 的组合，任意 500 错误页面
  都会把 SECRET_KEY、数据库路径、源码与局部变量吐给请求方。
- **CA/Root/Leaf/Intermediate 私钥全部以明文形式存于 `db.sqlite3`**（字段名 `private_key_encrypted`
  具有误导性）。README 已如实声明，但本报告把它列为最高风险项之一：一旦拿到该文件即可完全
  冒充该根 CA 签发任何证书。

严重度分布：**P0 5 项 / P1 6 项 / P2 4 项 / 供应链 5 项 / 纵深防御 7 项**。

---

## 1. 攻击面清单

| 路径 | 方法 | 认证要求（源码声明） | 实际有效控制 |
| --- | --- | --- | --- |
| `/` (`homepage`) | GET | 公开 | 公开证书元数据（含序列号、SAN、有效期） |
| `/download/<serial>/` | GET | **无** | 无 —— 任意人按序列号取任意证书（叶证书含中间证书链） |
| `/download_private/<serial>/` | GET | `@login_required` | 登录 + `created_by != request.user` 检查（有效） |
| `/download_pkcs12/<serial>/` | GET/POST | **无装饰器** | 仅靠 owner 检查副作用拦截（见 P0-4） |
| `/create_ca/` | GET/POST | `@login_required` | 登录；root 创建无所有权需求，intermediate 有 owner 检查 |
| `/create_intermediate/` | GET/POST | `@login_required` | 登录；**无 owner 检查**（见 P0-2） |
| `/create_leaf/` | GET/POST | `@login_required` | 登录 + 中间证书所有权检查（有效） |
| `/revoke_certificate/<cert_id>/` | GET/POST | `@login_required` | 登录；**无 owner 检查**（见 P0-1） |
| `/change-password/` | GET/POST | `@login_required` | `PasswordChangeForm`（有效） |
| `/login/` `/logout/` | ALL | 公开 | Django `LoginView` / `LogoutView`（POST + CSRF） |
| `/admin/` | ALL | Django admin | `is_staff` + `is_superuser` 有效 |

CSRF 中间件全局启用，所有 POST 表单均带 `{% csrf_token %}`，**未发现 `@csrf_exempt`**。
模板全部依赖 Django 自动转义，**未发现 `|safe` 被用于用户可控数据**
（`change_password.html` 的 `help_text|safe` 是 Django 自带的静态文案）。
URL 反解（`{% url %}`）被大量使用，未发现拼接式 URL 构造。

---

## 2. P0 —— 可直接利用的高危问题

### P0-1 任意已登录用户可吊销任意用户的证书（越权写）

**位置**：`localca_project/LocalCA/views.py:372-402`（`revoke_certificate`）

```python
@login_required
def revoke_certificate(request, cert_id):
    cert = get_object_or_404(LeafCertificate, id=cert_id)   # ← 无 created_by 过滤
    if RevokedCertificate.objects.filter(certificate=cert).exists():
        ...
    else:
        RevokedCertificate.objects.create(certificate=cert, reason="Revoked by admin")
```

`cert_id` 是自增主键，可枚举。对比同文件 `create_leaf` 的正确写法：
`get_object_or_404(IntermediateCertificate, id=intermediate_id, created_by=request.user)`。

**复现（已验证）**：`.scratch/audit_probe.py` PROBE 1
—— 攻击者登录后 `POST /revoke_certificate/<victim_leaf_id>/`，受害者的叶证书被标记吊销，
HTTP 200，`RevokedCertificate` 记录被创建。

**影响**：服务中断型攻击（DoS）。被吊销的证书若已通过某种渠道分发到系统，会造成信任链断裂。
同时审计日志会把吊销动作记在攻击者名下，掩盖真实意图。

**修复**：

```python
cert = get_object_or_404(LeafCertificate, id=cert_id, created_by=request.user)
```

并在 `RevokedCertificate` 上补 `created_by=request.user`。若确实需要「管理员可吊销他人证书」，
应显式判断 `request.user.is_staff`，而不是默认放开。

---

### P0-2 任意已登录用户可用他人的 Root CA 私钥签发中间 CA（CA 权限提升）

**位置**：`localca_project/LocalCA/views.py:243-295`（`create_intermediate`）

```python
@login_required
def create_intermediate(request):
    roots = RootCertificate.objects.all()          # ← 全部用户的 Root
    ...
    root_cert = get_object_or_404(RootCertificate, id=root_id)   # ← 无 owner 检查
    intermediate_cert_data = ca_manager.create_intermediate_certificate(
        intermediate_name, validity_days,
        root_cert.public_key,
        root_cert.private_key_encrypted,           # ← 直接使用他人的 CA 私钥
    )
```

`create_ca` 中同一功能有正确检查（`views.py:185-190`），但 `create_intermediate`
这个「旧版」视图完全绕过了它，且该视图**仍然注册在路由中**（`LocalCA/urls.py:21-24`）。

**复现（已验证）**：`.scratch/audit_probe.py` PROBE 2
—— 攻击者 `POST /create_intermediate/`，用受害者的 Root CA 私钥签发出一个中间 CA
（`signed_by_root = Victim Root CA`，`created_by = attacker`），返回 200。

**影响**：这是本报告中最严重的问题。受害者的 Root CA 是**被终端设备信任的根**；
攻击者由此获得一条**受信任的签发路径**，可以为任意域名（含通配符 SAN）签发绕过高危告警的
证书，实施内网 MITM。攻击者无需知道受害者口令，受害者也几乎无从察觉（后果见 P0-3）。

**修复**：删除该遗留视图与其路由；如必须保留，则复用 `create_ca` 中的检查：

```python
if not RootCertificate.objects.filter(id=root_id, created_by=request.user).exists():
    raise PermissionDenied
```

并把 `roots` 查询改为 `filter(created_by=request.user)`。

---

### P0-3 CA 私钥明文落库，字段名具有误导性

**位置**：`localca_project/LocalCA/ca.py:111-114, 140-143, 176-179`；`models.py:22, 43, 68`

```python
"private_key": private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()).decode(),
```

模型字段名为 `private_key_encrypted = models.TextField()`，但写入的是**未加密的 PKCS#1 PEM**。
`README.md` 的 Security 章节确实声明了这一点，但字段命名会让二次开发者误以为已有加密保护。

**影响**：
- Root CA 私钥（本应用中唯一真正的信任锚）以明文存在于 `db.sqlite3`；
  任何读到该文件的人（备份、卷快照、容器逃逸、`docker cp`、误提交、磁盘镜像）都能
  永久伪造该 CA 的任意下级证书——注意**根证书无法吊销**，泄露即不可逆。
- 明文私钥即等于「有 `db.sqlite3` 就有 CA 控制台」，使 P0-2 的危害可被离线放大。
- 管理后台 `/admin/LocalCA/rootcertificate/<id>/change/` 会把 PEM 私钥**原样渲染进 HTML 表单**
  （已验证，见 `.scratch/audit_probe2.py` PROBE 8，`"BEGIN RSA PRIVATE KEY" in body == True`），
  使明文密钥暴露在浏览器缓存、开发者工具、以及任何 XSS/HTML 注入面之下。

**修复**：
1. 用主密钥（来自环境/`docker secret`/KMS）对私钥做信封加密后再落库，
   例如 `serialization.BestAvailableEncryption(master_key)` 存储 PEM，并在字段名中去掉歧义。
2. 后台把 `private_key_encrypted` 设为只读（`readonly_fields`）并做打码展示。
3. 审计并删除历史遗留的对象/备份——Django admin 删除对象不等于清除 SQLite 中的残留页，
   必要时对 DB 做 `VACUUM` 或整库轮换。
4. 明确威胁模型：如果目标环境无法保护 `db.sqlite3`，应改用外部密钥保管（PKCS#11 / Vault / 硬件令牌），
   而不是把 CA 私钥放在 Web 应用可读的 SQLite 里。

---

### P0-4 私钥导出视图缺少 `@login_required`（靠副作用兜底）

**位置**：`localca_project/LocalCA/views.py:450-514`（`download_pkcs12`）

`download_private`（`views.py:405`）与 `download_pkcs12`（`views.py:450`）逻辑几乎相同，
但后者**没有 `@login_required` 装饰器**（对比 `views.py:127/243/298/372/405/517` 都有）。
匿名请求会走到 `if cert.created_by != request.user`，
`AnonymousUser` 与 `User` 比较触发 Django 的 `redirect_to_login`（实测 302，非 500）。

**为什么仍然要报 P0**：
- 该保护的成立依赖**两个偶然事实**：`cert.created_by` 恰好非 `NULL`，且比较运算符
  恰好触发 `AnonymousUser.__eq__`。模型里 `created_by` 是 `null=True`
  （`models.py:13-17, 34-38, 57-61`），一旦出现 `created_by IS NULL` 的证书
  （例如既有的旧数据、admin 手工创建、将来引入迁移），该视图对匿名用户即成为
  **无认证的私钥导出接口**（`.p12` 中含明文私钥）。
- 生产环境把 `PermissionDenied` 映射为登录跳转，也意味着「无权限」和「未登录」无法区分，
  掩盖了鉴权边界的真实形状，不利于监控。

**修复**：加 `@login_required`；owner 判断统一改为
`if cert.created_by_id is None or cert.created_by_id != request.user.id: raise PermissionDenied`。
并对 `created_by` 增加 `null=False`（配合数据回填）或至少 `db_index`。

---

### P0-5 DEBUG 默认开启 + 硬编码 SECRET_KEY + 默认口令

**位置**：`localca_project/localca_project/settings.py:24-29`；`LocalCA/management/commands/initadmin.py:20-38`

```python
SECRET_KEY = 'django-insecure-…（原文完整值已从本仓库移除，见 git 历史中的 08db704）'
DEBUG = True
ALLOWED_HOSTS = ['*']
```

```python
if User.objects.count() == 0:
    username, password = "admin", "password"
```

- SECRET_KEY **硬编码在版本库中且从未轮换**（已核对全部 141 次提交历史，
  该值自首次提交起未变）。它能伪造签名 Cookie、会话、密码重置令牌与 `messages` 框架数据。
- `DEBUG=True` 是**投产默认值**，`docker-compose*.yml` 也没有覆盖它。
- **实测**：`POST /create_ca/` 带 `validity_days=abc`（或 `999999999`）触发未捕获异常 →
  HTTP 500 的 Django 调试页**包含 `SECRET_KEY`、`Traceback`、`Python Version`、源码与局部变量**
  （`.scratch/audit_probe3.py` PROBE 11 已验证三类输入均可触发）。
- 配合 `ALLOWED_HOSTS=['*']` 与 `initadmin` 的固定口令 `password`，
  「未授权者读到 SECRET_KEY 与源码」→「用 admin/password 登录」→「拿到全部 CA 私钥」是一条完整链路。
- 附带安全问题：`views.py:149, 192, 252, 253, 315, 316` 直接 `int(request.POST.get(...))`，
  空值 / 非数字 / 极大值分别抛 `ValueError` / `OverflowError`，无异常兜底（只捕获了 `ValueError`
  且位置在转换之后）。

**修复**：

```python
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]          # 缺失即启动失败
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h]
```

`initadmin` 改为读取 `DJANGO_SUPERUSER_PASSWORD` 或生成随机口令并只打印一次；
输入统一用 Django `Form` 做类型/范围校验（`IntegerField(min_value=1, max_value=...)`）。

---

## 3. P1 —— 高危及纵深防御缺失

### P1-1 证书有效期仅在浏览器侧限制，服务端不限

模板限制：Root `max="7300"`、Intermediate `max="3650"`、Leaf `max="825"`
（`create_ca.html:47, 163`、`create_leaf.html:77`）。服务端**完全不校验上限**。

**复现（已验证）**：`.scratch/audit_probe.py` PROBE 4 ——
`POST /create_leaf/` 带 `validity_days=36500`，成功签发 **100 年期叶证书**（有效期至 2126 年）。
`ca.py` 也**没有「子证书不得晚于签发者到期时间」的校验**，所以可以签发比 CA 活得更久的证书。

**影响**：违反 CA/Browser Forum 基线要求（当前公有信任叶证书上限 200 天）与运维安全基线；
一旦证书私钥泄露，攻击窗口被无限放大。对私有 CA 虽非硬性合规问题，但属于明显的策略缺口。

**修复**：服务端校验 `1 <= validity_days <= 上限`，并强制
`leaf.not_valid_after <= intermediate.not_valid_after`（`ca.py` 内实现，所有调用点共享）。

### P1-2 叶证书缺少 KeyUsage / ExtendedKeyUsage

`ca.py:305-366` 的 `sign_leaf_csr` 只附加 SAN、SKI、AKI、`BasicConstraints(ca=False)`，
**没有 KeyUsage**。叶证书因此不含「只能用于数字签名与密钥协商、不可用于签发证书」的约束，
也缺少 EKU（`serverAuth`/`clientAuth`）以限制用途。强烈建议用
`x509.KeyUsage(..., key_cert_sign=False, crl_sign=False, critical=True)`，
并按用途加 `ExtendedKeyUsage`。这是纵深防御：即便 BasicConstraints 已被多数实现正确处理，
缺少 KeyUsage 会扩大旧实现或用途校验不严的客户端上的滥用面。

### P1-3 中间 CA 未限制路径长度

`ca.py:297` 对中间证书使用 `BasicConstraints(ca=True, path_length=None)`，
即中间 CA 可以无限继续签发下级 CA。应显式设 `path_length=0`（或按层级设定），
否则「中间 CA 泄露」等于「根 CA 泄露」。

### P1-4 下载响应缺少 `Content-Disposition` 引号与转义

`views.py:105-107, 113, 438, 505`：

```python
response["Content-Disposition"] = f"attachment; filename={cert.common_name}_chain.pem"
```

`cert.common_name` / `cert.name` 直接来自用户输入，未加引号也未做 RFC 6266 编码。
**实测**（PROBE 6）：CN 为 `evil".internal` 时响应头为
`attachment; filename=evil".internal_chain.pem` —— 引号破坏文件名语义，
在部分客户端可能造成文件扩展名/类型混淆（例如诱使保存为可执行文件）。
CR/LF 注入被 Django 拦截（不会产生响应拆分），但这不是应用可以依赖的边界。

**修复**：用 ASCII 回退 + `filename*=UTF-8''<percent-encoded>` 双形式，或直接生成
无歧义的固定文件名（如 `<serial>.pem`）。

### P1-5 私钥响应缺少 `Cache-Control: no-store`

`views.py:435-438` 与 `501-505` 返回私钥/`.p12` 时未设置任何缓存与安全响应头。
在共享终端、代理或浏览器中间缓存场景存在残留风险。

**修复**：`response["Cache-Control"] = "no-store"`，并补 `X-Content-Type-Options: nosniff`、
`Referrer-Policy`。全局可加 `SecurityMiddleware` 相关配置与 `Content-Security-Policy`。

### P1-6 无登录限速 / 无账户锁定

`/login/` 直接用 Django `LoginView`，无任何速率限制、失败计数或锁定。
结合 `initadmin` 的固定弱口令与 `DEBUG=True` 的信息泄露，暴力破解成本很低
（默认 docker 端口 80 映射到宿主机所有网卡）。

**修复**：接入 `django-axes` 或前置 nginx `limit_req`；强制首次登录改密；
禁用/删除 `initadmin` 的固定口令路径。

---

## 4. P2 —— 中低危与代码质量问题

1. **吊销状态不可被外界获知**：`RevokedCertificate` 只是在数据库里打标记，
   既不生成 CRL，也不提供 OCSP 端点。这意味着**吊销在密码学层面无效**（客户端无从查询）。
   对一个 CA 产品而言，这是功能级的信任缺陷。建议至少支持导出 CRL 并提供 `.crl` 分发路径，
   或在文档中明确「吊销仅具备记录意义」。
2. **死模板带 XSS/密钥曝光隐患**：`templates/LocalCA/home.html` 未被任何视图引用
   （已核对全仓库无 `home.html` 引用），但它把私钥**内联进 JavaScript 字符串**：
   `onclick="downloadKey('{{ cert.private_key_encrypted }}', ...)"`。
   该模板同时 `{% extends "base.html" %}`（错误路径）。它当前不可达，但一旦被接回去就是
   直接的密钥泄露面。建议删除。
3. **失效的 URL 反解**：`templates/LocalCA/create_intermediate.html:55` 使用
   `{% url 'home' %}`，该 name **不存在**（已实测 `NoReverseMatch`），一旦渲染即 500。
   与 P0-2 一起看，说明这条创建中间证书的旧链路从未被测试覆盖。
4. **`datetime.utcnow()` 已弃用**：`ca.py:86, 88, 281, 283, 331, 333` 与 `views.py:348`。
   Python 3.12+ 会发出 `DeprecationWarning`；返回 naive datetime 而 Django 配置 `USE_TZ=True`，
   存在时区语义混淆风险（证书时间应为 UTC 且显式 aware）。
   建议统一改为 `datetime.now(timezone.utc)`。
---

## 5. 供应链与部署面

1. **依赖已落后于上游安全修复**：
   - `Django==5.2.11`（`requirements.txt:1`）。仓库内已有 dependabot 分支
     `dependabot/pip/django-5.2.14`（commit `680b93b`）待合并；上游 5.2.13 是一次
     security bump，5.2.13/5.2.14 均含安全修复。
     参见 [Django 5.2.14 release notes](https://docs.djangoproject.com/sv/6.0/releases/5.2.14/)、
     [Django 5.2.12 release notes](https://docs.djangoproject.com/en/6.0/releases/5.2.12/)。
   - `cryptography==44.0.1`（`requirements.txt:2`）。仓库内已有
     `dependabot/pip/cryptography-48.0.1`（commit `d804b81`）待合并；上游存在
     [CVE-2026-69247](https://github.com/advisories/GHSA-g6cj-pr64-35w5)
     （另见 [Ubuntu](https://ubuntu.com/security/CVE-2026-69247)、
     [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-69247)），
     且生态内多个项目正以 `cryptography → 48.0.1` 的方式做安全升级。
     **精确的受影响版本区间请以 GHSA-g6cj-pr64-35w5 原文为准**——本环境只有搜索接口，
     无法读取公告正文，故此处不给出具体区间断言，仅指出「已过时且上游有安全通告」。
   - `requirements.txt` **未做哈希锁定**（无 `--hash`，无 `pip-tools`/`Poetry` 产物），
     构建不可复现，也无法检测依赖替换。
2. **Dockerfile 以 root 运行**：`Dockerfile` 基础镜像 `python:3.10-slim` 未固定 digest，
   未创建非特权用户，未使用多阶段构建；容器内默认 root，配合 `volumes: ./localca_project:/app`
   的源码绑定挂载，容器进程对宿主机源码树具备写权限。
   建议：固定 `FROM python:3.12-slim@sha256:...`、`USER app`、生产镜像不含源码挂载。
   另外本地 Python 版本（3.10）与 CI（3.12）不一致，容易出现「CI 绿、容器红」。
3. **容器启动即 `makemigrations`**：`localca_project/start.sh:4` 与各 compose 的 `command`
   在**每次启动**执行 `makemigrations` + `migrate`。运行时自动生成迁移在并发/多副本下竞态，
   且 `.gitignore` 把 `migrations` 整个忽略掉，导致模型变更无法被评审、无法回滚。
   建议：迁移文件入库、启动只跑 `migrate --noinput`。
4. **CI 未做安全检测**：`.github/workflows/*.yml` 只有 `python manage.py test` 与 `pylint`，
   没有依赖漏洞扫描（pip-audit / Dependabot alerts 之外的 CI 门禁）、没有 SAST、没有 secret 扫描。
   另外两处工作流 `permissions` 都授予了 `pull-requests: write`，而实际只读不写，
   违反了最小权限（`pull_request_target` 场景下危害更大）。
   还使用了已过时的 `actions/setup-python@v3`。
5. **部署配置不一致可能静默削弱防护**：`docker-compose-from-registry-arm.yml` 缺少
   `CSRF_TRUSTED_ORIGINS`（其余 compose 都有，README 也要求手动添加）。
   另外 `docker-compose.yml:8` 与声明卷 `db:` 并存，容器实际写入**宿主机目录 `./db`**
   而非具名卷，导致「以为数据在卷里、实际在源码树里」的备份与权限误判。
6. **README 引导用户从未固定的远程分支取配置并直接运行**：
   `wget .../refs/heads/main/docker-compose-from-registry.yml` —— 供应链上
   等于信任「任意时刻的通配符分支内容」，建议改为按 tag/commit 固定。

---

## 6. 未发现的问题（已主动排查，供参考）

以下项经过针对性检索与走读，**未发现命中**：

- 命令注入：全仓库无 `subprocess`、`os.system`、`shell=True`、`eval`、`exec`。
- 反序列化：无 `pickle`、无 `yaml.load`（也未使用 yaml）。
- 路径穿越：无用户可控路径拼接，无 `open(request...)` 模式；证书不落盘为文件。
- 模板注入 / XSS：模板未对用户可控数据使用 `|safe`；自动转义生效；
  SAN、CN、证书名渲染均走默认转义。
- SQL 注入：全部使用 Django ORM，无 `raw()` / `extra()` / 字符串拼 SQL。
- CSRF：中间件启用，所有 POST 表单带 `{% csrf_token %}`，无 `@csrf_exempt`。
- 目录遍历/未授权静态资源：静态目录由 nginx `alias` 托管，未暴露 `db/`。
- 证书私钥泄露到日志：`AuditLog` 只记录 CN/序列号，未记录密钥材料。
- 强算法：RSA 2048 + SHA-256；PKCS12 导出在用户提供口令时使用
  `BestAvailableEncryption`（正确）；序列号使用 `x509.random_serial_number()`（正确）。

---

## 7. 修复优先级建议

> 本节为审计当时给出的建议排序。**「立刻」与「高」两档已在第 9 节完成**，
> 并逐项附验证方式；未完成项见 9.3。

| 优先级 | 动作 | 覆盖问题 |
| --- | --- | --- |
| 立刻（投产阻断） | 生产环境强制 `DEBUG=False`、SECRET_KEY 与 ALLOWED_HOSTS 走环境变量 | P0-5 |
| 立刻 | 删除 `/create_intermediate/` 路由与视图（或补 owner 校验） | P0-2 |
| 立刻 | `revoke_certificate` 加 `created_by=request.user` 过滤 | P0-1 |
| 立刻 | 删除 `initadmin` 固定口令，改随机/环境变量 | P0-5 |
| 立刻 | `download_pkcs12` 补 `@login_required`，owner 判断改用 `_id` 比较 | P0-4 |
| 高 | 私钥信封加密落库 + admin 只读打码 + 字段更名 | P0-3 |
| 高 | 服务端校验 `validity_days` 上下限与「不超过签发者有效期」 | P1-1 |
| 高 | 依赖升到 Django 5.2.14 / cryptography 48.0.1 并加哈希锁定 | 供应链 |
| 中 | 叶证书补 KeyUsage/EKU，中间 CA 设 `path_length=0` | P1-2, P1-3 |
| 中 | 登录限速/锁定；部署改非 root、固定镜像 digest | P1-6, 供应链 |
| 中 | 吊销补 CRL 导出（或在文档中声明吊销的局限） | P2-1 |
| 低 | 删除死模板 `home.html`；修 `{% url 'home' %}`；`utcnow` → `timezone.now()` | P2-2/3/4 |

---

## 8. 审计方法与可复现性

本报告中的「已验证」结论均来自**在本地隔离测试数据库**上运行的真实请求，
未修改仓库任何受版本控制的内容（`git status` 仅显示新增的 `.scratch/` 未跟踪目录）。

- 环境：`.audit-venv/`（仓库 `.gitignore` 已忽略 `venv`，故未被 `git status` 视为变更），
  Python 3.14 + `Django==5.2.11` + `cryptography==44.0.1`。
- 探针脚本：
  - `.scratch/audit_probe.py` —— PROBE 1/2/4/5/6：吊销越权、中间 CA 越权签发、
    有效期绕过、私钥越权下载（被正确拦截）、响应头注入。
  - `.scratch/audit_probe2.py` —— PROBE 7/8/9/10：`download_pkcs12` 认证路径、
    admin 明文私钥渲染、`created_by IS NULL` 边界、匿名下载与匿名审计记录。
  - `.scratch/audit_probe3.py` —— PROBE 11/12：恶意输入导致 500 与 DEBUG 页面信息泄露、
    安全相关 settings 快照。
- 复现方式：

```bash
cd LocalCA
python3 -m venv .audit-venv && .audit-venv/bin/pip install Django==5.2.11 cryptography==44.0.1
.audit-venv/bin/python .scratch/audit_probe.py
```

如需清理审计产物：`rm -rf .audit-venv .scratch`。

---

## 9. 修复记录（2026-09-18 同工作区）

审计后在同一工作区完成了修复与验证。项目本身的 `AGENTS.md` 未定义提交规约，
故所有改动保持在未提交状态，由仓库所有者决定如何入库。

### 9.1 P0 全部修复

| 编号 | 问题 | 修复方式 | 验证 |
| --- | --- | --- | --- |
| P0-1 | 任意登录用户可吊销任意证书 | `revoke_certificate` 改为 `@require_POST` + `owner 或 staff` 校验；URL 携带证书类型，POST body 必须与 URL 一致 | `tests_revocation.RevocationAuthorityTests`（9 项）；浏览器 E2E |
| P0-2 | 可用他人 Root 私钥签发中间 CA | `create_intermediate` 与 `create_ca` 统一走 `IntermediateCertificateForm`，其 `root_id` 查询集仅为 `created_by=request.user` | `tests_ui.FormValidationTests.test_intermediate_form_only_accepts_roots_owned_by_the_user` |
| P0-3 | CA 私钥明文落库、admin 明文渲染 | admin 全面改造：`private_key_encrypted` 从表单中排除并只读打码显示；`AuditLog` 只读且禁止新增。**私钥仍为明文存储**——这是需要密钥管理方案的设计变更，见 9.3 | `.scratch/audit_probe2.py` PROBE 8 复测：admin 页面不再含 PEM |
| P0-4 | `download_pkcs12` 缺 `@login_required` | 补装饰器；`download_private` / `download_pkcs12` 的 owner 判断统一为 `is_owner()`（比较主键，`AnonymousUser` 与 `NULL` 属主均不通过） | `tests_revocation.PrivateKeyAccessTests`（6 项） |
| P0-5 | DEBUG 默认开 + 硬编码 SECRET_KEY + 默认口令 | `settings.py` 改为从环境变量读取且在缺 SECRET_KEY 时**拒绝启动**；`DJANGO_ALLOWED_HOSTS` 必须显式给出；`initadmin` 口令改为可配置；4 个 compose 文件与 `.env.example` 同步补齐所需变量 | `env -u DJANGO_SECRET_KEY manage.py check` 报错退出；`devctl start localca check` 通过 |

### 9.2 同批修复的 P1 / P2

- **P1-1 有效期**：新增 `LocalCA/forms.py`，服务端强制 `1 ≤ validity_days ≤ 825`（叶）/`7300`（CA），
  并强制**子证书不得晚于签发者到期时间**。原 `int(request.POST[...])` 崩溃路径随之消失
  （`abc` / 空 / `999999999` 现在都是表单错误而非 500）。
- **P1-4 响应头**：新增 `_attachment_disposition()`，ASCII 部分加引号并对非 ASCII 使用 RFC 6266
  `filename*`；私钥/`.p12` 响应补 `Cache-Control: no-store` 与 `X-Content-Type-Options: nosniff`。
- **P2-2 死模板**：删除 `templates/LocalCA/home.html`（未引用，且把私钥内联进 JS 字符串）。
- **P2-3 失效 URL**：`create_intermediate.html` 重写为继承 `base.html`，`{% url 'home' %}` 修正为 `homepage`。
- **P2-4 `utcnow`**：`views.py` 中最后一处 `datetime.utcnow()` 移除（`ca.py` 中 6 处仍在，见 9.3）。
- **修复过程中新发现并修复的两处缺陷**（均非原审计项，由本轮验证暴露）：
  - **重复证书名导致 HTTP 500**：`RootCertificate.name` / `IntermediateCertificate.name` /
    `LeafCertificate.common_name` 均为 `UNIQUE`，而视图只捕获 `ValueError`，
    同名插入抛出未处理的 `IntegrityError`。现由表单在写入前校验重名并给出可读错误。
  - **`messages.error()` 渲染为无效的 `alert-error`**：Django 默认 message tag 是 `error`，
    而 Bootstrap 5 没有该类，错误提示实际无样式（深色背景下几乎不可见）。
    已在设置了显式 `MESSAGE_TAGS` 映射（error→danger 等）。
- **供应链**：迁移文件纳入版本库（原先被 `.gitignore` 忽略，导致模型变更无法评审）；
  `.dockerignore` 不再排除 `migrations/`；`start.sh` 去掉运行时 `makemigrations`；
  CI 增加 `DJANGO_TESTING` 以在测试环境提供一次性密钥。

### 9.3 仍未修复（需要产品或架构决策）

1. **私钥明文存储**（P0-3 的根因）。当前只做了「不再从 admin 渲染」。真正解决需要主密钥/KMS
   信封加密，或改用外部签名服务；这会影响部署形态与备份流程。
2. **无 CRL / OCSP**。吊销只在本应用内记录并写入审计日志，**不向客户端发布**，
   因此对已分发证书不具备密码学效力。UI 的确认弹窗已明确告知这一点，
   但完整的解决方式是提供 CRL 分发点或 OCSP 响应器。
3. **`ca.py` 仍用 `datetime.utcnow()`**（86/88/281/283/331/333 行），返回 naive datetime
   而配置为 `USE_TZ=True`；建议统一改为 `datetime.now(timezone.utc)`。
4. **RSA 2048 且无 ECDSA 选项**；叶证书仍缺 KeyUsage/EKU；中间 CA 仍为 `path_length=None`。
5. **登录无速率限制/锁定**。
6. **`initadmin` 仍会在空库时创建 `admin` 用户**（口令已改为可配置，但默认值仍不安全，
   且 README 仍宣传 `admin/password`）。

### 9.4 验证证据（可复跑）

| 层次 | 命令 | 结果 |
| --- | --- | --- |
| 单元/集成测试 | `DJANGO_TESTING=true python manage.py test LocalCA` | **83 passed** |
| 真实浏览器 E2E | `python .scratch/browser_e2e.py` | **28/28 passed**（登录、深色模式切换、吊销全流程、405 校验） |
| 证书创建全流程（HTTP） | `python .scratch/check_create_flow2.py` | **7/7 passed**（建根/建中间/建叶、重名与非法有效期均转为表单错误） |
| 计算样式审计 | `python .scratch/style_probe.py <pages>` | `NO THEME PROBLEMS DETECTED` |
| Django 自检 | `devctl start localca check` | `no issues (0 silenced)` |
| pylint（CI 门禁） | `pylint $(git ls-files '*.py' \| grep -v migrations)` | 9.90/10 |

浏览器 E2E 覆盖：表单登录 → 首页渲染 → **点击**深色模式按钮（断言 `body` 背景由
`rgb(255,255,255)` 变为 `rgb(26,26,26)`、两个主题属性同步、写入 localStorage、跨页面保持）
→ 打开吊销确认弹窗（断言目标 URL/类型/id/CSRF/证书名/RFC 5280 原因/「仅本地记录」警告）
→ 提交并断言页面出现成功消息与吊销标记 → 断言 GET 访问吊销/删除端点返回 405。

> 说明：本沙箱内 chromium 的合成器始终输出黑帧，截图无法用于视觉判定，
> 因此上述「视觉」结论全部基于 **计算样式（computed style）与 DOM 断言**，
> 而非像素。截图仍作为产物保留在 `.scratch/shots/`。


---

## 10. 前端重写：Django 模板 → Vue 3 SPA（2026-09-18 同工作区）

应要求将前端从 Django 服务端渲染模板重写为 Vue 3 单页应用，Django 退化为 JSON API。
本节记录这次架构变更对安全面的影响——**这是审计结论需要同步更新的部分**。

### 10.1 变更摘要

| 方面 | 重写前 | 重写后 |
| --- | --- | --- |
| 页面渲染 | Django 模板（9 个） | Vue 3 SPA（Vue Router 客户端路由） |
| 数据接口 | 无（表单 POST + HTML） | `/api/` 下 15 个 JSON 端点 |
| 认证 | 会话 Cookie + CSRF（Django `LoginView`） | 会话 Cookie + CSRF（自建 JSON 登录端点，`X-CSRFToken` 头） |
| 私钥导出保护 | `@login_required` + owner 检查 | 不变（`api_download_private` / `api_download_pkcs12`） |
| 前端构建 | 无（Bootstrap/FontAwesome 走 CDN） | Vite 7 + Tailwind CSS 4 + pnpm，产物 `frontend/dist` |

### 10.2 安全面变化（逐项评估）

1. **权限模型未变，且被更严格地复用**：`can_manage_certificate` / `is_owner` /
   `_revocation_filter` 等判定逻辑原样迁移到 `api.py`，`serializers.py` 只负责序列化，
   不参与授权决策。授权仍由服务端强制，`serializers` 输出的 `can_manage` 仅用于
   前端决定是否渲染按钮——**不是**安全边界。
2. **`RevokeForm` 的 URL/body 一致性校验保留**：`type` + `id` 必须与 URL 匹配，
   否则 400，防止过期弹窗吊销错误对象。
3. **不可序列化的字段从未出口**：`serializers.py` 不输出 `private_key_encrypted`，
   且有测试断言 `/api/certificates/` 响应中不含 `BEGIN RSA PRIVATE KEY` /
   `BEGIN CERTIFICATE` / `private_key`。
4. **CSRF 覆盖面扩大而非缩小**：SPA 通过 `X-CSRFToken` 头提交，Django CSRF 中间件
   对 `/api/` 的 POST 仍然生效（有测试 `test_csrf_is_enforced` 用
   `enforce_csrf_checks=True` 断言无 token 时 403）。
5. **SPA 兜底路由不遮蔽 API**：catch-all 注册在 `/api/` 与 `/admin/` 之后，
   且有测试断言 `/api/session/` 返回 JSON 而非 HTML。
6. **新引入的浏览器侧风险点**：Vue 默认转义插值，未使用 `v-html`；
   确认全仓库无 `v-html`/`innerHTML` 赋值（仅有测试探针使用）。
7. **新增依赖面**：引入 npm 依赖（vue / vue-router / pinia / vite / tailwindcss）。
   已提交 `pnpm-lock.yaml`，并使用 `packageManager` 固定 pnpm 版本；
   Docker 构建用 `--frozen-lockfile`，不再有"构建时静默升级依赖"的可能。

### 10.3 本次重写中发现并修复的真实缺陷

| 缺陷 | 影响 | 修复 |
| --- | --- | --- |
| **前端发 JSON、后端按 `request.POST` 绑定表单** | 所有写操作（创建/吊销/删除/改密）返回 400 "This field is required"，**功能完全不可用** | 新增 `api._payload()`：按 `Content-Type` 同时接受 JSON 与 urlencoded；补 6 个测试覆盖两种编码 |
| `CertificateTree` 用 `forward()` 闭包转发事件 | 吊销/删除弹窗**永远不打开**（事件链断裂） | 改为内联 `@revoke="emit('revoke', $event)"` |
| 登录表单缺少 `computed` 导入且无空值防护 | 空表单提交白跑一次请求 | 补 `computed` 导入，按钮在字段为空时禁用 |
| `spa_index` 不接受 catch-all 的 `resource` 参数 | 所有深链接 500 | 视图接受并忽略该参数 |
| `STATICFILES_DIRS` 指向 `dist/assets` 而非 `dist` | 静态查找器解析成 `assets/assets/*`，资源 404 | 指向 dist 根目录 |
| Vite 产物引用 `/assets/*` | Django 不提供该路径，JS/CSS 404 | 设置 `base: '/static/'` |
| **`base: '/static/'` 同样作用于 dev server** | 开发服务器把整个应用搬到 `/static/`，而 router 路径是 `/login`、`/create/leaf`，**客户端路由在开发环境完全不可用**（README 记录的 `pnpm dev` 流程是坏的） | `base` 改为按命令区分：`build → /static/`、`serve → /` |

### 10.4 验证证据

| 层次 | 命令 | 结果 |
| --- | --- | --- |
| Django 测试（含 API 契约、JSON/表单双编码、权限矩阵） | `DJANGO_TESTING=true manage.py test LocalCA` | **72 passed** |
| 真实浏览器 E2E（Vue SPA） | `python .scratch/spa_e2e.py` | **30/30 passed** |
| 匿名路径 | `python .scratch/spa_e2e.py --anonymous` | **8/8 passed** |
| 前端生产构建 | `cd frontend && pnpm build` | 成功（app.js 114 kB / app.css 25 kB，gzip 后 44 kB / 5.6 kB） |
| Tailwind 产出校验 | 抽查 8 个源码中使用的工具类 + 深色变体 + `@theme` 令牌 | 全部生成；`dark:` 以 Tailwind 4 的 `:where(.dark,.dark *)` 形式产出 |
| 未构建兜底页 | 移除 `frontend/dist` 后访问 `/` | 200，显示构建指引 |
| **Vite dev server** | `LOCALCA_URL=http://127.0.0.1:5173 python .scratch/spa_e2e.py` | **31/31 passed**（+ 匿名 8/8）；`/`、`/login`、`/create/leaf` 均 200，`/api` 代理到 Django 正常 |
| 开发/生产两条路径 | 同一份 E2E 分别针对打包产物与 Vite 未压缩源码各跑一次 | 均全绿 |
| pylint（CI 门禁） | `pylint --rcfile=.pylintrc <现有源文件>` | 9.87/10（剩余告警为既有 R0901/R0903 与 `create` 分支的 R0911） |

浏览器 E2E 在真实 Vue 应用上验证：表单登录 → 证书树渲染（16 张卡片 / 3 个根）→
客户端过滤 → **点击**主题切换（断言 `body` 背景 `rgb(246,247,249)` → `rgb(22,24,28)`、
写入 localStorage、跨客户端导航与整页刷新保持）→ 打开吊销弹窗（断言目标/CSRF/RFC 5280
原因/本地仅记录警告）→ 提交并断言成功消息与吊销标记、吊销按钮消失 →
经 UI 创建叶证书并断言出现在表格 → 非 staff 访问审计被拒（403）→ 登出回到登录页。

### 10.5 仍未修复（与第 9.3 节一致，未因重写而改变）

私钥明文落库、无 CRL/OCSP（吊销缺少密码学效力）、`ca.py` 的 `utcnow`、
叶证书缺 KeyUsage、登录无限速。前端重写不改变这些结论。

### 10.6 顺带修掉的旧问题

- `.dockerignore` 不再排除 `migrations/`；`start.sh` 不再运行时 `makemigrations`。
- `Dockerfile` 改为多阶段：node 阶段 `pnpm install --frozen-lockfile && pnpm build`，
  Python 阶段只装运行时依赖（剔除 pylint/autopep8），并以非 root 用户运行。
- `Dockerfile` 基础镜像从 Python 3.10 提到 3.12，与 CI 对齐。

---

## 11. 第二轮加固（2026-09-28）

按用户要求处理审计遗留项。本节记录改了什么、如何验证，以及**仍然没有解决的部分**。

### 11.1 私钥静态加密（关闭 P0-3 的根因）

**威胁模型**（必须先说清，否则会高估收益）：防的是「拿到数据库文件或备份的人」——
`docker cp`、卷快照、误提交、磁盘镜像。**不防**掌握运行中服务器的人（内存里有解封后的
根密钥）、不防有权限的合法用户、不防知道口令的人。这是静态数据保密，不是入侵防御。

**方案：信封加密 + 每行 AAD**

```
口令 ──scrypt(N=2^15,r=8,p=1)──► KEK（永不落盘）
KEK  ──AES-256-GCM───────────► 每用户根密钥（封装后入库）
根密钥 ──HKDF(kind|id|serial)─► 每张证书的密钥（按需派生，不落盘）
每张证书的密钥 ──AES-256-GCM(AAD)──► 私钥 PEM
```

- 用**根密钥**而非直接用口令加密每把私钥：改密码只需重新封装 32 字节，
  不必重加密全库；将来换 KMS/HSM 也只需接管封装这一步。
- **AAD 绑定证书身份**：把 A 行的密文粘贴到 B 行，解密会失败而不是静默返回错误的密钥。
- 原语全部来自既有依赖 `cryptography`（`Scrypt` + `AESGCM` + `HKDF`），**未新增依赖**。

**行为变更（安全降级点，已按最佳实践定）**

- **删除 `/api/download/<serial>/private/`**：明文导出会让静态加密形同虚设
  （一次点击就把私钥写进浏览器下载目录）。私钥只能以**强制口令的 PKCS12** 导出。
- 签发（根/中间/叶）现在要求密钥库**已解锁**；未解锁返回 `409 vault_locked`，
  前端弹出解锁对话框并自动重试。

**诚实的边界**：`vault_status`（API 与 `manage.py vault_status`）会明确列出
`plaintext`（历史明文密钥）与 `orphaned`（无属主、**永远无法加密**）的数量，
不会把「部分加密」说成「已加密」。

**命令**：`manage.py rewrap_keys --username <u>` 把历史明文密钥迁入密钥库（幂等、可 dry-run、
逐条报告失败且不中断）；`manage.py vault_status` 只读盘点。

### 11.2 其余各项

| # | 事项 | 结果 |
| --- | --- | --- |
| 3 | 全部改 UTC | `ca.py` 6 处 `utcnow()` → `datetime.now(timezone.utc)`；全仓库已无 naive datetime 调用 |
| 5 | 登录 API 限速 | 新增 `LocalCA/throttle.py`：按 IP 与按账号各 5 次/15 分钟，超限 429 + `Retry-After`；成功登录清零；失败固定加 300ms 延迟以抹平时序；缓存键有上限且会过期。纯标准库实现，**未新增依赖**。**局限**：基于 locmem，多进程/多副本不共享——已在代码与文档中写明 |
| 6 | Docker | 修正容器布局（见 11.3）、移除 nginx 的应用源码挂载、拆分 dev 依赖、加 `CMD`；**实际构建并在容器内验证** |
| 7 | 依赖升级 | `Django 5.2.11→5.2.17`（**留在 5.2 LTS**）、`cryptography 44.0.1→50.0.1`、`gunicorn 23.0.0→26.2.0`、`pylint 3.3.1→4.0.9`；dev 依赖拆到 `requirements-dev.txt`，生产镜像不再安装 linter |
| 2 | CRL/OCSP | **按用户指示暂不处理** |
| 4 | KeyUsage / path_length | **按用户指示暂不处理**（无限下签是设计意图） |

### 11.3 Docker 验证中发现并修复的真实缺陷

| 缺陷 | 后果 | 修复 |
| --- | --- | --- |
| **容器布局与仓库布局不一致** | `settings.py` 由 `BASE_DIR.parent/'frontend'/'dist'` 推出 `/frontend/dist`，而镜像把应用放在 `/app`，该路径为 `/frontend/dist` 不存在 → **容器只服务「frontend not built」兜底页**，前端完全不可用；同时 `collectstatic` 报警告 | 镜像改为镜像仓库布局（`/app/localca_project` + `/app/frontend/dist`），并在 Dockerfile 中写明原因 |
| `initadmin` 仍创建 `admin/password` | 每次新部署都有一个公开的弱口令超级用户，且**明文打印进容器日志**；README 还在宣传这个口令 | 无内置口令：优先读 `DJANGO_SUPERUSER_PASSWORD`（不回显），否则随机生成并只打印一次；README 已更正 |
| `docker-compose.yml` 卷定义自相矛盾 | 同时声明具名卷 `db:` 与绑定挂载 `./db:/app/db`，注释却称数据在具名卷里 | 统一为绑定挂载（与文件其余部分一致），并在所有 compose 文件顶部写明「数据库在哪、怎么备份」 |
| nginx 挂载了应用源码 | 无必要，且一旦 nginx 被攻陷可写源码 | 只挂载静态文件卷（只读） |
| `/api/` 未匹配路径回落到 SPA | 客户端拿到 HTML 200，把拼错的端点当成成功 | 新增 JSON 404 兜底（`/api/<path>`） |

### 11.4 验证证据

| 层次 | 命令 | 结果 |
| --- | --- | --- |
| Django 测试 | `DJANGO_TESTING=true manage.py test LocalCA` | **113 passed**（新增 `tests_vault.py` 37 项） |
| 浏览器 E2E | `python .scratch/spa_e2e.py` | **34/34**（含「未解锁时签发会弹解锁框 → 解锁 → 自动重试成功」） |
| 匿名 E2E | `python .scratch/spa_e2e.py --anonymous` | **8/8** |
| Docker 构建 | `docker build -t localca-verify .` | 成功（node 构建前端 + python 运行阶段） |
| 容器运行 | 真实 `docker run` + 绑定挂载库 | SPA 与 API 均正常；`staticfiles` 警告 0；迁移 `0001/0002/0003` 全部应用；`vaultrootkey` 表存在 |
| 非 root / 依赖裁剪 | 容器内 `id` 与 import 探测 | `uid=10001(localca)`；`pylint`/`autopep8` 均不存在 |
| 初始口令 | 两种场景各起一个容器 | 未设变量→随机口令且可用它登录、日志无 `Password: password`；设变量→不回显 |
| cryptography 50 | 真签发 根→中间→叶 + PKCS12 | 链验证通过、SAN 正确、`not_valid_after_utc` 为 aware、`.p12` 内无明文私钥 |
| pylint 4 | CI 门禁 | 9.39/10（修掉一处真实的参数遮蔽 `W0621`） |

### 11.5 仍然未解决 / 需要你知道的

1. **CRL / OCSP 仍缺**（按你指示）。吊销依旧只在本应用内记录，对已分发证书无密码学效力。
2. **密钥库的解锁是进程内状态**。多 gunicorn worker 或多副本时，一个 worker 被解锁不会
   让其他 worker 也解锁（签发请求可能落到未解锁的 worker 并返回 409，前端会再弹一次）；
   反之亦然。单进程部署不受影响。若要多副本，需要把根密钥交给共享后端（KMS/Redis+封装）。
3. **忘记口令 = 私钥永久不可恢复**，这是设计选择，没有后门。UI 与 README 都已明示。
4. **无属主的历史证书私钥无法加密**（没有口令可派生）。`vault_status` 会计入 `orphaned`
   并提示指派属主或删除；在此之前它们仍是明文。
5. **前端三个 major 版本未升级**：`vite 7→8`、`vue-router 4→5`、`pinia 3→4`。
   这些是破坏性迁移，不属于「修复依赖冲突」，本轮刻意留在当前大版本。
6. **`DJANGO_SUPERUSER_PASSWORD` 未设置时口令会出现在容器日志里一次**。
   这是首次启动的引导妥协；要避免就显式设置该变量（推荐）。

---

## 12. 第三轮：部署契约回归与旧数据升级复验（2026-09-28）

起因是一个直接提问：**「把新镜像直接替换进旧 compose 文件，能正常运行并读取旧数据吗？」**
实测答案分四层，其中第 2、3 层是本轮才发现的**真实回归 / 真实破坏**，第 11 轮遗漏了它们。

### 12.1 结论

| 层 | 旧部署只换镜像会怎样 | 处理 |
| --- | --- | --- |
| 启动前置 | 缺 `DJANGO_SECRET_KEY` 直接拒启；`DJANGO_DEBUG=false` 时还必须有 `DJANGO_ALLOWED_HOSTS` | 补 `.env`（照 `.env.example`） |
| **数据/静态卷挂载** | **静默失效**：compose 仍挂 `/app/db`、`/app/staticfiles`，而新镜像的库与静态文件在 `/app/localca_project/` 下。容器照常起来，但**自己新建一个空库**，nginx 的静态目录也是空的（CSS/JS 全 404）。数据没丢，只是没被挂上 | 四个 compose 的 `web` 卷目标改为 `/app/localca_project/db`、`/app/localca_project/staticfiles` |
| **文件属主** | 旧镜像以 root 运行、库归 root（绑定挂载则归宿主账号），新镜像默认 uid 10001 → 启动即 `attempt to write a readonly database` | ① `docker build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g)`；② 或用 root 容器 `chown -R 10001:10001 <卷目录>` |
| 数据本身 | **兼容**：迁移就地应用，账号/口令/证书/吊销/审计全部保留 | `manage.py rewrap_keys --username <u>` 把旧明文私钥迁入密钥库 |

**回归根因**：第 11 轮为修 `FRONTEND_DIST` 把镜像布局从「扁平 `/app`」改成「镜像仓库布局
`/app/localca_project`」，但**只改了 Dockerfile，没动任何 compose**；而 11.3/11.4 的容器验证
用的是显式正确的 `-v …:/app/localca_project/db`，**绕过了 compose 契约**，所以编排文件里的
旧路径当时没被暴露。教训：改动镜像内路径后必须用**编排文件本身**（而非手写 `docker run`）
做验收，否则卷映射会静默失配 —— 这类故障不会报错，只会「看起来数据没了」。

### 12.2 复验证据（本轮实跑）

| 验证 | 做法 | 结果 |
| --- | --- | --- |
| 默认构建（含 `ARG APP_UID/APP_GID` 新改动） | `docker build -t localca-verify .` | 成功 |
| uid 可覆盖 | `docker build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g)` | 成功；容器内 `uid=1000(localca)`、`manage.py` 可读、直接写宿主目录库文件成功 |
| 镜像内真实路径 | 容器内读 `settings` | `DB=/app/localca_project/db/db.sqlite3`、`STATIC_ROOT=/app/localca_project/staticfiles`；`/app/db` 在镜像里**不存在** |
| 旧挂载点（回归证据） | `-v <hostdir>:/app/db` + `migrate` | 挂载点为**空**，库落在 `/app/localca_project/db/` → 卷完全没被使用 |
| 静态卷（同款回归） | `-v <hostdir>:/app/staticfiles` + `collectstatic` | 挂载点 **0** 个文件，`/app/localca_project/staticfiles` **4** 个文件 → nginx alias 到 `/app/staticfiles` 必然 404 |
| **旧库升级（决定性）** | `08db704` worktree 建旧库 + seed → 新镜像（属主匹配 + 补 `.env` + 修正挂载） | 迁移 `0002`、`0003` **就地应用**；`operator` 账号用**旧口令**经 `/api/login/` 登录成功；根/中间/叶（含 SAN）、吊销（含旧版自由文本理由 `superseded by policy`）、审计 2 条全部保留；`protected=false` 如实标注旧密钥仍为明文 |
| 旧私钥迁移 | `vault_status` → `rewrap_keys --username operator` | 4 把明文 → 4 把封装，复盘点 `plaintext=0` |
| **编排文件验收** | `docker compose -p lcatest up -d --build`（修正后的 `docker-compose.yml`，nginx:80） | 全栈起来；`GET /` 200、`/static/assets/app.js` **200 (114KB)**、`app.css` **200 (24KB)**、`/api/session/` 200、`/api/nope` 404（JSON 兜底）、SPA 深链 `/create/leaf` 200；nginx 侧静态卷 **141** 个文件 |
| 四个 compose 可解析 | `docker compose -f <file> config` | 全部 OK |
| 后端测试 | `DJANGO_TESTING=true manage.py test LocalCA` | **113 passed** |

### 12.3 本轮改动

| 文件 | 改动 |
| --- | --- |
| `Dockerfile` | 新增 `ARG APP_UID/APP_GID`（默认 10001）；`groupadd`/`useradd`/`chown`/`USER` 全部改用它们，使镜像可构建成与既有卷属主一致 |
| `docker-compose.yml` | `web` 卷改为 `/app/localca_project/{db,staticfiles}`；移除与旧布局绑定的 `./localca_project:/app` 源码覆盖挂载；`build.args` 从 `.env` 注入 `APP_UID/APP_GID` |
| `docker-compose-from-registry.yml`、`…-arm.yml`、`…-traefik.yml` | `web` 卷目标同步到新路径；顶部注释更正库位置并指向 README 升级章节（nginx 挂载点不变，共享同一个卷） |
| `README.md` | 新增「Upgrading from an earlier version」：三项破坏性变更、卷改动示例、属主两种解法、数据兼容性、回滚前提 |
| `.env.example` | 增加 `APP_UID/APP_GID` 说明（仅源码构建使用） |

### 12.4 仍未做的 / 边界

1. **回滚未实测**。迁移只加列/加表，但**没有验证旧镜像能读新 schema**；README 因此要求
   回滚必须先还原升级前的库备份，而不是承诺向后兼容。升级前请**先复制库文件或卷**。
2. **`rewrap_keys` 的口令仍是命令行参数**，会进入 shell 历史与进程列表。本轮未改；
   若要更安全应支持从 stdin/环境变量读取。
3. **多副本 / 多 worker 下密钥库仍不共享**（见 11.5 第 2 条），与部署路径改动无关。
4. 本轮**没有**改任何 Python 业务逻辑，除 `rewrap_keys` 输出文案的统计修正（见 12.5）。

### 12.5 顺带修掉的一个真实文案缺陷

`rewrap_keys` 原先输出 `Wrapped 3 key(s); 0 failed; 3 already wrapped.` ——「封装了 3 把」
与「已有 3 把」自相矛盾（后者统计的是**执行后**的状态）。已改为只报本次实际封装数与
失败数，随后单独打印 `After:` 盘点行；本轮 4 把密钥的迁移输出已验证为
`Wrapped 4 key(s); 0 failed.` + `After: wrapped=4 plaintext=0`。

---

## 13. 第四轮：证书导入（2026-09-28）

按用户要求新增「导入证书」能力，用于把已有的 CA / 证书链搬进 LocalCA。第 11 轮曾把
「本版本只签发、不导入」写进结论（11.1）与 README（12.1），本轮把这句话**改写为**：
导入是受支持的一等能力，但私钥仍只进不出、入库即封装。本节记录它带来的攻击面变化与论证。

### 13.1 能力与边界

| 项 | 结论 |
| --- | --- |
| 入口 | 新页面 `/import` + `POST /api/import/`（multipart；`dry_run=1` 出计划，`dry_run=0` 落库） |
| 支持格式（按内容识别，不看扩展名） | PEM（单/多/整链、证书与私钥同文件或分文件、`TRUSTED CERTIFICATE` 标签）；私钥 PKCS#8 / PKCS#1 / SEC1 / **加密** PKCS#8 / 传统 OpenSSL 加密 PEM；DER（证书/私钥/PKCS#7）；PKCS#7 = P7B/P7C（DER+PEM）；PKCS#12/PFX（含附加链证书、空口令、单密钥条目）；ZIP 打包上述任意格式 |
| 明确不支持 | JKS/JCEKS（需新增 `pyjks` 依赖，与本项目零新增依赖约定冲突，给 keytool 转换指引）；SSH 密钥与 SSH 证书；PGP；CRL（识别后忽略并说明） |
| 分层规则 | 自签 CA → 根；中间 CA 必须挂在根下、叶必须挂在中间 CA 下；**由根直接签发的终端证书**与**自签名终端证书**在 root/intermediate/leaf 模型里无法表示，计划中判为 `unsupported` 并说明原因，不硬塞 |
| 查重 | 同 SHA-256 指纹 → `skip`；同序列号但指纹不同 → `conflict`（`serial_number` 全表唯一，只能人工处理）；库里已有该证书但无密钥、批次带密钥 → `attach_key` |
| 属主 | 导入者即属主；只能挂到自己的 CA 下（staff 可挂任意 CA）——否则任何登录用户都能往别人的层级里塞行，而证书树是全员可见的 |
| 限制 | ≤8 文件、单文件 ≤1 MiB、总计 ≤5 MiB、单次 ≤200 个证书/密钥；ZIP 另有条目数/解压体积/压缩比上限 |
| 审计 | 每张写入一条 `IMPORT`（含指纹前缀与是否带密钥），另有一条汇总 |

### 13.2 攻击面变化与论证

**导入不新增任何权限。** 任何已登录用户本来就能自建自签名根 CA 并签发（`api_create_certificate`
只要求登录 + 已解锁的密钥库），导入只是把「自己生成的」换成「别处生成的」，且作用域仍限
自己的账户。因此本轮没有引入新的权限提升路径。

新增的真实风险面是**上传解析器**，已按下表收口：

| 风险 | 控制 |
| --- | --- |
| 大文件 / 海量对象 / 解压炸弹 | 文件数、单文件、总大小、对象数、ZIP 条目数/解压体积/压缩比全部设上限，超限 400 |
| 上传物残留 | 服务端**不暂存**：dry run 与 commit 各自解析同一批文件，密钥材料只在请求内存里存在 |
| 明文私钥落库 | 导入私钥只经 `keys.store_wrapped_key`，与生成路径同一条代码；旧明文字段写 '' |
| 绕过密钥库 | 带密钥的导入需要已解锁，未解锁返回 409 `vault_locked`（复用前端既有解锁流程） |
| 往别人层级塞证书 | 父级属于他人 → `conflict`（staff 例外，与 `can_manage_certificate` 语义一致） |
| 无密钥 CA 被当成可签发 CA | `keys.issuers_with_key()` 把无密钥 CA 从 `/api/issuers` 与两个签发表单的 queryset 中排除（而非让用户填完表单再吃 409） |
| 密钥材料进入日志/审计 | 审计只记名称、指纹前缀与是否有密钥，不含任何密钥内容 |

**不变量保持不变**：仍然没有明文私钥下载端点；私钥仍只以强制口令的 PKCS12 导出；密钥仍
要求已解锁才能使用。

### 13.3 验证证据

| 层次 | 做法 | 结果 |
| --- | --- | --- |
| 格式矩阵 | `tests_import.ImporterFormatTests`（28 项，`cryptography` 现造夹具，不依赖 openssl） | PEM/DER/PKCS7/PKCS12/ZIP、加密 PKCS#8、传统 OpenSSL 加密 PEM、`TRUSTED CERTIFICATE`（含尾部信任数据）、CSR/SSH 忽略、垃圾拒绝、四类上限、去重 全部通过 |
| 规划与执行 | `ImportPlanTests` / `ImportApplyTests` | 层级重建、挂到已存根、父级缺失、根直签叶、自签终端证书、已存在跳过、补钥匙、序列号冲突、重名改名、他人 CA 越权、staff 例外、覆盖项、逐条失败隔离 |
| API | `ImportApiTests` | 401 / dry run 不写库 / 未解锁 409 / 落库并出现在证书树 / 密钥为封装密文且旧明文字段为空 / 无密钥证书 `has_key=false` 且不出现在签发菜单 / staff 可见 / 非法 overrides 400 / 未知格式 400 / 审计落账 / meta 暴露格式 |
| 真实调用链（实测） | 对 `:18001` 的 SPA API 用 dev 账号走完整流程 | 登录 → `/api/vault/status/`（wrapped=3, unsealed=false）→ 无密钥链 dry run（create×2，父级正确）→ commit（root+intermediate 落库）→ 证书树出现且 `has_key=false` → `/api/issuers/` 只剩原有带密钥 CA（无密钥的两个被排除）→ 带密钥 PKCS12 dry run 显示 `attach_key` 与 `requires_vault_unlock=true` → 未解锁提交返回 **409 vault_locked** |
| 测试总量 | `DJANGO_TESTING=true manage.py test LocalCA` | **180 passed**（原 113 + 新增 67） |
| lint | `pylint LocalCA/importers.py LocalCA/import_service.py` | 9.72/10（与仓库基线 9.3 相比不劣化；`tests_import.py` 9.11 高于既有测试文件 8.39） |

本轮实测中发现并修掉的两个真实缺陷（都不是推理）：

1. `('import', fingerprint)` 是二元组而执行层按三元组解包 → **整条链只有根被写库**，
   中间 CA 与叶静默进 `failed`。由「链式导入落库」这一条真实调用链暴露，测试已固化。
2. 已存在的行在计划里被显示成 `名称 (imported)`（改名避让逻辑被错误地套用到不会写入的行），
   会误导操作者以为该证书将被重命名。已改为：`skip`/`attach_key` 显示库中真实名称，
   除非操作者显式覆盖。

另外，`cryptography` 的 PKCS#12 错误把「不是 PFX」与「口令错误」报成同一种 `ValueError`，
因此判别必须靠外层结构（`SEQUENCE { INTEGER 3, ... }`）而不能靠异常文本——否则一张普通
DER 证书会被误报为口令错误；`TRUSTED CERTIFICATE` 的尾部信任数据 `cryptography` 也不接受，
需先截取首个 DER 对象。

### 13.4 仍未做的 / 边界

1. **没有「导入来源」列**。本轮刻意不动 schema（不出迁移 `0004`），来源只体现在审计日志里。
2. **JKS 仍不支持**（依赖决策），README 给 `keytool -importkeystore` 转换指引。
3. **PKCS#12 只支持单密钥条目**：`cryptography` 无法枚举多密钥条目的 p12，需逐个导出。
4. **导入的证书不会覆盖既有同名证书**，只跳过或报冲突；没有「替换」语义。
5. **无密钥的 CA 永远不能签发**，只能作为登记与信任链的一环存在（这是设计，不是缺陷）。
6. 导入**不改动**已分发证书：吊销在这里仍只是记录，没有 CRL/OCSP（见 11.5 第 1 条）。
