# 9955HX 登录状态与 Token 小工具

Python 标准库服务和原生中文页面，复用本机既有 `ccxi-token` / `ccxi-admin-token`。仅固定账户 `zhkyy` 和 `rms-t` / `rms-pre` / `admin-t` / `admin-pre`；不提供任意账号、HTTP、Shell 或业务写入入口。本目录不包含凭证。

## 访问与使用

入口：`https://shiki-9955hx.tailaed862.ts.net:8446/`。9955HX 需在线，真实认证还需要其企业网络、DNS/aTrust 与账户授权。页面打开只查询状态，不会自动登录。

1. 选择环境，点击“获取当前 Token”：优先返回仍有效缓存，仅在需要且协议支持时尝试刷新。
2. Admin 有可用 refreshToken 时可点“刷新 / 续期”，明确请求上游换取 Token。RMS 缓存有 ticket 和访问令牌时也提供显式刷新：调用固定只读 `GET /sino-workbench/permission/headMenu` 验证会话，可能更新认证会话；仅当访问令牌已过期且服务器刷新会话仍有效时，才可能从 `refreshToken` 响应头取得新 Token。令牌未到期且没有新响应头时仍返回缓存。首次登录、缺少凭据或会话失效时使用网页登录。
3. 展开“登录 / 重新登录”，在 HTTPS 页面输入固定账户的密码，提交后输入立即清空。密码仅供本次登录，不新增密码文件，不暗示已接入系统密钥环。
4. 结果按服务实际 `source` 区分“本地缓存 / 上游登录 / 上游刷新”。刷新操作返回 `source=cache` 时明确表示未签发新 Token，不称续期成功。RMS 只有在旧令牌已过期、收到新响应头、HTTP 200 / code 200 且有效期延长等协议检查通过后才返回 `source=refresh`。Token 默认遮罩，可显式显示、复制和清除；认证成功不代表业务接口授权已验证。

验证码、MFA 或 SSO 授权等人工步骤只按服务实际结果提示，不猜测具体挑战、不绕过认证。连接中断或超时时可能无法确认操作结果，先更新只读状态再决定是否重试；页面不自动重放登录。

## 运行和边界

运行环境为 Linux、Python 3 标准库；前端无需安装或构建。`provider.py` 直接加载本机既有认证助手模块，仓库不包含这些助手及其私人配置：

| 能力 | 必须存在的本机模块 |
| --- | --- |
| RMS | `~/.local/share/ccxi-token/ccxi_token.py` |
| Admin | `~/.codex/skills/ccxi-admin-auth/scripts/ccxi_admin_token.py` |

`ccxi-token` / `ccxi-admin-token` 的命令行包装器本身不是本服务的调用入口；仅复制此仓库不能获得上述认证能力。助手应在对应执行设备通过其既有受信任安装方式准备，不复制其他机器的密码、Token、缓存或私人配置。

新检出目录先复制无凭据模板，再人工将 `origin` 改为实际 HTTPS Origin、将 `identities` 改为被允许的准确 Tailscale 登录身份：

```sh
cp config.example.json config.json
# 人工编辑 config.json，确认真实 Origin 和身份后再启动。
python3 server.py --port 8844 --config config.json
```

现有部署目录为 `/home/shiki/code/it-tools-local/auth`。`config.json` 属于本机配置，已被 Git 忽略；示例中的 `.invalid` 地址和身份不能用于实际部署。`.gitignore` 使用源码白名单，缓存、日志、运行状态、备份及未审核的新文件默认不会进入仓库；需要新增源码时应同时审查白名单。

后端只绑定 `127.0.0.1`，由本机 Tailscale Serve 发布。`config.json` 固定 HTTPS Origin 和允许的 Tailscale 登录身份。页面及 API 检查 Host、来源及 Serve 注入身份；不得绑定组网/公网或允许普通代理伪造身份头。本机进程属于受信任边界。

现有用户服务为 `it-tools-auth.service`。服务单元、Tailscale Serve 映射及本机历史源码备份不在此仓库内。部署需保留这些设置、身份和来源约束；更新和回退由具备授权的执行者完成，并验证 `enabled` / `active`、重启恢复和实际网页。前端源码修改和模拟测试不代表部署或真实认证已通过。

## API 与隐私

- `GET /api/status`：只读缓存，包含时间、状态、实际 `capabilities`、冷却剩余秒数及去敏 `lastOperation`。缓存未过期不代表上游仍认可会话。
- `POST /api/token`：`{"env":"admin-t"}`，获取缓存或按需刷新。
- `POST /api/refresh`：`{"env":"admin-t"}`（或允许的 RMS 环境），显式请求受支持的刷新。RMS 使用固定只读会话验证入口，可能更新认证会话；不接受自定义 URL，未到期返回缓存不等于续期。
- `POST /api/login`：`{"env":"admin-t","password":"仅本次私有输入"}`，真实登录。密码非空、无自动重试；后端通过私有管道传递给认证执行器，不进入命令参数。
- 所有 POST 要求 JSON、准确 Origin、`X-Workbench-Request: 1`，拒绝额外账号、URL、命令及未知字段。不提供 CORS；所有响应 `no-store`，同源 CSP，关闭访问日志，不展示敏感原始异常或上游正文。
- 密码与 Token 不进入 URL、浏览器存储、构建文件或普通日志。上游普通文本工具可能保存 URL/本地输入的默认行为不适用于本认证页面。
- Token 只在当前页面内存，默认遮罩；切换环境、离开页面、5 分钟时限或已知到期会清除。后台页自动遮罩。显式复制后进入系统剪贴板，由用户自行按需清理。
- 登录密码提交即从输入框清除，切换环境或离开时也清除。页面不保存密码到密钥环，不搬运凭证到 3600。
- 同环境并发与失败冷却由后端控制；页面操作期间禁用重复按钮，状态查询不触发认证。失败不伪报成功，保留页面已有未过期 Token，仍明确上游状态未确认。已有助手缓存继续按助手协议管理。
- 上游明确拒绝续期后，按缓存文件版本（inode、mtime、大小）停止重复认证。只有这些非敏感版本标记保存在 `~/.local/state/it-tools-auth/refresh-rejections.json`，没有密码或 Token；新登录产生的新缓存不受旧标记阻止。服务重启会恢复此保护。

## 验证

现有模拟测试使用临时缓存和本地临时端口，认证请求均替换为模拟响应，不执行真实登录或刷新。其中协议响应测试仍需上述两个既有助手模块可导入；这不是独立可移植的助手实现。

```sh
cd /home/shiki/code/it-tools-local/auth
python3 -m unittest -v test_auth.py
python3 -m py_compile server.py provider.py test_auth.py
node --check app.js
```

模拟测试不等同于真实登录/续期。真实环境验证应记录环境、来源、认证端点确认、缓存/到期变化等去敏证据，不打印 Token、密码或原始认证正文。浏览器、Serve 身份、服务更新与回退的实测结果由交付报告单独记录。
