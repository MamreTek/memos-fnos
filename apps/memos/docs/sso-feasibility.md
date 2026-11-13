# REQ-002 技术验证记录

日期：2026-11-13；分支 `issue/3`，基于合并后的 `main` `829aede`。本记录是技术门槛进展，不是飞牛免登录的完成或兼容声明。

## 当前结论

真实 Memos 26.11.0 的 OAuth2、原生账号绑定和浏览器刷新 Cookie 路径可用。授权码核心、浏览器登录事务及原生会话客户端现已实现并通过真实 Memos 接口测试；完整桥接尚未接入安装包，不能把飞牛 Header 直接当作 Memos 会话。用户在 fnOS 1.2.1010 上安装验证包并回传普通用户 JSON，确认 amd64 服务运行、网关可达及三项格式有效的身份头；另报告切换管理员后 is_admin=true、区分正常。独立浏览器打开方式和不可复用主体契约仍待确认。

官方网关只明确提供 `X-Trim-Userid`、`X-Trim-Username`、`X-Trim-Isadmin`。其中 UID 是否会在删除/重建后复用，现有文档未作保证。安装命名空间和哈希不能消除 UID 复用风险。没有可靠主体方案前不允许自动继承旧绑定。

用户已明确：删除用户只在飞牛执行，不接受本应用删除前手动解绑；旧笔记不能被新用户继承，保留给 Memos 管理员使用原生登录后的受保护能力处理。D-001 已决定，不再等待用户接受手动操作。2026-11-13 重新读取官方 llms.txt / llms-full.txt，与前次完整文档一致；公开 API 索引仍未给出不可复用账号主体或账号删除事件契约。这是当前技术能力缺口，不是尚待用户批准的操作。

## 已运行的验证

| 范围 | 结果与限制 |
| --- | --- |
| 目标 fnOS / 网关 | fnOS 1.2.1010（用户报告）；用户回传 0.0.1 / amd64 / gateway_headers_present=true / is_admin=false，随后报告管理员为 true、区分正常。身份指纹仅保存在仓库外的私有证据，不公开；第二份完整 JSON 未取得，未将其当作代理亲自采集的双用户证据 |
| 未登录 / 伪造 Header | 对实际网关发出不带 Cookie/Token、伪造 X-Trim-Userid/Username/Isadmin 的请求，HTTP 200 / text/plain 返回 invalid token，没有身份 JSON。该检查证明无会话的伪造头未获授权，不代表有效会话中的全部头覆盖行为已测 |
| Go 授权码核心 | auth-test 的 race / vet 通过；覆盖 S256、精确回调、客户端认证、过期/重放/并发、错误不反射凭据和私有路由限制。真正跨监听器隔离尚未实现 |
| 浏览器登录事务 / 原生客户端 | 新增 state + 独立 HttpOnly Cookie + 服务端 PKCE 事务，最多 1024 条、5 分钟、并发一次性消费；跨浏览器/重复 Cookie/重复参数/过期均拒绝。原生 Connect 客户端检查当前用户及刷新 Cookie、拒绝重定向/超限响应/非法属性，敏感错误脱敏。race / vet 通过；未发布 HTTP 登录路由或浏览器页面 |
| Unix 网关授权 Handler | 新增 `internal/gateway`，在真实 Unix 连接上下文中接受固定路径/单值身份头和精确授权参数，TCP 伪造头拒绝；必须注入稳定主体 Resolver，缺失或失败不签发授权码，不回显身份/内部错误。真实本地 Unix/TCP 的 race / vet 测试通过；尚未接线到应用服务，不证明平台账号生命周期已解决 |
| 新组件对接真实 Memos | HTTP 与 HTTPS 部署上下文的真实 Go 授权码核心 → 浏览器事务 → 原生 Connect 客户端 → Memos 26.11.0 通过；回调重放拒绝、普通成员、原生当前用户确认、刷新 Cookie 轮换及退出后拒绝刷新通过。NAS 主体为 fixture；未执行浏览器 DOM、TLS、代理或 NAS 跳转。新组件 ARM64 测试二进制已交叉编译，未运行 |
| 核心对接真实 Memos | auth-integration 通过：实际 Go token/userinfo Handler 与官方 26.11.0 release 完成交换、不同普通用户/重复映射、私有笔记隔离、原生刷新/退出及保留密码登录；ARM64 测试二进制交叉编译通过，未运行 |
| 原生管理员恢复 | 扩展 auth-integration 通过：管理员重新密码登录后读取已知私人笔记并导出临时归档成员的保留笔记；匿名导出 401，另一普通成员导出/读笔记 403，导出不含另一成员私有内容，归档成员旧访问 Token 401。原生成员界面已有导出入口；未在 NAS 删除真实账号，未验证 fnOS 删除识别或删除后凭据自动撤销 |
| 原安装包检查与 13 项生命周期测试 | 通过；正式 packaging、镜像、权限和数据路径没有修改 |
| Go 网关验证程序 | `go test -race ./...`、`go vet ./...` 通过；覆盖身份缺失/重复/格式错误、路由/方法、敏感输入不反射、账号指纹及私钥保护 |
| 实际 Unix Socket / 进程 | 启停、重复启动、状态、重启保留指纹、私有控制路由隔离、卸载前停止通过；这是本机进程测试，不是 fnOS 平台验证 |
| 官方 fnpack 1.2.3 | 独立验证包构建通过；核对外/内层所有文件、manifest 校验、amd64/ARM64 ELF 和静态构建。ARM64 仅交叉编译，本机无 QEMU，未运行 ARM64 验证程序 |
| 最终 FPK 冒烟 | 从实际包中读取 amd64 静态程序与启停脚本，在临时目录完成 start/status/stop，通过 |
| 真实 Memos OAuth2 | 用测试 OAuth Provider 与官方 26.11.0 服务进行 PKCE 交换、两用户映射、重复登录及私有笔记交叉访问拒绝，均通过；测试 Provider 不替代 fnOS 网关验证 |
| 绑定与兼容性 | 原生受保护的 linked-identity API 将临时已有账号与外部身份绑定，原笔记保留；普通密码、PAT API 及关闭注册后拒绝新 SSO 用户通过 |
| 实际 Chromium 153.0.8010.12 | 未向网页注入访问 Token，原生 Memos 页面由 HttpOnly / SameSite=Lax Cookie 引导并展示 A 的私有笔记；清理旧缓存后进入 B 并展示 B 的笔记 |
| 缓存负面对照 | 只换 B 的刷新 Cookie、保留 A 的有效 localStorage Token 时，重新打开仍进入 A。已实测，正式方案必须处理，不能只替换 Cookie |
| 退出 | 原生 Connect SignOut API 后重用旧刷新 Cookie 被拒绝；尚未验收完整退出 UI、NAS 退出及全部并发标签页场景 |

本机 Docker daemon 需要交互式 sudo，本轮未重跑 `make APP=memos integration`，也未把本机进程/浏览器验证冒充该容器检查。完整生产桥接、auth-browser-test 尚未交付。新增 CI auth-probe 作业复现组件/探针测试、双架构构建及最终包 amd64 自检，旧主包/容器作业保留；新分支运行结果按实际记录。REQ-001 原基线的 amd64/ARM64 CI 已通过，但不能作为新 SSO 的验收结果。

### 会话接口的重要差异

该固定版本 REST `POST /api/auth/signin` 的刷新 Cookie 位于 `Grpc-Metadata-Set-Cookie`，浏览器不会自动保存。使用上游网页同样的 Connect `POST /memos.api.AuthService/SignIn`（`Content-Type: application/json`、`Connect-Protocol-Version: 1`）能返回标准 Set-Cookie，并由真实原生网页初始化。正式适配器应使用这个受支持的服务接口，并仅安全转发预期的 Memos Cookie。

不修改上游 JWT 签发、不编辑数据库、不关闭全局密码认证。清理两个缓存键只在固定版本的隔离技术验证中执行；正式实现仍需围绕有效旧 Token、在途刷新、多个标签页和 `memos_token_sync` 广播建立可验证的边界。当前单页测试不足以宣称整个账号切换验收已通过。

### 版本与来源

- 测试主机：Linux amd64，普通用户运行临时实例；所有数据库、测试账号、机密和私有笔记 fixture 均在测试结束后清理。
- 服务二进制：官方 [Memos 26.11.0 release](https://github.com/usememos/memos/releases/tag/26.11.0) 的 `memos_26.11.0_linux_amd64.tar.gz`。
- 发布包 SHA-256：`38b81c2bd1859555f4f7f277756541fd1ca332c94bbbee443626ace42d7b4061`，与该 release 的 checksums.txt 比对。
- 解压后二进制 SHA-256：`bd62d659f01efca3fdab21df3fa301e9dcd8c426203ffcdfa7fe7c686edab405`；`--version` 为 26.11.0。
- 尝试读取已固定的 OCI 镜像文件时，注册表文件重定向连接两次中断，因此本次会话验证改用校验过的官方 release 二进制；**不是固定 OCI 镜像的容器集成证据**。正式镜像与 Compose 未变。
- 浏览器：实际 Chromium `153.0.8010.12`，Playwright 新建空白浏览器上下文；没有使用已有个人浏览器会话。
- 网关验证候选包：`memos-sso-probe-0.0.1-all.fpk`，SHA-256 `6e40f1d99def670d07058ce49909fa40d2295d4fbc3aad0f885485e8946a9d64`。正式 Memos 0.1.3 的固定镜像校验及官方 fnpack 构建另行通过。

复现服务/浏览器验证需要安装 Python Playwright 及 Chromium，准备上述官方发布二进制，再从仓库根目录执行：

```sh
MEMOS_BINARY=/absolute/path/to/verified/memos make APP=memos auth-feasibility
```

脚本严格校验二进制 SHA-256，只启动新的临时实例和本机测试 Provider。它不会连接已安装的 Memos，不接受 NAS 密码，也不会输出 Cookie/Token。现阶段这个实验命令不能替代 PRD 的完整验证。auth-test、auth-integration 已提供，覆盖独立授权码核心、浏览器登录事务、原生客户端及真实 Memos 接口；auth-browser-test 仍待完整启动/回调/代理实现。核心边界与复现命令见 [auth-bridge](../auth-bridge/README.md)。

另只读检查了公开的非官方 [pyfnos 用户接口](https://github.com/Timandes/pyfnos/blob/main/fnos/user.py) 与其 [getInfo 测试](https://github.com/Timandes/pyfnos/blob/main/tests/test_user_get_info.py)。该测试要求 uid/name/isAdmin/groups，未建立不可复用用户主体或可靠删除通知契约。非官方接口存在本身也不能补足这个保证；未安装该 SDK、未用其登录 NAS、未采集 NAS 密码。

## 剩余门槛与交接

用户明确要求阶段性提交和新包测试后，新增 memos-sso-probe 0.0.2。它随包附上固定官方 Memos 二进制与四组静态 Go 测试程序；在 NAS 专用应用用户下使用回环临时端口和私有临时数据，启动后执行 endpoint、memosclient、browserflow、oauthbridge，自检结果在网关 JSON 的 `auth_checks` 返回。安装命名空间/UID 指纹保持 0.0.1 兼容，不连接正式 Memos，不把真实 NAS 身份绑定到笔记账号。原生临时 Memos 会话使用随机密码，测试结束或停止时清理自有进程/数据；原始测试日志仅在私有 0600 文件中。

本机最终 FPK 的 amd64 自检、启停、私有权限及临时数据清理通过；四组 cases 均为 passed。包 SHA-256 `0f5112825f844b24391a5a5e56f7e4feb48835378e6d62cd850f9edc040d45c5`，官方 fnpack 1.2.3 和全部双架构 ELF/内外载荷校验通过。ARM64 未运行。此交付允许 issue/3 的阶段性提交和草稿 PR，完整 SSO 仍为开发中，不交付可合并的完成声明。

用户随后回传实际 NAS 的 0.0.2 / amd64 JSON：`auth_checks.status=passed`，browserflow、endpoint、memosclient、oauthbridge 四组均 passed，Memos 版本 26.11.0，网关身份头有效、普通用户标记 false。与 0.0.1 私有证据逐项比较，安装、UID、用户名三项指纹全部不变；公开文档不保存具体指纹。该结果是用户提供的实机组件自检证据，系统版本沿用此前用户报告的 fnOS 1.2.1010，当前 JSON 未附构建号，代理未直接采集或核对设备上的包校验。它不验证完整浏览器/代理入口、删除重建隔离或 ARM64；`memos_sso_implemented=false` 仍是准确状态。

1. 正向网关已有用户回传证据，管理员切换已有用户反馈，无会话的伪造 Header 检查通过。仍需确认独立浏览器打开方式、退出后刷新及完整登录链路。浏览器工具仍读取失败，实机证据按用户回传记录，不存密码、原始 UID 或用户名。
2. 取得平台可靠主体及账号生命周期契约，自动防止删除/重建后旧绑定继承，并满足仅管理员原生恢复的删除要求。用户已拒绝先手动解绑，不能继续列为待批准的兼容方案；不能用“首次测试未复用”、轮询或 Memos 临时成员归档替代这个保证。
3. 门槛满足后再完成正式三监听器桥接、首次接入/原生绑定、端口代理、持久配置与备份恢复、并发标签页保护，以及完整协议/容器/浏览器测试。
4. 核心可以独立推进，但完整实机/身份生命周期门槛仍未满足；当前不提交“已完成”的待合并 PR、不改正式登录路径、不声称 NAS SSO 可用。Issue #3 保持开发中；产品要求已明确，尚缺受支持的自动生命周期识别方式。

技术依据：[飞牛统一网关](https://developer.fnnas.com/docs/core-concepts/gateway-registration)、[飞牛开放 API 概述](https://developer.fnnas.com/api/overview)、[Memos Authentication](https://usememos.com/docs/configuration/authentication)、Memos 提交 `b40d8a7b573774c52b022c8d6537d6baf2129dc0` 的 `server/api/auth_service_session.go`、`server/api/header_carrier.go`、`core/access/memo.go`、`server/fileserver/memo_export.go`、`web/src/components/Settings/MemberSection.tsx`、`web/src/contexts/AuthContext.tsx`、`web/src/auth-state.ts` 与 `provider/idp/oauth2/oauth2.go`。
