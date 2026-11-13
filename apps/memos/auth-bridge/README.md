# Memos fnOS 认证桥接（实现中）

当前实现包括 `internal/oauthbridge` 授权码核心、`internal/browserflow` 浏览器登录事务，以及 `internal/memosclient` 原生 Connect 会话客户端。它们尚未组成可运行的完整认证服务，也未接入现有 `.fpk`。保留 Memos 26.11.0、原生 linked identity 与原生会话的接口契约；正式 0.1.3 包未改变。

已实现并测试：

- 一个固定客户端、至多两个精确回调地址；拒绝前缀匹配、额外查询参数、userinfo URL 凭据及 fragment。
- 256 位随机、60 秒有效、单次使用的授权码，强制 S256 PKCE，绑定同一个客户端和原始回调；并发交换只有一次成功。
- Basic 或表单客户端认证，拒绝混合/重复参数、超限请求体和查询参数中的凭据。客户端机密按固定长度哈希进行常量时间比较。
- 60 秒 bearer 与最少的平坦 sub / display_name userinfo；短期记录仅在内存中保存随机令牌的哈希，限制容量并回收过期记录。
- 仅 token / userinfo 的私有 HTTP Handler，不提供身份签发路由，不根据客户端 X-Trim-* Header 授权；错误不反射请求中的授权码、机密或用户资料。
- 浏览器登录事务：随机 state、独立 HttpOnly / SameSite=Lax Cookie、服务端 S256 verifier，5 分钟有效且最多 1024 条；跨浏览器、缺失/重复参数、重复 Cookie、过期和并发回调被拒绝，合法回调在网络交换前单次消费。公开地址、NAS 地址和精确回调来自受验证配置，不从请求 Host 或转发头推导。
- 原生 Connect 客户端：SSO SignIn、GetCurrentUser、RefreshToken、SignOut；让 Memos 校验自己的访问 Token，拒绝通过未验证 JWT 内容确定用户。限制响应大小、关闭重定向和环境代理，验证预期的 host-only / HttpOnly / SameSite / Secure 刷新 Cookie，不把会话凭据序列化到页面或日志。
- 实际 Memos 26.11.0 调用这个 Go Handler 完成 PKCE 交换、普通用户映射、重复登录、私有笔记隔离、Connect 刷新 Cookie / SignOut 及密码登录检查。
- 新浏览器事务与原生 Connect 客户端也通过真实服务验证：使用测试主体串联真实 Go 授权码核心和 Memos，覆盖 HTTP、HTTPS 部署上下文对应的 Cookie、回调重放拒绝、刷新轮换和退出后拒绝刷新。HTTPS 上下文由配置控制；这不是浏览器 TLS 或真实 NAS 网关验收。
- 管理员重新通过原生密码登录后，可按上游权限读取已知私人笔记、导出保留成员的笔记；临时 Memos 成员归档后这些路径仍可用，普通成员和匿名导出被拒绝，导出不包含另一成员的私人笔记，归档成员的旧访问 Token 被拒绝。仅验证临时 Memos 归档，不代表已识别飞牛删除事件或解决 UID 复用。

尚未实现：真实网关授权路由、可靠 NAS 主体映射及删除识别、浏览器启动/回调 HTTP 路由和页面交接、5230 代理与多标签页保护、配置持久化/备份、Compose 及安装向导接线。用户已拒绝删除前手动解绑的方案；不能将删除处理转嫁给用户。Authorize 只能由后续受信网关层在验证稳定身份后调用，不能把原始 UID/用户名直接当成不可复用主体。新事务完成后仅向服务端调用方返回原生会话，不发布 Cookie 或 HTML；后续必须先完成账号切换保护，不能直接将这个组件暴露为登录接口。当前代码不会监听端口或自动授予 NAS 用户 Memos 访问。

从仓库根目录验证：

```sh
make APP=memos auth-test
MEMOS_BINARY=/absolute/path/to/verified/memos make APP=memos auth-integration
```

使用 Go 1.26.8；核心仅依赖标准库。auth-test 运行 race 单元测试和 vet；未设置 MEMOS_BINARY 时不运行独立的真实服务测试。auth-integration 必须显式提供当前 Linux 架构对应的官方 Memos 26.11.0 release 二进制：amd64 SHA-256 `bd62d659f01efca3fdab21df3fa301e9dcd8c426203ffcdfa7fe7c686edab405`，ARM64 `06e8b9cda66209abb5dcdd5c9c512e172fc6dce088e19af8c0ddb94d1ffca9b6`。只启动普通用户的临时实例和本机测试接口，结束后清理，不连接 NAS 或已有 Memos 数据。

ARM64 已交叉编译授权码核心、浏览器事务和原生会话客户端的测试二进制，尚未运行。上述接口测试不代替真实网关/浏览器完整链路、TLS Cookie、容器双架构、账号删除重建和备份恢复验收；auth-browser-test 仍待完整流程实现。技术记录见 [SSO 验证记录](../docs/sso-feasibility.md)。

独立的 [memos-sso-probe 0.0.2](../tests/fnos-gateway-probe/README.md) 已打包四组实际测试程序和两种架构的固定 Memos 二进制，可在目标 NAS 用临时实例运行并返回 `auth_checks`。本机从最终 FPK 验证 amd64 全部通过；它不是对正式 Memos 启用 SSO 的安装包。

协议依据：[RFC 6749 客户端认证](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)、[RFC 7636 S256 校验](https://www.rfc-editor.org/rfc/rfc7636#section-4.6)。当前仅是这些接口契约的实现片段，不宣称完整 OAuth/OIDC 服务已交付。
