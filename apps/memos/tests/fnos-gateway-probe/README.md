# fnOS 网关验证包（REQ-002 技术门槛）

这是独立的 `memos-sso-probe` 0.0.2 测试应用，不是 Memos 日常免登录升级包。它通过 Unix Socket 提供诊断，并在本机回环临时端口运行一次性的 Memos 26.11.0 测试实例；不开放 LAN 端口、不使用 Docker、不连接现有 Memos，不读取 NAS 密码或真实笔记。正式包仍是 `memos-fnos` 0.1.3，端口仍为 5230。

本版将真实的授权码核心、浏览器登录事务和原生会话客户端编译为双架构测试程序，随包附上固定且校验过的官方 Memos 发布二进制。每次启动顺序运行 endpoint、memosclient、browserflow、oauthbridge 四组测试，覆盖回调防重放、原生登录/刷新/退出、普通成员隔离与管理员恢复；测试主体、账号、密码和笔记均为临时 fixture，结束或停止时清理自有进程及私有临时数据。通过不代表真实 NAS 主体映射、浏览器页面/代理交接或删除重建隔离已经实现。

本验证包使用 Go 标准库，输出 JSON 诊断数据，不新增产品前端。没有模拟成功的 Memos 登录页面。只有真实 fnOS 转发成功才能返回身份指纹；本地 Unix Socket 测试不代表 fnOS 已验证。

目标设备为用户报告的 fnOS 1.2.1010，符合声明的最低版本 1.1.3100。用户已回传 0.0.2 / amd64 JSON，四组自检均 passed、网关身份头有效；安装、UID、用户名指纹与 0.0.1 全部相同。原始指纹仅保存在仓库外的私有证据中。此为用户提供的实机结果，完整 SSO 和 ARM64 运行尚未验收。

## NAS 上验证

1. 通过应用中心手动安装/升级 `memos-sso-probe-0.0.2-all.fpk`，先核对同名 `.sha256`。已有同名 0.0.1 可直接升级，不替换 `memos-fnos`。包内含 x86_64、ARM64 静态程序；本机实际验证 amd64，ARM64 尚未运行。
2. 用测试账号 A 登录飞牛，点击 **Memos 登录验证**，记录是否打开独立浏览器标签页，以及显示的 JSON。若桌面不能打开，手动在飞牛地址后添加 `/app/memos-sso-probe`，单独记录结果。
   新字段 `auth_checks.status` 初始可为 `running`；等待几秒后刷新。预期为 `passed`，四个 `cases` 都为 `passed`。若为 `failed`，回传 JSON 中的安全错误码，不回传日志中的任何凭据。`memos_sso_implemented=false` 仍是准确的状态。
3. 关闭该页、退出飞牛，用同一浏览器登录测试账号 B，重新点击入口。两次 `installation_fingerprint` 应相同，`uid_fingerprint` 应不同。重新登录 A，应恢复 A 的指纹。
4. 在未登录飞牛的无痕窗口打开同一地址，应由系统要求登录或拒绝访问，不能取得身份 JSON。退出 A 后刷新原页，也应由系统重新校验。
5. 在应用中心停止、启动验证应用，确认指纹不变。测试完成后可以单独卸载验证应用。

本轮先回传 0.0.2 的 JSON 和 fnOS 版本/构建号，重点看 `auth_checks`；已确认过的普通/管理员区分无需重复证明。JSON 不含原始 UID、用户名、Cookie、Token 或 NAS 地址；身份指纹只在同一次安装内可比较。不要回传 NAS 密码、会话 Cookie 或私人笔记。

错误码：`E_GATEWAY_IDENTITY` 表示没有收到格式有效的三项网关 Header；`E_ROUTE` 表示实际转发路径不符合文档契约。生命周期 `E_START_EXIT` 的具体安全错误码位于应用私有变量目录 `probe/service.log`；Socket 访问被系统拒绝、桌面入口不支持网关或最低版本不满足，都应原样记录，不能宣称免登录已可用。

自检错误码：`E_AUTH_PAYLOAD` 为包内测试载荷缺失/校验失败，`E_AUTH_SUITE` 为实际测试失败，`E_AUTH_CANCELLED` 为停止或超时，`E_AUTH_DIRECTORY` / `E_AUTH_LOG` 为私有目录/日志不可用。详情只保存在私有的 `probe/auth-check.log`（0600）；网关响应不回显测试日志、Cookie 或 Token。自检最长两分钟，不通过时不会连接正式 Memos 来绕过失败。

### 身份稳定性仍是单独门槛

`X-Trim-Userid` 在官方文档中是 UID。HMAC 指纹不能把可复用的 UID 变成不可复用身份。上面的 A/B 测试只能证明当前会话行为，不能证明删除/重建用户永不复用 UID。

若管理员另行验证删除/重建行为，只使用明确可删除的临时测试账号，不操作现有用户。记录重建前后 UID 指纹、改名后 UID/用户名指纹变化。一次未观察到复用也不足以保证未来不复用；正式桥接仍需要平台的稳定主体契约，或经确认的防止旧绑定继承方案。无法满足时先报告兼容性决策，不使用用户名自动认领旧 Memos 账号。

## 构建与测试

从仓库根目录执行：

```sh
make APP=memos gateway-probe-test
make APP=memos tools
make APP=memos gateway-probe-package
make APP=memos gateway-probe-smoke
```

需要固定 Go 1.26.8（Linux amd64 构建机）、Python 3.12+ 和已校验的官方 fnpack 1.2.3。可设置 `GOCACHE` 到可写目录，使用 `FNPACK=/absolute/path/to/fnpack` 指定工具。测试创建本机 Unix Socket 和短期进程。

构建器交叉编译两种架构，检查全部探针/测试/Memos 的静态 ELF，验证两份官方发布包及原始二进制的固定 SHA-256，核对官方 fnpack 外层及 `app.tgz` 的全部文件和 manifest 校验，再输出包、SHA-256 与构建信息到 `apps/memos/dist/gateway-probe/`。它不会打包本机身份指纹私钥。下载缓存位于 `.cache/memos-release`；离线构建可对 build.py 传入 `--memos-release-cache`，缓存仍必须符合固定校验。

`gateway-probe-smoke` 从最终 FPK 解出实际载荷，以本机专用临时目录执行真实启停、四组自检、私有文件权限及临时数据清理检查；不是 fnOS 实机验收。CI 会执行同一检查，并上传独立测试候选，原主包/容器验证继续保留。

最低系统版本 `1.1.3100` 来自[官方原生应用示例](https://developer.fnnas.com/docs/examples/native)的国内版统一网关声明，仍需记录目标设备实际构建号。入口刻意使用 `type=url` 来验证本需求的独立浏览器契约；[网关文档](https://developer.fnnas.com/docs/core-concepts/gateway-registration)只展示了 `iframe` 示例，因此不能预先宣称此组合受支持。

运行身份为专用 package 用户，不加入 Docker 组。网关 Socket 为 0660，私有控制 Socket 为 0600，控制目录为 0700。启停经私有控制 Socket，不使用不可信 PID 文件向其他进程发信号；错误状态不会改写现有私钥或放宽权限。`/stop`、`/healthz` 不在网关路由上提供。

官网图标来源及 MPL-2.0 说明沿用 Memos 包；构建时一起保留许可证。Go BSD 许可证来自官方 [`go1.26.8/LICENSE`](https://github.com/golang/go/blob/go1.26.8/LICENSE)，SHA-256 `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`。

Memos 原始二进制的固定来源、发布包校验和 MIT 许可证分别见 `MEMOS-NOTICE`、`MEMOS-LICENSE`；构建时一起放入安装包。它们不属于生产 Memos 容器升级。
