# 验证矩阵

本表把代码与 Docker 检查、fnOS 实机和手机验证分别记录。候选包不能据此宣称已通过实机认证。最新自动化结果以对应提交的 GitHub Actions 为准。

| 项目 | 环境 / 方法 | 状态 |
|---|---|---|
| 镜像架构与 digest | 官方 OCI 索引；amd64、arm64；原始索引存于 evidence/ | 已核实 |
| 包元数据 / JSON / Bash / 图标 / 路径 | `make check` | 本地通过 |
| 11 项生命周期行为 | `make test`；真实端口监听、失败保护、SQLite/附件备份恢复、Docker 错误分类及脱敏 | 本地通过（对应提交的 CI 为准） |
| 官方 fnpack 1.2.3 构建 | `make package`；检查内外层每个载荷与 manifest 校验和 | 本地通过 |
| amd64 真实 Memos | CI `make integration` | 通过，见下方运行证据 |
| arm64 真实 Memos / QEMU | CI `make integration` | 通过；不是 ARM fnOS 实机 |
| N150 x86_64 fnOS | 精确版本/构建号、安装、启停、桌面、NAS 重启、升级和卸载保留 | 待实机 |
| ARM64 fnOS | 同上 | 待实机 |
| Android Moe Memos 2.1.0 | 官方发行说明支持 26.10/26.11；双向/附件/离线同步 | 声明已核实；实际同步待验 |
| iOS Moe Memos | 2.0.7 仅声明支持至 0.31.0 | 本包 26.11.0 待兼容验证 |

真实容器测试创建独立临时目录，验证首次账号、私有笔记、图片附件字节、非 root 用户、停止后再启动、容器重建、升级前备份、隔离恢复和卸载钩子保留。测试拒绝触碰已存在的同名容器。其安全断言覆盖匿名访问隔离和注入式登录失败；未改动上游 Web 界面，API 中保存 HTML 文本不构成浏览器 XSS 渲染验收。

运行证据：2026-11-12，[CI 43152302689](https://github.com/cedarot/fn-apps/actions/runs/43152302689)，提交 `bcb15fe2dcc19ff6961d0ba43734c56283277208`，package、amd64 与 arm64 三项均通过。后续提交仍以其对应 Actions 为准。初次用例错误地预期非法凭证返回 401；核对固定版本源码后修正为 HTTP 400 / INVALID_ARGUMENT，并保留无 token 的断言，两种架构重测通过。

## fnOS 实机记录模板

每种架构分别记录：日期、包 SHA-256、提交、Memos 镜像、fnOS 精确版本/构建号、CPU、Docker/Compose、手机客户端及来源。

- 干净安装：依赖可识别、拉取成功，真实数据目录与 ACL 正确。
- 应用中心启停与状态：就绪前不误报运行；主动停止不会被额外脚本拉起。
- 桌面入口：使用当前 NAS 主机名/IP，打开根页面并完成首次账号创建。
- 数据保留：重建容器和重启 NAS 后笔记/图片仍可读。
- 升级与恢复：停止写入、一致备份、失败中止；用原镜像在隔离目录恢复并核验。
- 卸载保留：检查飞牛资源清理的实际行为，重新安装后验证内容。
- 同步：记录笔记双向变更、附件和离线恢复同步结果。
- 失败：镜像无法拉取、端口占用、目录无权限时显示清楚错误，不影响其他应用。

最小 fnOS 版本未认证，因此候选 manifest 不填写未经测试的 `os_min_version`。正式发行前须根据上述结果设定兼容范围；没有填写该字段不表示支持所有旧系统。

2026-11-13 首次收到用户反馈时，0.1.1 移除了未经核实的 `install_dep_apps=docker` 声明，保留 `docker-project` 资源与 Docker CLI/守护进程检查。依据为[官方 Docker 案例](https://developer.fnnas.com/docs/examples/docker)和官方 fnpack 1.2.3 Docker 模板。随后用户提供原文「Docker 不可用或无访问权限」，已确认是生命周期 `docker info` 检查报错，不能继续归因为 manifest 依赖提示。

0.1.2 依据[飞牛官方应用权限](https://developer.fnnas.com/docs/core-concepts/privilege)的附加组契约及 [Docker 官方非 root 访问说明](https://docs.docker.com/engine/install/linux-postinstall/)，为宿主包用户声明 `join-groups: ["docker"]`，保留现有用户/主组。错误分类用例覆盖权限拒绝、守护进程连接失败、超时、未知错误和原始上下文脱敏；现有容器 CI 继续验证检查和 Memos 行为。此项不会验证 fnOS 是否实际落实声明或安装期执行身份，目标 fnOS 安装仍须复验；不将加入 Docker 组描述为普通无特权操作。
