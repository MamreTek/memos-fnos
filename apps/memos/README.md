# Memos for fnOS

本应用维护在 `cedarot/fn-apps` 的 `apps/memos/` 目录。下方开发命令从本目录执行；仓库根目录也可使用 `make APP=memos <目标>`。

为飞牛 NAS 提供 Memos 的 Docker 应用包：应用中心启停和状态、桌面浏览器入口、笔记与附件持久化、升级前备份。

**当前为 0.1.3 候选包，fnOS 实机兼容性尚未验收。** 一个 `platform=all` 安装包使用官方 amd64/arm64 镜像；ARM64 容器模拟测试不能代替 ARM64 fnOS 实机测试。

## 安装

1. 从目标飞牛 NAS 桌面打开 Docker，确认能正常查看容器或镜像列表，确认 TCP `5230` 空闲。
2. 从本项目 PR 的 CI 产物获取 `memos-fnos-0.1.3-all.fpk` 及同名 `.sha256`，验证校验和。
3. 在「应用中心 → 设置 → 手动安装」选择 `.fpk`。首次启动会拉取固定镜像，NAS 需要能访问 Docker Hub。
4. 应用显示运行后，点击 Memos 桌面图标；或访问 `http://<NAS-IP>:5230`。创建首个管理员账号，再配置注册及笔记可见性。

数据在飞牛文件管理的应用共享目录 `memos-fnos/data`，备份在 `memos-fnos/backups`。实际磁盘路径由系统提供，不限定存储卷。默认卸载保留数据；目标 fnOS 的共享目录保留行为仍待实机验证，卸载前请另存备份。

0.1.3 修正创建容器时数据子目录尚不存在的问题：由飞牛资源声明提前准备 `data` 和 `backups`，保留原数据位置、Docker 访问组声明和分类错误提示。请使用当前候选包复验；已存在的数据不会重新初始化。

## 手机连接

手机安装 [Moe Memos](https://memos.moe/)，服务地址填写 `http://<NAS-IP>:5230`，使用当前客户端支持的 Memos 登录方式。先在同一局域网完成同步。

本包固定 **Memos 26.11.0** 及多架构索引 digest，不自动更新。Android **2.1.0** 的发行说明已声明支持 26.10/26.11；iOS **2.0.7** 仅声明支持至 0.31.0，不能保证与本候选包同步。iOS 的新版/实际商店版本需另行验证；浏览器可直接使用 Memos。

本项目未设置公网访问、FN Connect、域名或 TLS；NAS 登录不会替代 Memos 自身账号认证。

## 开发与构建

需要 Linux、Python 3.12+、Bash 和常见系统工具；真实集成测试需要非 root 用户访问 Docker 和 Compose v2。请使用专用测试主机，测试会占用 `5230`，并在发现同名容器时拒绝运行。

```sh
make check test
make verify-image
make tools
make package
make integration
cd dist
sha256sum -c memos-fnos-0.1.3-all.fpk.sha256
```

Linux amd64 构建工具由 `make tools` 从飞牛官方下载并校验固定 SHA-256；其他开发平台可用 `make package FNPACK=/absolute/path/to/fnpack` 指定官方工具。

`docker-compose.yaml` 使用 JSON 语法（合法 YAML），以便标准库离线检查。fnOS 的 `docker-project` 托管启停；宿主脚本使用 package 用户，通过 `join-groups: ["docker"]` 声明 Docker 管理访问。容器直接使用该用户的非 root UID/GID，避免递归修改飞牛 ACL；容器没有 Docker 附加组或 socket 挂载。包内不包含宿主架构相关二进制。

共享根及 `data`、`backups` 均声明为系统资源。Compose 按官方 fnpack 1.2.3 Docker 模板的 `/var/apps/<app>/shares/<app>/data` 共享链接挂载数据，实际存储卷由 fnOS 解析。宿主钩子严格解析 `TRIM_DATA_SHARE_PATHS` 的冒号分隔列表，保留旧版单根路径兼容。

CI 对 amd64 和 QEMU 模拟的 arm64 执行真实镜像集成测试，并生成候选包；不自动发布、上架或部署。详细证据与待验项见 [测试矩阵](docs/validation.md)。

- [备份、恢复与排错](docs/operations.md)
- [项目约定](docs/project-decisions.md)
- [第三方资产与许可证](docs/third-party.md)
- [REQ-001 / Issue #1](https://github.com/cedarot/fn-apps/issues/1)

## 飞牛网页登录接入（开发中）

[Issue #3](https://github.com/cedarot/fn-apps/issues/3) 先执行 REQ-002 的网关与原生会话技术验证；当前安装包尚未提供飞牛免重复登录。独立的[登录验证包 0.0.2](tests/fnos-gateway-probe/README.md)能在目标 NAS 的临时 Memos 实例中运行真实登录组件测试，JSON 的 `auth_checks.status` 应为 `passed`。它不改变正式 Memos 的账号、数据或 5230 端口。技术证据和未通过门槛见 [SSO 验证记录](docs/sso-feasibility.md)。
