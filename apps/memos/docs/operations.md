# 操作说明

## 状态和错误

应用中心显示运行，表示本应用 Compose 容器处于 running 且 `/healthz` 数据库检查通过。初次拉取镜像和初始化可能需要等待；健康检查尚未成功时不会报为运行。

可在飞牛 Docker 中查看 `memos-fnos-memos` 的日志和健康检查记录。命令行诊断：

```sh
docker logs --tail 100 memos-fnos-memos
docker inspect --format '{{json .State}}' memos-fnos-memos
appcenter-cli list
```

- 旧 Docker 依赖声明：0.1.0 含未经核实的 `install_dep_apps=docker`，0.1.1 起已移除并沿用 `docker-project` 资源。用户提供的原文「Docker 不可用或无访问权限」实际来自生命周期检查；不能仅凭选包后立即提示，就把它判断为 manifest 依赖问题。
- Docker 权限：0.1.2 通过飞牛官方 `join-groups` 声明为现有 `memos-fnos` 应用用户添加 `docker` 附加组，保持原用户名及主组，供宿主生命周期执行 Docker 管理检查。该组授予 Docker 管理能力；Memos 容器仍按非 root UID/GID 运行，未配置该附加组或 Docker socket 挂载。平台是否在安装期落实此声明仍需目标设备验证。
- `E_DOCKER_PERMISSION`：Docker 访问被拒绝。若飞牛桌面 Docker 能正常查看容器/镜像列表，需核对应用用户的附加组及安装期执行身份。可在 NAS 终端只读执行 `id memos-fnos` 和 `stat -c '%U:%G %a' /var/run/docker.sock`，记录包版本、fnOS 精确版本和结果以便排查；账号不存在也应如实记录。由包的声明授权，包内不运行 sudo/usermod 或修改 socket 模式。
- `E_DOCKER_UNAVAILABLE`：无法连接 Docker 服务；从飞牛桌面打开 Docker 检查功能状态。
- `E_DOCKER_TIMEOUT`：Docker 响应超时；检查 Docker 服务状态后重试。
- `E_DOCKER_CHECK`：其他检查失败；提供错误码、退出码和 fnOS 精确版本。原始 Docker stderr 与连接上下文不回显到用户日志。
- 「缺少系统工具：docker」：检查设备提供的 Docker CLI/PATH；包内脚本不安装独立守护进程。
- 拉取失败：检查 NAS 对 Docker Hub 的访问。固定引用包含 digest，不能改成未核实的镜像源或 rolling tag。
- `bind source path does not exist`：镜像可已拉取成功，但 Docker 创建容器时数据目录尚未准备好。0.1.3 将共享根及 data/backups 子目录声明为飞牛资源，并使用官方模板的应用共享链接，保留原来的数据位置。改用当前候选包复验；如果仍失败，记录缺失路径及精确 fnOS/包版本，检查声明目录和应用共享链接是否已由系统创建。
- 端口占用：解决 TCP 5230 的占用后重试；首版不支持改端口，不会自动停止其他容器。
- 目录不可写或 UID 不一致：核对系统声明目录授予应用用户的 ACL 与子目录所有者。不要用 `chmod 777` 或切换 root 掩盖问题；安装回调幂等核验目录，已有数据不会自动 chown。
- 状态不可用：检查容器健康检查和 Memos 日志；没有健康信息的同名容器不会被当成成功运行。

## 升级与备份

1. 先在应用中心停止 Memos，等待停止。
2. 在目标版本具备明确数据库迁移/手机兼容说明后，手动安装新版包。
3. `upgrade_init` 检查实例已停止，在共享目录 `backups/upgrade-<UTC>-<随机后缀>` 写入 `data.tar.gz`、`metadata.txt` 和 `SHA256SUMS`。
4. 归档、校验和或路径验证失败时中止升级，保留原数据；不会跳过备份启动新版本。
5. 升级完成后验证笔记、附件和手机同步，再自行决定备份保留期限。首版没有自动清理或后台自动更新。

备份包含账号及私人笔记，请保持目录访问受限。`metadata.txt` 记录旧包版本和原容器镜像；它不作为脚本执行，也不存储明文密码或 Token。

## 隔离恢复

不要把旧镜像直接指向已迁移的数据库。先停止应用，复制完整备份到另一处保留，再恢复到**新建的空目录**；保留原数据不动。只使用自己信任的本应用备份。

在备份目录验证：

```sh
sha256sum -c SHA256SUMS
tar -tzf data.tar.gz
```

检查目录成员以 `data/` 为根，不含绝对路径或 `..`，确认后用 `mkdir` 创建全新的隔离目录（目录已存在时应停止）：

```sh
mkdir /path/to/new-empty-recovery
tar -xzf data.tar.gz -C /path/to/new-empty-recovery
```

使用 `metadata.txt` 记录的原镜像在隔离测试端口运行，保持非 root UID/GID 与恢复目录所有者匹配。核对笔记内容、附件字节与私有内容访问限制。验收通过后再规划切换，切换前保留现有数据；本包不自动覆盖现有数据或回滚数据库。

## 卸载与重新安装

本包两个卸载钩子均不删除共享数据、不执行 volume prune、也不清理其他镜像/容器。fnOS 管理本应用的 Compose 资源回收。请在卸载前另存备份，并避免选择系统可能提供的删除用户数据选项。是否能保留并复用该共享目录，须以目标 fnOS 实机结果为准。

## 测试设备要求

正式兼容声明需要精确 fnOS 版本、构建号、CPU 架构、Docker/Compose 版本，以及客户端版本。当前未接入用户 NAS，也没有修改用户设备。无需向本仓库提交密码、Token、SSH 私钥或私人数据。
