# 操作说明

## 状态和错误

应用中心显示运行，表示本应用 Compose 容器处于 running 且 `/healthz` 数据库检查通过。初次拉取镜像和初始化可能需要等待；健康检查尚未成功时不会报为运行。

可在飞牛 Docker 中查看 `memos-fnos-memos` 的日志和健康检查记录。命令行诊断：

```sh
docker logs --tail 100 memos-fnos-memos
docker inspect --format '{{json .State}}' memos-fnos-memos
appcenter-cli list
```

- 选择 0.1.0 包后提示需要安装 Docker：旧包含未经核实的 `install_dep_apps=docker` 声明，可能在安装脚本运行前被当作普通应用依赖检查。保留现有 Docker，改用 0.1.1；新版依照官方示例使用 `docker-project` 资源。目标设备是否通过安装检查仍需复验。
- Docker 不可用：若安装过程中出现「Docker 不可用或无访问权限」，这是脚本对实际守护进程的检查失败，需核对应用中心的 Docker 运行状态及应用用户访问权限；若出现「缺少系统工具：docker」，则需检查设备提供的 Docker CLI/PATH。记录完整错误、发生阶段及 fnOS 精确版本便于定位。包内脚本不会安装独立守护进程或修改 Docker 权限。
- 拉取失败：检查 NAS 对 Docker Hub 的访问。固定引用包含 digest，不能改成未核实的镜像源或 rolling tag。
- 端口占用：解决 TCP 5230 的占用后重试；首版不支持改端口，不会自动停止其他容器。
- 目录不可写或 UID 不一致：核对共享目录授予应用用户的 ACL 与子目录所有者。不要用 `chmod 777` 或切换 root 掩盖问题；新装目录由应用用户创建，已有数据不会自动 chown。
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
