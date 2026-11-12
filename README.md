# fn-apps

飞牛 fnOS 第三方应用封装仓库。每个应用在 `apps/<app>/` 下独立维护源码、打包配置、测试与使用说明。

| 应用 | 目录与说明 | 当前状态 |
|---|---|---|
| Memos | [apps/memos](apps/memos/) | Docker 通用候选包；amd64 / ARM64 镜像与容器测试通过，fnOS 实机待验 |

## 构建与验证

在仓库根目录使用 `APP` 选择应用，默认是 `memos`：

```sh
make APP=memos check test
make APP=memos verify-image
make APP=memos tools package
make APP=memos integration
```

也可直接执行 `make -C apps/memos check test`。需要指定 fnpack 时使用绝对路径：`make APP=memos package FNPACK=/absolute/path/to/fnpack`。候选产物生成在 `apps/memos/dist/`，不会提交到 Git。

真实容器测试需要可访问 Docker 的非 root 用户，使用专用测试主机。CI 负责官方打包与 amd64 / QEMU ARM64 集成测试，不自动部署或发布。

## 目录约定

```text
apps/
  memos/
    packaging/   # 飞牛安装包内容
    scripts/     # 校验与构建
    tests/       # 行为和容器测试
    docs/        # 应用操作及验证记录
    Makefile
    README.md
.github/workflows/ # 仓库 CI
docs/              # 共享开发约定
Makefile           # 应用命令分发
```

仓库从 `MamreTek/memos-fnos` 迁移至 [cedarot/fn-apps](https://github.com/cedarot/fn-apps)，原有历史、Issue #1 和 PR #2 沿用。Memos 在 NAS 上的应用 ID 仍为 `memos-fnos`，端口与数据目录沿用原约定；此次源码整理不要求迁移 NAS 数据。

各应用的安装和兼容范围见对应 README。当前 Memos 仍为候选包，fnOS 实机和手机客户端同步待验收。
