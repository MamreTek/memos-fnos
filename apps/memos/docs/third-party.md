# 第三方来源

Memos 服务端镜像来自 [usememos/memos 26.11.0](https://github.com/usememos/memos/tree/26.11.0)，提交 `b40d8a7b573774c52b022c8d6537d6baf2129dc0`，MIT License。上游许可证随包保存在 `app/MEMOS-LICENSE`。

用户指定的图标来自 [Moe Memos 官网](https://memos.moe/) 的 [`memos.png`](https://memos.moe/memos.png)。2026-11-12 下载的 1024×1024 原图，与 [Moe Memos 源码中的 App Store 图标](https://github.com/mudkipme/MoeMemos/blob/b53f6ba377c29db1af63cf0d014f50592b3a5be2/MoeMemos/Assets.xcassets/AppIcon.appiconset/App_store_1024_1x.png) 逐字节一致，SHA-256 为 `0e089ecdefc0086d1f60f39b6185a0cfb4e3a13a13e8e76a36d056069f1d7865`。此图标采用上游 MPL-2.0 许可证，与服务端镜像及封装许可证分别保留。

仓库的 `assets/moe-memos-icon.png` 保存未修改原图，`assets/icon-source.json` 记录固定来源、提交、校验值与处理方式。仅使用 Pillow 12.2.0 的 `Image.Resampling.LANCZOS` 缩放到 64/256 像素，保留原图颜色、背景与比例；对应文件同时用于应用中心和桌面入口。构建直接使用已生成的 PNG，不需要安装 Pillow。上游完整许可证及来源说明随包保存在 `app/MOE-MEMOS-LICENSE` 和 `app/MOE-MEMOS-NOTICE`。

本项目是 cedarot/fn-apps 维护的第三方封装，不是 Memos、Moe Memos 或飞牛官方发行包。封装自身许可证位于 `app/PACKAGING-LICENSE`，保留已有版权声明。

fnpack 仅用于开发构建，来源 [飞牛官方 CLI](https://developer.fnnas.com/docs/cli/fnpack)。锁定 Linux amd64 1.2.3 及 SHA-256，下载来源与校验逻辑在 `scripts/fetch_fnpack.py`；不会把该二进制打进用户包。

客户端兼容证据：[Android 2.1.0](https://github.com/mudkipme/MoeMemosAndroid/releases/tag/2.1.0)、[iOS 2.0.7](https://github.com/mudkipme/MoeMemos/releases/tag/2.0.7)。发行说明中的支持范围与开发分支 README 可能不同；实际手机测试结果单独记录。
