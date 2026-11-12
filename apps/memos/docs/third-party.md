# 第三方来源

Memos 镜像及图标来自 [usememos/memos 26.11.0](https://github.com/usememos/memos/tree/26.11.0)，提交 `b40d8a7b573774c52b022c8d6537d6baf2129dc0`，MIT License。上游许可证随包保存在 `app/MEMOS-LICENSE`。

图标来自该提交的 `web/public/android-chrome-512x512.png`，仅用 Lanczos 缩放到 64/256 像素。未重画品牌或更改上游标识。本项目是 cedarot/fn-apps 维护的第三方封装，不是 Memos 或飞牛官方发行包。封装自身许可证位于 `app/PACKAGING-LICENSE`，保留已有版权声明。

fnpack 仅用于开发构建，来源 [飞牛官方 CLI](https://developer.fnnas.com/docs/cli/fnpack)。锁定 Linux amd64 1.2.3 及 SHA-256，下载来源与校验逻辑在 `scripts/fetch_fnpack.py`；不会把该二进制打进用户包。

客户端兼容证据：[Android 2.1.0](https://github.com/mudkipme/MoeMemosAndroid/releases/tag/2.1.0)、[iOS 2.0.7](https://github.com/mudkipme/MoeMemos/releases/tag/2.0.7)。发行说明中的支持范围与开发分支 README 可能不同；实际手机测试结果单独记录。
