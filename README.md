# 幕匣第三方源码与重链接材料

[English](README.en.md)

这里提供 RenReader / 幕匣 1.0.0（Build 7）的第三方源码、运行时适配代码、修改、头文件、许可和重链接工具。它不是完整 App 业务源码仓库，也不将整个 App 以 MIT 或另一单一许可证重新授权。App 的业务 Swift、作品、存档、账户资料和签名密钥不在本仓库。

完整材料已发布到 [v1.0.0-build7-materials](https://github.com/SoBison/muxia-open-source/releases/tag/v1.0.0-build7-materials)。匿名下载已核对文件大小、SHA-256 和内部交付清单；文件名、版本、实际下载地址与发布状态见 `materials.json`。

材料与托管下载机制相配套，App 对象已完成搬迁后的重链接核验。

## Git 与 Release 的范围

- `src/`：从已核验材料选取的 SDK-free 运行时／Native／桥接源和必要 producer 脚本；每版 `rr_host.py` 独立保留，不应以 canonical host 覆盖所有版本。
- `headers/`：公开依赖的相应头文件，不含 Apple SDK 或 Live2D Core。
- `licenses/`：原始第三方许可和版权声明；适用条件以各组件文本为准。
- `tools/`：来源恢复和 App／Native 重链接工具。
- `inventory.json`：本仓库选定文件的大小、哈希和来源；机器生成的大型原始输入／签收记录在完整 Release 资产中保留。
- Release 资产 `Muxia-OpenSource-Materials.zip`：完整对应源码归档、精确构建输入、App 对象、静态库、公共 framework providers 以及完整清单。大型归档和二进制不放入 Git history；只克隆 Git 不等于取得全部重链接输入。

Release 资产另包含托管交付机制的验证源码：`ReleaseLegalManifest.swift`、`LegalNoticesView.swift` 两份法律页面相关 Swift，以及相应生成／检查脚本。它们位于 `HostedDelivery/Source/`，不包含其他 App 业务 Swift，也不改变原有许可范围。

不支持 Live2D；不会提供或下载 Live2D Core／Cubism Native Framework、模型或 Apple SDK。保留的兼容性名称或 SDK-free stub 不表示启用了该能力。历史 QA/probe/fixture 与机器来源报告没有作为仓库代码收录；完整材料仍保留其实际范围和来源。

## 下载与核对

在本仓库实际发布的 Release 中下载 `materials.json` 指定的资产；未发布时无法从本仓库下载。先验证文件，再展开到一个新目录：

```sh
python3 tools/verify_asset.py /downloads/Muxia-OpenSource-Materials.zip
python3 -m zipfile -e /downloads/Muxia-OpenSource-Materials.zip /fresh/materials
python3 tools/materialize_sources.py --source /fresh/materials/Sources --output /fresh/materialized-sources
```

来源恢复只校验／复制，不执行源码；可用重复的 `--prefix` 只恢复需要的逻辑目录。输出目录必须尚不存在，父目录须已存在。

## 重链接

使用自己合法安装、与清单匹配的 Xcode／iPhoneOS SDK；不从本仓库复制 Apple 工具或 SDK。App 对象与 providers 来自完整 Release 资产：

```sh
python3 tools/replay_portable.py --kit /fresh/materials/AppRelink/Kit   --manifest-sha 920bd2fbed5bb4237aceda1f45ce2eef0f3c5938fecc899016385ea77224aa9c   --artifact-root /fresh/materials/NativeRelink/Providers   --sdk /path/to/iPhoneOS27.1.sdk   --clang /path/to/XcodeDefault.xctoolchain/usr/bin/clang   --output /fresh/unsigned-app-replay
```

Native 工具使用 `--kit /fresh/materials/NativeRelink --sources /fresh/materials/Sources --providers /fresh/materials/NativeRelink/Providers`；`--sources` 指向包含 `inventory.json` 和 `objects/` 的原始材料目录，其余参数见 `python3 tools/replay_native.py --help`。组件构建和差异范围以资产内说明／清单为准，不能仅据一次链接成功推断所有二进制字节相同。

按相应许可修改组件后，可在自己的 App kit 副本中更新输入 SHA／size 和清单 SHA，再使用 `--modified-components`；Native 工具提供 `--replace LOGICAL_PATH=FILE`。完整性 pin 用来识别输入，不禁止依许可修改。修改结果不会冒充原版字节等价。输出未签名，安装／分发需使用自己的 Apple 凭据与设置。

## 许可与边界

各第三方文件保留其原许可／版权。本仓库不替换这些条款，也不对全部混合材料另加整体 MIT 许可。`APPLICATION-OBJECTS-PERMISSION.txt` 保留对材料资产内 App 对象进行修改组件重链接和调试的既有用途许可；不扩大为全部 App 业务源码授权。

这份源码与重链接交付不是作品使用权、App Store 审核批准或所有设备兼容的证明。用户自行提供并确认有权使用作品；App 不附带小说或作品下载目录。
