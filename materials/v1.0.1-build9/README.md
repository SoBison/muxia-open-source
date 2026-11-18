# 幕匣 / Muxia 1.0.1 (Build 9)

## 下载及合并材料 / Download and restore the materials

下载 [基础材料 ZIP](https://github.com/SoBison/muxia-open-source/releases/download/v1.0.0-build7-materials/Muxia-OpenSource-Materials.zip)，并保留本更新 ZIP。只需解出本更新包中的 `restore_materials.py`。将三个文件放在同一目录，使用 Python 3.8 或更新版本运行以下命令。合并后的 ZIP 需要约 2.1 GB 的额外磁盘空间。

Download the [base materials ZIP](https://github.com/SoBison/muxia-open-source/releases/download/v1.0.0-build7-materials/Muxia-OpenSource-Materials.zip) and keep this update ZIP. Extract `restore_materials.py` from this update and place the three files in the same directory. Run the command below with Python 3.8 or later. The restored ZIP needs about 2.1 GB of extra disk space.

```sh
python3 restore_materials.py Muxia-OpenSource-Materials.zip Muxia-OpenSource-Update-1.0.1-build9.zip Muxia-OpenSource-Materials-1.0.1-build9.zip
```

程序会校验基础 ZIP、每个文件以及最终 ZIP 的大小和 SHA-256。解压合并后的 ZIP，打开其中的 `README.md` 查看源码、重新链接步骤和许可证。

The script verifies the base ZIP, every file, and the restored ZIP's size and SHA-256. Extract the restored ZIP and open its `README.md` for the source, relinking steps, and license notices.

## 下载更新 / Download the update

[下载 Build 9 更新 ZIP / Download the Build 9 update ZIP](Muxia-OpenSource-Update-1.0.1-build9.zip?raw=1)

| 文件 / File | 字节 / Bytes | SHA-256 |
| --- | ---: | --- |
| Build 7 基础材料 / Base materials ZIP | 970449762 | `8cad5c1261d287d08eb40fc16f1cedb7fde77f6b4f6b0c84112e7be7e3e2b03e` |
| Build 9 更新 / Update ZIP | 27241076 | `4b73cbce62d34b1a591018b9a6885d9c3defe7336d1e7ec8566dc8ef69edcc59` |
| 合并的 ZIP / Restored ZIP | 2096556576 | `4b9a479f4c9a72946789aa000427b27ef7dbd3cf676648ef8220233986898669` |
