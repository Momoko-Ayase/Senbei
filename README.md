# Senbei Android

用于静态还原 Android 版受保护的 `libil2cpp.so` 和 IL2CPP
`global-metadata.dat`。生产路径已经完全 Rust 化，不执行保护器代码，也不依赖
Unicorn、IDA 或 Python。

## 兼容性

| 游戏 | 平台 | 版本 | 架构 | libil2cpp.so | global-metadata.dat |
|------|------|------|------|--------------|---------------------|
| リバースブルー×リバースエンド | Android | 1.28.2 | AArch64 | 支持 | v31 MethodDef token |

当前 SO 实现针对该版本的 Stage 2 模块格式，运行时会从模块产物中发现
`0x9B` 的种子、AES-256 key schedule 和相关配置，不硬编码样本 offset。
metadata 默认使用模块 `0x0C` 中确认的 seed `0xA6FAE968`。

## 构建

```powershell
cargo build --release
```

生成的程序为：

```text
target\release\senbei-android.exe
```

## 还原 libil2cpp.so

```powershell
senbei-android restore-so INPUT OUTPUT --index INDEX_JSON --report REPORT_JSON
```

示例：

```powershell
senbei-android restore-so `
  Native\libil2cpp.so `
  Native\libil2cpp_restored.so `
  --index Native\libil2cpp_stage2_modules\index.json `
  --report Native\libil2cpp_restore_report.json
```

省略 `--index` 时，默认读取输入文件同目录下的：

```text
libil2cpp_stage2_modules\index.json
```

可选参数：

- `--dump-aux FILE`：保存解码后的辅助 ELF 数据。
- `--outer-only`：只还原主容器，不物化辅助动态链接表。
- `--preserve-entrypoint`：保留保护器入口点；正常干净输出不应使用此项。

完整还原会静态处理 `0x9B/0x9D/0x9E` 数据，恢复 ELF load image、隐藏动态
符号、字符串、SysV/GNU hash、version、`.rela.dyn` 和 `.rela.plt`，移除
`SHT_LOUSER` 私有区并将入口点归零。

## 还原 metadata

```powershell
senbei-android restore-metadata INPUT OUTPUT --report REPORT_JSON
```

示例：

```powershell
senbei-android restore-metadata `
  Package\base\assets\bin\Data\Managed\Metadata\global-metadata.dat `
  Package\base\assets\bin\Data\Managed\Metadata\global-metadata_restored.dat `
  --report metadata_restore_report.json
```

可用 `--seed 0xA6FAE968` 显式指定十六进制 seed，也支持十进制。还原操作是
幂等的：已规范化的 image 会保持不变。

## Workspace

| Crate | 职责 |
|-------|------|
| `senbei-android-cli` | 命令行参数解析与结果输出 |
| `senbei-android-io` | 路径推导、原地覆盖保护、原子写入与 JSON 报告 |
| `senbei-android-elf` | AArch64 ELF 还原与结构验证 |
| `senbei-android-crypto` | `0x9B/0x9D` 容器、AES、Huffman/LZ 和字变换 |
| `senbei-android-metadata` | v31 MethodDef token 静态逆变换与覆盖验证 |
