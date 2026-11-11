//! Simplified Chinese (zh-CN) console and report text.

use std::borrow::Cow;

use crate::{Cli, Msg, Step, Term};

pub(crate) fn msg(msg: &Msg) -> Cow<'static, str> {
    match msg {
        Msg::CompanionMissing => "缺少伴生文件：此加载器需要匹配的 <input>._ 载荷。请将它放在输入文件所在的文件夹中，然后重试。浏览器版需同时添加这两个文件。".into(),
        Msg::CompanionMismatch => "伴生文件不匹配：提供的 ._ 载荷过短，或其头部与加载器不一致。请使用来自同一构建版本的伴生文件；其中任一文件都可能已损坏。".into(),
        Msg::InputTooShort { actual, required } => format!("输入过短（至少需要 {required} 字节，实际为 {actual} 字节）").into(),
        Msg::NotProtected => "不是受 CrackProof 保护的文件".into(),
        Msg::InvalidPeOffset { offset, input_len } => format!("对于 {input_len} 字节的输入，PE 头部偏移 {offset} 无效").into(),
        Msg::DllNeedsPe32Plus { found } => format!("DLL 流水线需要 PE32+ 可选头部魔数，实际为 0x{found:04X}").into(),
        Msg::LayoutUnsupported => "未找到 stage5 标记 — 此解包工具不支持该构建版本的布局".into(),
        Msg::InternalPanic { file, line, column, message } => format!("内部错误位于 {file}:{line}:{column}：{message}").into(),
        Msg::DecodeFailed => "受保护数据未能按预期解码；文件可能已损坏，或该构建版本的布局不受支持".into(),
        Msg::NotPe => "输入不是 PE 映像".into(),
        Msg::NotElf64 => "输入不是 ELF64 小端序映像".into(),
        Msg::NotAarch64 => "输入不是 AArch64 映像".into(),
        Msg::NotMetadata => "不是 il2cpp global-metadata.dat".into(),
        Msg::NotIl2cppMetadata => "不是 IL2CPP global-metadata.dat".into(),
        Msg::UnsupportedMetadataVersion { version } => format!("不受支持的元数据版本 {version}").into(),
        Msg::MetadataTransformFailed => "元数据变换未通过验证".into(),
        Msg::LimitEntry { requested, limit } => format!("资源限制：{requested} 字节的条目超出 {limit} 字节的上限").into(),
        Msg::LimitTotal { requested, adding, limit } => format!("资源限制：{requested} 字节的任务总量超出 {limit} 字节的上限（新增 {adding} 字节）").into(),
        Msg::LimitEntries { requested, limit } => format!("资源限制：{requested} 个条目超出 {limit} 的上限").into(),
        Msg::LimitDepth { requested, limit } => format!("资源限制：嵌套深度 {requested} 超出 {limit} 的上限").into(),
        Msg::OutputNotRetained => "研究检查：未保留输出文件".into(),
        Msg::DryRunDiscarded => "试运行：生成的输出已丢弃".into(),
        Msg::TransformNoop => "变换已运行并通过验证；无需改写任何内容".into(),
        Msg::CompanionUnmatched => "存在同目录 `._` 文件，但不是此存根的载荷".into(),
        Msg::CompanionUnreadable { reason } => format!("无法读取同目录 `._` 文件：{reason}").into(),
        Msg::CompanionUnreadableUnknown => "无法读取同目录 `._` 文件".into(),
        Msg::MetadataLeftUntouched { version } => format!("不受支持的元数据版本 {version}，保持原样").into(),
        Msg::UnexpectedPanic { message } => format!("意外内部错误：{message}").into(),
        Msg::InputNotExamined => "无法检查输入项".into(),
        Msg::NoCandidateValidated => "无候选通过验证".into(),
        Msg::NoModule0c => "没有适用于 v24.1 元数据的模块 0x0C".into(),
        Msg::AmbiguousModule0c => "模块 0x0C 绑定存在歧义".into(),
        Msg::UnsafePackageEntry { package } => format!("应用包 `{package}` 中存在不安全的条目路径").into(),
        Msg::UnsafeNestedEntry { path } => format!("`{path}` 中存在不安全的条目路径").into(),
        Msg::EntryStubTargetOutsideCode { branch, target } => format!("入口点 {branch} 目标 0x{target:X} 位于可执行节之外（DD8 选择可能错误）").into(),
        Msg::MissingMz => "缺少 'MZ' DOS 签名".into(),
        Msg::TruncatedDosHeader => "DOS 头部已截断（无 e_lfanew）".into(),
        Msg::MissingPeSignature { offset } => format!("0x{offset:X} 处缺少 'PE\\0\\0' 签名").into(),
        Msg::TruncatedCoffHeader => "COFF 头部已截断".into(),
        Msg::TruncatedOptionalHeader => "可选头部已截断".into(),
        Msg::BadOptionalMagic { magic } => format!("可选头部魔数 0x{magic:X} 无效").into(),
        Msg::ImplausibleSectionCount { count } => format!("节数量 {count} 不合理").into(),
        Msg::ZeroSizeOfImage => "SizeOfImage 为零".into(),
        Msg::SectionTablePastEof => "节表超出文件末尾".into(),
        Msg::SectionRawPastEof { index, start, end, file_len } => format!("节 #{index} 的原始数据 [0x{start:X}..0x{end:X}] 超出文件大小 0x{file_len:X}").into(),
        Msg::NoBaseRelocations => "原生 DLL 无基址重定位表（DD[5] 为零）— 在非首选基址加载时将崩溃".into(),
        Msg::ZeroEntryPoint => "入口点 RVA 为零".into(),
        Msg::EntryUnmapped { rva } => format!("入口点 RVA 0x{rva:X} 未映射到任何节").into(),
        Msg::EntryAllZeros { rva } => format!("RVA 0x{rva:X} 处的入口点全为零（存根未恢复）").into(),
        Msg::EntryAllInt3 { rva } => format!("RVA 0x{rva:X} 处的入口点全为 int3 填充（存根未恢复）").into(),
        Msg::EntryNotExecutable { rva } => format!("入口点 RVA 0x{rva:X} 不在可执行节中").into(),
        Msg::ImportDirectoryUnmapped { rva } => format!("导入目录 RVA 0x{rva:X} 未映射到任何节").into(),
        Msg::ImportNameUnmapped { index, rva } => format!("导入描述符 {index} 的 DLL 名称 RVA 0x{rva:X} 未映射到任何节").into(),
        Msg::ImportNameUnreadable { index, rva } => format!("导入描述符 {index} 在 RVA 0x{rva:X} 处的 DLL 名称不是可读的 ASCII（导入仍处于加密状态？）").into(),
        Msg::ClrDirectoryUnmapped { rva } => format!("CLR (COR20) 目录 RVA 0x{rva:X} 未映射到任何节").into(),
        Msg::ClrHeaderBadSize { rva, size } => format!("RVA 0x{rva:X} 处的 COR20 头部 cb 为 0x{size:X}（应为 0x48）— CLR 头部已损坏").into(),
        Msg::ClrMetadataUnmapped { rva } => format!("CLR MetaData RVA 0x{rva:X} 未映射到任何节").into(),
        Msg::ClrMetadataNoBsjb { rva } => format!("RVA 0x{rva:X} 处的 CLR MetaData 缺少 'BSJB' 签名（元数据已损坏 — 托管映像将无法加载）").into(),
    }
}

pub(crate) fn step(step: &Step) -> Cow<'static, str> {
    match step {
        Step::DecryptHeader => "正在解密文件头部...".into(),
        Step::DecryptPayload => "正在解密载荷...".into(),
        Step::LocateConfig => "正在定位配置布局...".into(),
        Step::DecryptStage2 => "正在解密 stage2...".into(),
        Step::DecryptStages3To5 => "正在解密阶段 3-5...".into(),
        Step::DecryptSections => "正在解密节数据...".into(),
        Step::DecryptSectionsNewLayout => "正在解密节数据（新布局）...".into(),
        Step::LoadSections => "正在加载并解压各节...".into(),
        Step::DecryptImports => "正在解密导入字符串...".into(),
        Step::RebuildHeaders => "正在重建 PE 头部...".into(),
        Step::Pe32LocateConfig => "正在定位配置布局 (PE32)...".into(),
        Step::Pe32Stages => "正在解密各阶段 (PE32)...".into(),
        Step::Pe32EighthStage => "正在解密第八阶段 (PE32)...".into(),
        Step::Pe32Load => "正在加载并解压文件数据 (PE32)...".into(),
        Step::Pe32Text { formula } => {
            format!("正在解密 .text (PE32 dd8, formula={formula})...").into()
        }
        Step::Pe32TextSkip => "正在跳过 .text dd8（已是明文）...".into(),
        Step::Pe32Imports => "正在解密导入字符串 (PE32)...".into(),
        Step::Pe32Rebuild => "正在重建 PE 文件布局 (PE32)...".into(),
        Step::InitKeys => "正在初始化密钥...".into(),
        Step::DecryptKeyTable => "正在解密密钥表...".into(),
        Step::DecryptPrimary => "正在解密主描述符...".into(),
        Step::RelocsParams => "正在处理重定位与解压参数...".into(),
        Step::DecryptBlock1 => "正在解密代码块 1 (addr3)...".into(),
        Step::DecryptBlocks2To3 => "正在解密代码块 2-3 (addr3b, addr4)...".into(),
        Step::DecryptBlock4 => "正在解密代码块 4 (addr5)...".into(),
        Step::DllSections => "正在解密并解压各节...".into(),
        Step::FixHeaders => "正在修正 PE 头部与节表...".into(),
        Step::AndroidPrimary => "正在解码主 0x9D 目标映像容器...".into(),
        Step::AndroidAuxiliary => "正在解码辅助 0x9D ELF 容器...".into(),
        Step::AndroidTables => "正在重建静态 ELF 动态链接器表...".into(),
        Step::WriteTo { dest } => format!("写入 {dest}").into(),
    }
}

pub(crate) fn term(term: &Term) -> Cow<'static, str> {
    match term {
        Term::Ok => "正常",
        Term::Suspect => "可疑",
        Term::Recognized => "已识别",
        Term::NotRecognized => "未识别",
        Term::Skipped => "已跳过",
        Term::Error => "错误",
        Term::Restored => "已恢复",
        Term::Duplicate => "重复",
        Term::NotTarget => "非目标",
        Term::Unchanged => "未更改",
        Term::Inventoried => "已列出",
        Term::Failed => "失败",
        Term::Blocked => "受阻",
        Term::NotAttempted => "未尝试",
        Term::Succeeded => "成功",
        Term::Rejected => "已拒绝",
        Term::Clean => "通过",
        Term::Warnings => "警告",
        Term::NotRun => "未运行",
        Term::Absent => "无",
        Term::Spliced => "已拼接",
        Term::Unmatched => "不匹配",
        Term::Unreadable => "不可读",
        Term::Detection => "检测",
        Term::ManifestInventory => "清单清点",
        Term::EntryProbe => "条目探测",
        Term::Recovery => "恢复",
        Term::StaticValidation => "静态验证",
        Term::OutputWrite => "输出写入",
        Term::SharedLibrary => "共享库",
        Term::Metadata => "元数据",
        Term::ExeStyle => "EXE 风格加载器",
        Term::Dll => "DLL 加载器",
        Term::AndroidStaged => "Android 分阶段加载器",
        Term::MetadataSeeded => "基于种子的元数据变换",
        Term::MetadataStructural => "结构化元数据变换",
        Term::MetadataMethodIndices => "元数据方法索引恢复",
        Term::WindowsPe => "Windows PE",
        Term::AndroidElf => "Android ELF",
        Term::Il2cppMetadata => "il2cpp 元数据",
        Term::NativeExe => "原生 EXE",
        Term::ManagedExe => ".NET EXE",
        Term::NativeDll => "原生 DLL",
        Term::ManagedDll => ".NET DLL",
        Term::HeaderMagic => "头部魔数",
        Term::ExternalCompanionDeclaration => "声明了外部伴生文件",
        Term::CompanionSpliced => "已拼接伴生文件",
        Term::PrivateSection => "私有节",
        Term::AesSchedule => "AES 密钥编排表",
        Term::ValidatedMetadataTransform => "已验证的元数据变换",
        Term::Known => "已知",
        Term::ContextRequired => "需要应用上下文",
        Term::Unverified => "未验证",
        Term::Original => "原始文件",
        Term::SplicedCompanion => "已拼接伴生文件",
    }
    .into()
}

pub(crate) fn cli(cli: &Cli) -> Cow<'static, str> {
    match cli {
        Cli::Error => "错误".into(),
        Cli::Warning => "警告".into(),
        Cli::DoneIn { ms } => format!("完成，用时 {ms} ms").into(),
        Cli::PressEnter => "\n按 Enter 退出…".into(),
        Cli::ScanUnreadable { count } => format!("扫描期间有 {count} 个文件无法读取，可能遗漏了目标").into(),
        Cli::Summary { unpacked, skipped, errors, suspect, metadata } => format!("已解包 {unpacked} · 已跳过 {skipped} · 错误 {errors} · 可疑 {suspect} · 元数据 {metadata}").into(),
        Cli::SummaryPackages { packages } => format!(" · 应用包 {packages}").into(),
        Cli::IntegrityFailed => "完整性检查失败".into(),
        Cli::IntegrityFailedLikelyCrash => "! 完整性检查失败（运行时极可能崩溃）".into(),
        Cli::MetadataLine { rel, dest, remapped } => format!("元数据  {rel}  ->  {dest}  ({remapped} 个方法字段已重映射)").into(),
        Cli::MetadataVersionLine { version, dest, remapped } => format!("元数据 v{version} -> {dest} ({remapped} 个方法字段已重映射)").into(),
        Cli::MetadataAlreadyClean { version } => format!("元数据 v{version}:").into(),
        Cli::MetadataNothingToDo => "已解混淆，无需处理".into(),
        Cli::EmbeddedMetadataLine { input, dest } => format!("元数据  {input} (内嵌)  ->  {dest}").into(),
        Cli::EmbeddedMetadataFailed => "内嵌元数据".into(),
        Cli::MetadataUnsupportedLine { version } => format!("不受支持的元数据版本 {version}，保持原样").into(),
        Cli::OutRequiresDirectory => "--out 需要目录参数".into(),
        Cli::UnknownOption { option } => format!("未知选项 '{option}'").into(),
        Cli::MultipleInputs { first, second } => format!("指定了多个输入路径（'{first}' 与 '{second}'）").into(),
        Cli::SubcommandNeedsPath { subcommand } => format!("'{subcommand}' 需要输入路径").into(),
        Cli::InspectNoDryRun => "'inspect' 不保存输出文件；无需指定 --dry-run".into(),
        Cli::InspectNoOut => "'inspect' 不保存输出文件；不能与 --out 同时使用".into(),
        Cli::DryRunNoOut => "--dry-run 不保存输出文件；不能与 --out 同时使用".into(),
        Cli::ColorRequiresMode => "--color 需要 auto、always 或 never".into(),
        Cli::ThreadsRequiresInteger => "--threads 需要正整数参数".into(),
        Cli::LimitRequiresInteger { flag } => format!("{flag} 需要无符号整数参数").into(),
        Cli::LimitMustBePositive { flag } => format!("{flag} 必须大于零").into(),
        Cli::LimitTooLarge { flag } => format!("{flag} 超出受支持的字节范围").into(),
        Cli::UnknownLimit { flag } => format!("未知资源选项 '{flag}'").into(),
        Cli::HelpPath => "  <file|folder>\n\
             \x20              受 CrackProof 保护的 PE (.exe/.dll)、il2cpp\n\
             \x20              global-metadata.dat、受保护的 Android AArch64 库 (.so)、\n\
             \x20              Android 应用包 (.apk/.apks/.xapk)，或包含上述任意项的\n\
             \x20              文件夹。省略子命令时等同于 'unpack'。"
            .into(),
        Cli::HelpInspect => "  inspect PATH\n\
             \x20              执行完整的静态恢复并输出详细分析报告：识别依据、尝试过\n\
             \x20              的各恢复方案及排除原因、最终选用的方案、静态验证结论，\n\
             \x20              以及保护头部字段、种子、模块记录与恢复映像结构数据。\n\
             \x20              不保存恢复后的输出文件或日志，自动清理临时目录，且绝不\n\
             \x20              执行输入文件。"
            .into(),
        Cli::HelpUnpack => "  unpack PATH  检测并恢复；写出输出（默认）。".into(),
        Cli::HelpJson => "  --json       向标准输出写出单份带版本号的机器可读报告，不输出其他\n\
             \x20              内容。隐含静默模式与 --no-log。"
            .into(),
        Cli::HelpDryRun => "  --dry-run    执行完整的恢复流程，但不保存输出文件与日志。Android 提取\n\
             \x20              期间使用的临时工作区会在完成后自动清理。"
            .into(),
        Cli::HelpThreads => "  --threads N  本次运行的工作线程数上限（正整数）。覆盖 SENBEI_THREADS；\n\
             \x20              设为 1 则使用顺序执行路径。环境变量保持不变。"
            .into(),
        Cli::HelpColor => "  --color MODE auto（默认）、always 或 never；也支持 --color=MODE。\n\
             \x20              auto 会分别为终端标准输出与标准错误着色，除非 NO_COLOR\n\
             \x20              非空或 TERM=dumb。显式指定 always/never 会覆盖这些变量。\n\
             \x20              JSON 与保存的日志始终为纯文本。"
            .into(),
        Cli::HelpScanAll => "  --scan-all   同时探测低于大小下限的 .exe/.dll/.so/元数据文件名；其他\n\
             \x20              文件名仍会被排除。"
            .into(),
        Cli::HelpStrictIntegrity => "  --strict-integrity\n\
             \x20              当任一输出未通过静态完整性检查（可疑项）或有文件出错时，\n\
             \x20              以非零状态码退出。默认关闭：可疑项仍会写出，且除非有文件\n\
             \x20              出错，否则进程以 0 退出。静默级别保持不变。\n\
             \x20              配合 'inspect' 使用时，该检查作用于为研究而实际恢复的\n\
             \x20              映像；不保留输出文件。"
            .into(),
        Cli::HelpLimits { entry_mib, total_mib, entries, depth } => format!(
            "  Android 资源限制（MiB = 1048576 字节）：\n\
             \x20 --max-entry-mib N  单个归档条目/解码缓冲区/输出（默认 {entry_mib}）\n\
             \x20 --max-total-mib N  累计归档字节数及单次引擎任务预算（默认 {total_mib}）\n\
             \x20 --max-entries N    归档条目/阶段 2 记录数（默认 {entries}）\n\
             \x20 --max-depth N      嵌套深度，根为 0（默认 {depth}）\n\
             \x20 提取或分配前会检查限制；这些限制不是内存使用峰值的上限。"
        )
        .into(),
        Cli::HelpLanguage => "  SENBEI_LANG  显示语言：en、zh-CN、zh-TW、ja 或 ko。未设置时使用系统\n\
             \x20              语言。JSON 与保存的日志始终使用英文。"
            .into(),
        Cli::HelpExitCodes => "  退出代码：0 成功，1 有目标失败（或启用 --strict-integrity 时存在可疑\n\
             \x20 项），2 命令行参数被拒绝。"
            .into(),
        Cli::ReportScanHeading => "扫描".into(),
        Cli::ReportScan { skipped, walk_errors, probe_errors } => format!("已探测非目标 {skipped} · 遍历错误 {walk_errors} · 探测错误 {probe_errors}").into(),
        Cli::ReportScanIncomplete => "分析不完整；部分目录项或所选文件无法检查".into(),
        Cli::AnalysisIncomplete => "分析不完整".into(),
        Cli::AnalysisIncompleteInput => "I/O、资源限制或基础环境阻碍了所请求的操作".into(),
        Cli::AnalysisIncompleteEntry => "所请求的条目分析未能完成".into(),
        Cli::Source { size } => format!("输入项: {size} 字节 (0x{size:X})").into(),
        Cli::Target { platform, format, kind } => format!("目标: {platform} · {format} · {kind}").into(),
        Cli::FormatUnavailable => "格式不可用".into(),
        Cli::KindUnavailable => "种类不适用或不可用".into(),
        Cli::ProtectionRecognition { status } => format!("保护识别: {status}").into(),
        Cli::Evidence { evidence } => format!("依据: {evidence}").into(),
        Cli::Route { route, outcome } => format!("方案 {route}: {outcome}").into(),
        Cli::SelectedRoute { route } => format!("已选用方案: {route}").into(),
        Cli::StaticRecovery { status } => format!("静态恢复: {status}").into(),
        Cli::OutputValidation { status } => format!("输出静态验证: {status}").into(),
        Cli::Companion { state } => format!("伴生文件: {state}").into(),
        Cli::CompanionIdentity { size, sha256 } => format!("{size} 字节 · SHA-256 {sha256}").into(),
        Cli::InputView { view } => format!("分析输入视图: {view}").into(),
        Cli::InputViewSplicedNote => "小于 0x1000 的文件偏移对应加载器存根；0x1000 及以上的偏移对应伴生文件中的 (文件偏移 - 0x1000)".into(),
        Cli::MetadataIdentity { version, layout } => format!("IL2CPP 元数据版本: {version} · 布局定义 {layout}").into(),
        Cli::SeededTokens { value } => format!("基于种子的方法令牌: {}", yes_no(*value)).into(),
        Cli::StructuralTokens { value } => format!("结构化方法令牌: {}", yes_no(*value)).into(),
        Cli::MethodIndexRestore { value, context } => format!("方法索引恢复: {} · 需要应用上下文: {}", yes_no(*value), yes_no(*context)).into(),
        Cli::Container { kind, entries, manifests } => format!("容器: {kind} · 条目 {entries} · 清单 {manifests}").into(),
        Cli::Manifest { source, package, version } => format!("清单 {source} → {package} {version}").into(),
        Cli::Unnamed => "<unnamed>".into(),
        Cli::Candidate { entry } => format!("候选: {entry}").into(),
        Cli::MetadataEvidence => "元数据变换依据".into(),
        Cli::Entry { name, status } => format!("条目 {name}: {status}").into(),
        Cli::EntryRoute { route } => format!("方案: {route}").into(),
        Cli::EntryMetadataVersion { version } => format!("元数据版本: {version}").into(),
        Cli::EntryRemapped { remapped } => format!("已重映射方法字段: {remapped}").into(),
        Cli::ModuleContextSource { source } => format!("模块上下文来源: {source}").into(),
        Cli::StageLine { stage, status } => format!("阶段 {stage}: {status}").into(),
        Cli::Recovered { size, sha256 } => format!("已恢复: {size} 字节 · SHA-256 {sha256}").into(),
        Cli::InspectionStatus { status, ms } => format!("检查状态: {status} · {ms} ms").into(),
        Cli::DiagnosticWarning => "警告".into(),
        Cli::DiagnosticError => "错误".into(),
        Cli::DiagnosticReason => "原因".into(),
        Cli::DiagnosticDetail => "详情".into(),
        Cli::DiagnosticEnglish => "英文原文".into(),
    }
}

/// A capability flag as a word of this language.
fn yes_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}
