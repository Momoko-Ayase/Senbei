//! Traditional Chinese (Taiwan) localization (`zh-TW`).

use std::borrow::Cow;

use crate::{Cli, Msg, Step, Term};

pub(crate) fn msg(msg: &Msg) -> Cow<'static, str> {
    match msg {
        Msg::CompanionMissing => "缺少伴生檔案？此載入器需要相符的 <input>._ 載荷。請將它放在輸入檔案旁並再試一次。".into(),
        Msg::CompanionMismatch => "伴生檔案不相符：所提供的 ._ 載荷過短，或其標頭與載入器不同。請使用來自同一組建的伴生檔案；兩個檔案其中之一可能已損毀。".into(),
        Msg::InputTooShort { actual, required } => format!("輸入過短（至少需要 {required} 位元組，實際為 {actual} 位元組）").into(),
        Msg::NotProtected => "不是受 CrackProof 保護的檔案".into(),
        Msg::InvalidPeOffset { offset, input_len } => format!("對於 {input_len} 位元組的輸入而言，PE 標頭偏移 {offset} 無效").into(),
        Msg::DllNeedsPe32Plus { found } => format!("DLL 管線需要 PE32+ 選用標頭魔術數字，但實際為 0x{found:04X}").into(),
        Msg::LayoutUnsupported => "找不到 stage5 標記——此解包工具不支援此組建的結構配置".into(),
        Msg::InternalPanic { file, line, column, message } => format!("於 {file}:{line}:{column} 發生內部錯誤：{message}").into(),
        Msg::DecodeFailed => "受保護資料未能如預期解碼；檔案可能已損毀，或此組建的結構配置不受支援".into(),
        Msg::NotPe => "輸入不是 PE 映像".into(),
        Msg::NotElf64 => "輸入不是小端序 ELF64 映像".into(),
        Msg::NotAarch64 => "輸入不是 AArch64 映像".into(),
        Msg::NotMetadata => "不是 il2cpp global-metadata.dat".into(),
        Msg::NotIl2cppMetadata => "不是 IL2CPP global-metadata.dat".into(),
        Msg::UnsupportedMetadataVersion { version } => format!("不支援的中繼資料版本 {version}").into(),
        Msg::MetadataTransformFailed => "中繼資料轉換未通過驗證".into(),
        Msg::LimitEntry { requested, limit } => format!("資源限制：{requested} 位元組的條目超過 {limit} 位元組的上限").into(),
        Msg::LimitTotal { requested, adding, limit } => format!("資源限制：工作總計 {requested} 位元組超過 {limit} 位元組的上限（新增 {adding} 位元組）").into(),
        Msg::LimitEntries { requested, limit } => format!("資源限制：{requested} 個條目超過上限 {limit}").into(),
        Msg::LimitDepth { requested, limit } => format!("資源限制：巢狀深度 {requested} 超過上限 {limit}").into(),
        Msg::OutputNotRetained => "研究檢查：未保留任何輸出檔案".into(),
        Msg::DryRunDiscarded => "試執行：已捨棄產生的輸出".into(),
        Msg::TransformNoop => "轉換已執行並通過驗證；無須改寫任何內容".into(),
        Msg::CompanionUnmatched => "同目錄下存在 `._` 檔案，但不是此載入器存根的載荷".into(),
        Msg::CompanionUnreadable { reason } => format!("無法讀取同目錄下的 `._` 檔案：{reason}").into(),
        Msg::CompanionUnreadableUnknown => "無法讀取同目錄下的 `._` 檔案".into(),
        Msg::MetadataLeftUntouched { version } => format!("不支援的中繼資料版本 {version}，已保持原樣").into(),
        Msg::UnexpectedPanic { message } => format!("非預期的內部錯誤：{message}").into(),
        Msg::InputNotExamined => "無法檢驗輸入項".into(),
        Msg::NoCandidateValidated => "沒有候選項目通過驗證".into(),
        Msg::NoModule0c => "v24.1 中繼資料缺少模組 0x0C".into(),
        Msg::AmbiguousModule0c => "模組 0x0C 繫結不明確".into(),
        Msg::UnsafePackageEntry { package } => format!("應用程式套件 `{package}` 中含有不安全的條目路徑").into(),
        Msg::UnsafeNestedEntry { path } => format!("`{path}` 中含有不安全的條目路徑").into(),
        Msg::EntryStubTargetOutsideCode { branch, target } => format!("進入點 {branch} 目標 0x{target:X} 位於可執行節區之外（DD8 選取可能錯誤）").into(),
        Msg::MissingMz => "缺少 'MZ' DOS 簽章".into(),
        Msg::TruncatedDosHeader => "DOS 標頭已截斷（無 e_lfanew）".into(),
        Msg::MissingPeSignature { offset } => format!("於 0x{offset:X} 處缺少 'PE\\0\\0' 簽章").into(),
        Msg::TruncatedCoffHeader => "COFF 標頭已截斷".into(),
        Msg::TruncatedOptionalHeader => "選用標頭已截斷".into(),
        Msg::BadOptionalMagic { magic } => format!("選用標頭魔術數字 0x{magic:X} 無效").into(),
        Msg::ImplausibleSectionCount { count } => format!("不合理的節區數量 {count}").into(),
        Msg::ZeroSizeOfImage => "SizeOfImage 為零".into(),
        Msg::SectionTablePastEof => "節區表超出檔案結尾".into(),
        Msg::SectionRawPastEof { index, start, end, file_len } => format!("節區 #{index} 原始資料 [0x{start:X}..0x{end:X}] 超出檔案大小 0x{file_len:X}").into(),
        Msg::NoBaseRelocations => "原生 DLL 無基底重定位表（DD[5] 為零）——在非偏好基底位址載入時將會當機".into(),
        Msg::ZeroEntryPoint => "進入點 RVA 為零".into(),
        Msg::EntryUnmapped { rva } => format!("進入點 RVA 0x{rva:X} 未映射至任何節區").into(),
        Msg::EntryAllZeros { rva } => format!("位於 RVA 0x{rva:X} 的進入點全為零（存根未恢復）").into(),
        Msg::EntryAllInt3 { rva } => format!("位於 RVA 0x{rva:X} 的進入點全為 int3 填充（存根未恢復）").into(),
        Msg::EntryNotExecutable { rva } => format!("進入點 RVA 0x{rva:X} 不在可執行節區內").into(),
        Msg::ImportDirectoryUnmapped { rva } => format!("匯入目錄 RVA 0x{rva:X} 未映射至任何節區").into(),
        Msg::ImportNameUnmapped { index, rva } => format!("匯入描述元 {index} 的 DLL 名稱 RVA 0x{rva:X} 未映射至任何節區").into(),
        Msg::ImportNameUnreadable { index, rva } => format!("匯入描述元 {index} 位於 RVA 0x{rva:X} 的 DLL 名稱不是可讀取的 ASCII（匯入表仍處於加密狀態？）").into(),
        Msg::ClrDirectoryUnmapped { rva } => format!("CLR (COR20) 目錄 RVA 0x{rva:X} 未映射至任何節區").into(),
        Msg::ClrHeaderBadSize { rva, size } => format!("位於 RVA 0x{rva:X} 的 COR20 標頭 cb 為 0x{size:X}（預期為 0x48）——CLR 標頭已損毀").into(),
        Msg::ClrMetadataUnmapped { rva } => format!("CLR MetaData RVA 0x{rva:X} 未映射至任何節區").into(),
        Msg::ClrMetadataNoBsjb { rva } => format!("位於 RVA 0x{rva:X} 的 CLR MetaData 缺少 'BSJB' 簽章（中繼資料已損毀——受控映像將無法載入）").into(),
    }
}

pub(crate) fn step(step: &Step) -> Cow<'static, str> {
    match step {
        Step::DecryptHeader => "解密檔案標頭...".into(),
        Step::DecryptPayload => "解密載荷...".into(),
        Step::LocateConfig => "定位組態配置...".into(),
        Step::DecryptStage2 => "解密 stage2...".into(),
        Step::DecryptStages3To5 => "解密階段 3-5...".into(),
        Step::DecryptSections => "解密節區資料...".into(),
        Step::DecryptSectionsNewLayout => "解密節區資料（新結構配置）...".into(),
        Step::LoadSections => "載入並解壓縮節區...".into(),
        Step::DecryptImports => "解密匯入字串...".into(),
        Step::RebuildHeaders => "重建 PE 標頭...".into(),
        Step::Pe32LocateConfig => "定位組態配置 (PE32)...".into(),
        Step::Pe32Stages => "解密各階段 (PE32)...".into(),
        Step::Pe32EighthStage => "解密 eighthStage (PE32)...".into(),
        Step::Pe32Load => "載入並解壓縮檔案資料 (PE32)...".into(),
        Step::Pe32Text { formula } => format!("解密 .text (PE32 dd8, formula={formula})...").into(),
        Step::Pe32TextSkip => "略過 .text dd8（已為明文）...".into(),
        Step::Pe32Imports => "解密匯入字串 (PE32)...".into(),
        Step::Pe32Rebuild => "重建 PE 檔案配置 (PE32)...".into(),
        Step::InitKeys => "初始化金鑰...".into(),
        Step::DecryptKeyTable => "解密金鑰表...".into(),
        Step::DecryptPrimary => "解密主要描述元...".into(),
        Step::RelocsParams => "處理重定位與解壓縮參數...".into(),
        Step::DecryptBlock1 => "解密程式碼區塊 1 (addr3)...".into(),
        Step::DecryptBlocks2To3 => "解密程式碼區塊 2-3 (addr3b, addr4)...".into(),
        Step::DecryptBlock4 => "解密程式碼區塊 4 (addr5)...".into(),
        Step::DllSections => "解密並解壓縮節區...".into(),
        Step::FixHeaders => "修補 PE 標頭與節區表...".into(),
        Step::AndroidPrimary => "解碼主要 0x9D 目標映像容器...".into(),
        Step::AndroidAuxiliary => "解碼輔助 0x9D ELF 實體化容器...".into(),
        Step::AndroidTables => "重建靜態 ELF 動態連結器表...".into(),
        Step::WriteTo { dest } => format!("寫入至 {dest}").into(),
    }
}

pub(crate) fn term(term: &Term) -> Cow<'static, str> {
    match term {
        Term::Ok => "正常",
        Term::Suspect => "可疑",
        Term::Recognized => "已識別",
        Term::NotRecognized => "未識別",
        Term::Skipped => "已略過",
        Term::Error => "錯誤",
        Term::Restored => "已恢復",
        Term::Duplicate => "重複",
        Term::NotTarget => "非目標",
        Term::Unchanged => "未變更",
        Term::Inventoried => "已列出",
        Term::Failed => "失敗",
        Term::Blocked => "受阻",
        Term::NotAttempted => "未嘗試",
        Term::Succeeded => "成功",
        Term::Rejected => "已拒絕",
        Term::Clean => "乾淨",
        Term::Warnings => "警告",
        Term::NotRun => "未執行",
        Term::Absent => "無",
        Term::Spliced => "已拼接",
        Term::Unmatched => "不相符",
        Term::Unreadable => "無法讀取",
        Term::Detection => "偵測",
        Term::ManifestInventory => "資訊清單清查",
        Term::EntryProbe => "條目探測",
        Term::Recovery => "恢復",
        Term::StaticValidation => "靜態驗證",
        Term::OutputWrite => "輸出寫入",
        Term::SharedLibrary => "共用程式庫",
        Term::Metadata => "中繼資料",
        Term::ExeStyle => "EXE 風格",
        Term::Dll => "DLL",
        Term::AndroidStaged => "Android 分階段",
        Term::MetadataSeeded => "基於種子的中繼資料",
        Term::MetadataStructural => "結構化中繼資料",
        Term::MetadataMethodIndices => "中繼資料方法索引",
        Term::WindowsPe => "Windows PE",
        Term::AndroidElf => "Android ELF",
        Term::Il2cppMetadata => "il2cpp 中繼資料",
        Term::NativeExe => "原生 EXE",
        Term::ManagedExe => ".NET EXE",
        Term::NativeDll => "原生 DLL",
        Term::ManagedDll => ".NET DLL",
        Term::HeaderMagic => "標頭魔術數字",
        Term::ExternalCompanionDeclaration => "宣告外部伴生檔案",
        Term::CompanionSpliced => "伴生檔案已拼接",
        Term::PrivateSection => "私有節區",
        Term::AesSchedule => "AES 金鑰排程",
        Term::ValidatedMetadataTransform => "已驗證的中繼資料轉換",
        Term::Known => "已知",
        Term::ContextRequired => "需要應用程式上下文",
        Term::Unverified => "未驗證",
        Term::Original => "原始檔案",
        Term::SplicedCompanion => "已拼接伴生檔案",
    }
    .into()
}

pub(crate) fn cli(cli: &Cli) -> Cow<'static, str> {
    match cli {
        Cli::Error => "錯誤".into(),
        Cli::Warning => "警告".into(),
        Cli::DoneIn { ms } => format!("完成，耗時 {ms} ms").into(),
        Cli::PressEnter => "\n請按 Enter 鍵結束…".into(),
        Cli::ScanUnreadable { count } => format!("掃描期間有 {count} 個檔案無法讀取，可能遺漏目標").into(),
        Cli::Summary { unpacked, skipped, errors, suspect, metadata } => format!("已解包 {unpacked} · 已略過 {skipped} · 錯誤 {errors} · 可疑 {suspect} · 中繼資料 {metadata}").into(),
        Cli::SummaryPackages { packages } => format!(" · 應用程式套件 {packages}").into(),
        Cli::IntegrityFailed => "完整性檢查失敗".into(),
        Cli::IntegrityFailedLikelyCrash => "! 完整性檢查失敗（執行時期極可能當機）".into(),
        Cli::MetadataLine { rel, dest, remapped } => format!("中繼資料  {rel}  ->  {dest}  (已重新映射 {remapped} 個方法欄位)").into(),
        Cli::MetadataVersionLine { version, dest, remapped } => format!("中繼資料 v{version} -> {dest} (已重新映射 {remapped} 個方法欄位)").into(),
        Cli::MetadataAlreadyClean { version } => format!("中繼資料 v{version}:").into(),
        Cli::MetadataNothingToDo => "已解除混淆，無須處理".into(),
        Cli::EmbeddedMetadataLine { input, dest } => format!("中繼資料  {input}（內嵌）  ->  {dest}").into(),
        Cli::EmbeddedMetadataFailed => "內嵌中繼資料".into(),
        Cli::MetadataUnsupportedLine { version } => format!("不支援的中繼資料版本 {version}，已保持原樣").into(),
        Cli::OutRequiresDirectory => "--out 需要指定目錄引數".into(),
        Cli::UnknownOption { option } => format!("未知的選項 '{option}'").into(),
        Cli::MultipleInputs { first, second } => format!("指定了多個輸入路徑（'{first}' 與 '{second}'）").into(),
        Cli::SubcommandNeedsPath { subcommand } => format!("'{subcommand}' 需要指定輸入路徑").into(),
        Cli::InspectNoDryRun => "'inspect' 不會寫入任何內容；請移除 --dry-run".into(),
        Cli::InspectNoOut => "'inspect' 不會寫入任何內容；不允許使用 --out".into(),
        Cli::DryRunNoOut => "--dry-run 不會寫入任何輸出；不允許使用 --out".into(),
        Cli::ColorRequiresMode => "--color 需要指定 auto、always 或 never".into(),
        Cli::ThreadsRequiresInteger => "--threads 需要指定正整數引數".into(),
        Cli::LimitRequiresInteger { flag } => format!("{flag} 需要指定無號整數引數").into(),
        Cli::LimitMustBePositive { flag } => format!("{flag} 必須大於零").into(),
        Cli::LimitTooLarge { flag } => format!("{flag} 超出支援的位元組範圍").into(),
        Cli::UnknownLimit { flag } => format!("未知的資源選項 '{flag}'").into(),
        Cli::HelpPath => "  <file|folder>\n\
             \x20              受保護的 CrackProof PE (.exe/.dll)、il2cpp\n\
             \x20              global-metadata.dat、受保護的 Android AArch64 程式庫\n\
             \x20              (.so)、Android 應用程式套件 (.apk/.apks/.xapk)，或包含\n\
             \x20              上述項目的資料夾。省略子命令時等同於 'unpack'。"
            .into(),
        Cli::HelpInspect => "  inspect PATH\n\
             \x20              執行研究用的真實靜態恢復流程，並回報觀測到的一切：\n\
             \x20              識別依據、嘗試過的各條路線及其遭拒原因、選用的路線、\n\
             \x20              靜態檢查的判定結果，以及引擎本身的結構依據（保護標頭\n\
             \x20              欄位、種子、模組記錄、恢復映像資訊）。不會保留任何\n\
             \x20              內容：無輸出檔案、無記錄檔、無暫存目錄，且絕不執行\n\
             \x20              輸入項。"
            .into(),
        Cli::HelpUnpack => "  unpack PATH  偵測並恢復；將結果寫入輸出（預設動作）。".into(),
        Cli::HelpJson => "  --json       將單一含版本資訊的機器可讀報告寫入 stdout，不輸出其他\n\
             \x20              內容。隱含安靜模式與 --no-log。"
            .into(),
        Cli::HelpDryRun => "  --dry-run    執行真實恢復流程但不保留任何內容：無輸出目錄，亦無\n\
             \x20              記錄檔。Android 提取仍會使用其專屬的暫存工作區，完成後\n\
             \x20              即會捨棄。"
            .into(),
        Cli::HelpThreads => "  --threads N  此次執行的工作執行緒正整數上限。會覆寫 SENBEI_THREADS；\n\
             \x20              設為 1 會使用循序執行路徑。環境變數本身不會變更。"
            .into(),
        Cli::HelpColor => "  --color MODE 可為 auto（預設）、always 或 never；亦支援 --color=MODE。\n\
             \x20              auto 會分別為終端機的 stdout/stderr 著色，除非 NO_COLOR\n\
             \x20              非空或 TERM=dumb。明確指定 always/never 會覆寫這些變數。\n\
             \x20              JSON 與儲存的記錄檔維持純文字。"
            .into(),
        Cli::HelpScanAll => "  --scan-all   一併探測低於檔案大小下限的 .exe/.dll/.so/中繼資料名稱；\n\
             \x20              其他檔案名稱仍會排除。"
            .into(),
        Cli::HelpStrictIntegrity => "  --strict-integrity\n\
             \x20              當任何輸出未通過靜態完整性檢查（可疑）或有檔案發生錯誤\n\
             \x20              時，以非零狀態碼結束。預設為關閉：可疑檔案仍會寫出，且\n\
             \x20              除非有檔案發生錯誤，否則處理序會以 0 結束。安靜模式層級\n\
             \x20              維持不變。搭配 'inspect' 時，檢查會套用至為研究而實際\n\
             \x20              恢復的映像；不會保留任何輸出檔案。"
            .into(),
        Cli::HelpLimits { entry_mib, total_mib, entries, depth } => format!(
            "  Android 資源限制（MiB = 1048576 位元組）：\n\
             \x20 --max-entry-mib N  單一封存條目／已解碼緩衝區／輸出（預設 {entry_mib}）\n\
             \x20 --max-total-mib N  累計封存位元組數與單一引擎工作配額（預設 {total_mib}）\n\
             \x20 --max-entries N    封存條目／階段 2 記錄數（預設 {entries}）\n\
             \x20 --max-depth N      巢狀深度，根層級 = 0（預設 {depth}）\n\
             \x20 系統會在解壓縮或配置記憶體前檢查限制；這些限制並非尖峰記憶體使用量上限。"
        )
        .into(),
        Cli::HelpExitCodes => "  結束代碼：0 成功，1 目標失敗（或啟用 --strict-integrity 時有可疑項），\n\
             \x20 2 命令列參數遭拒。"
            .into(),
        Cli::ReportScanHeading => "掃描".into(),
        Cli::ReportScan { skipped, walk_errors, probe_errors } => format!("已探測非目標 {skipped} · 走訪錯誤 {walk_errors} · 探測錯誤 {probe_errors}").into(),
        Cli::ReportScanIncomplete => "分析不完整；部分目錄項目或所選檔案無法檢驗".into(),
        Cli::AnalysisIncomplete => "分析不完整".into(),
        Cli::AnalysisIncompleteInput => "I/O、資源限制或底層機制導致無法完成所要求的工作".into(),
        Cli::AnalysisIncompleteEntry => "無法完成所要求的條目分析".into(),
        Cli::Source { size } => format!("來源: {size} 位元組 (0x{size:X})").into(),
        Cli::Target { platform, format, kind } => format!("目標: {platform} · {format} · {kind}").into(),
        Cli::FormatUnavailable => "格式無法使用".into(),
        Cli::KindUnavailable => "種類不適用或無法使用".into(),
        Cli::ProtectionRecognition { status } => format!("保護識別: {status}").into(),
        Cli::Evidence { evidence } => format!("依據: {evidence}").into(),
        Cli::Route { route, outcome } => format!("路線 {route}: {outcome}").into(),
        Cli::SelectedRoute { route } => format!("已選用路線: {route}").into(),
        Cli::StaticRecovery { status } => format!("靜態恢復: {status}").into(),
        Cli::OutputValidation { status } => format!("輸出靜態驗證: {status}").into(),
        Cli::Companion { state } => format!("伴生檔案: {state}").into(),
        Cli::CompanionIdentity { size, sha256 } => format!("{size} 位元組 · SHA-256 {sha256}").into(),
        Cli::InputView { view } => format!("分析輸入檢視: {view}").into(),
        Cli::InputViewSplicedNote => "低於 0x1000 的檔案偏移定址載入器存根；自 0x1000 起的偏移定址伴生檔案偏移（檔案偏移 - 0x1000）".into(),
        Cli::MetadataIdentity { version, layout } => format!("IL2CPP 中繼資料版本: {version} · 結構配置定義 {layout}").into(),
        Cli::SeededTokens { value } => format!("基於種子的方法權杖: {}", yes_no(*value)).into(),
        Cli::StructuralTokens { value } => format!("結構化方法權杖: {}", yes_no(*value)).into(),
        Cli::MethodIndexRestore { value, context } => format!("方法索引恢復: {} · 需要應用程式上下文: {}", yes_no(*value), yes_no(*context)).into(),
        Cli::Container { kind, entries, manifests } => format!("容器: {kind} · {entries} 個條目 · {manifests} 份資訊清單").into(),
        Cli::Manifest { source, package, version } => format!("資訊清單 {source} → {package} {version}").into(),
        Cli::Unnamed => "<unnamed>".into(),
        Cli::Candidate { entry } => format!("候選: {entry}").into(),
        Cli::MetadataEvidence => "中繼資料轉換依據".into(),
        Cli::Entry { name, status } => format!("條目 {name}: {status}").into(),
        Cli::EntryRoute { route } => format!("路線: {route}").into(),
        Cli::EntryMetadataVersion { version } => format!("中繼資料版本: {version}").into(),
        Cli::EntryRemapped { remapped } => format!("已重新映射的方法欄位: {remapped}").into(),
        Cli::ModuleContextSource { source } => format!("模組上下文來源: {source}").into(),
        Cli::StageLine { stage, status } => format!("階段 {stage}: {status}").into(),
        Cli::Recovered { size, sha256 } => format!("已恢復: {size} 位元組 · SHA-256 {sha256}").into(),
        Cli::InspectionStatus { status, ms } => format!("檢查狀態: {status} · {ms} ms").into(),
        Cli::DiagnosticWarning => "警告".into(),
        Cli::DiagnosticError => "錯誤".into(),
        Cli::DiagnosticReason => "原因".into(),
        Cli::DiagnosticDetail => "詳情".into(),
        Cli::DiagnosticEnglish => "英文原文".into(),
    }
}

/// A capability flag as a word of this language.
fn yes_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}
