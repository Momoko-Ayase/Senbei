//! Japanese (`ja`): console and report wording for Senbei.

use std::borrow::Cow;

use crate::{Cli, Msg, Step, Term};

pub(crate) fn msg(msg: &Msg) -> Cow<'static, str> {
    match msg {
        Msg::CompanionMissing => "コンパニオンが見つからない可能性があります。このローダーには対応する<input>._ペイロードが必要です。入力ファイルの隣に配置して再試行してください。".into(),
        Msg::CompanionMismatch => "コンパニオンが一致しません。指定された._ペイロードが短すぎるか、ヘッダーがローダーと異なります。同じビルドのコンパニオンを使用してください (いずれかのファイルが破損している可能性があります)。".into(),
        Msg::InputTooShort { actual, required } => format!("入力が短すぎます (最低{required}バイト必要ですが、{actual}バイトです)").into(),
        Msg::NotProtected => "CrackProofで保護されたファイルではありません".into(),
        Msg::InvalidPeOffset { offset, input_len } => format!("{input_len}バイトの入力に対する無効なPEヘッダーオフセット{offset}").into(),
        Msg::DllNeedsPe32Plus { found } => format!("DLLパイプラインにはPE32+のオプショナルヘッダーマジックが必要ですが、0x{found:04X}が検出されました").into(),
        Msg::LayoutUnsupported => "stage5マーカーが見つかりません — このビルドのレイアウトはこのアンパッカーでは非対応です".into(),
        Msg::InternalPanic { file, line, column, message } => format!("{file}:{line}:{column}で内部パニックが発生しました: {message}").into(),
        Msg::DecodeFailed => "保護データが想定どおりにデコードされませんでした。ファイルが破損しているか、このビルドのレイアウトに非対応です".into(),
        Msg::NotPe => "入力はPEイメージではありません".into(),
        Msg::NotElf64 => "入力はELF64リトルエンディアンイメージではありません".into(),
        Msg::NotAarch64 => "入力はAArch64イメージではありません".into(),
        Msg::NotMetadata => "il2cppのglobal-metadata.datではありません".into(),
        Msg::NotIl2cppMetadata => "IL2CPPのglobal-metadata.datではありません".into(),
        Msg::UnsupportedMetadataVersion { version } => format!("非対応のメタデータバージョン{version}").into(),
        Msg::MetadataTransformFailed => "メタデータ変換の検証に失敗しました".into(),
        Msg::LimitEntry { requested, limit } => format!("リソース上限: {requested}バイトのエントリが{limit}バイトの上限を超えています").into(),
        Msg::LimitTotal { requested, adding, limit } => format!("リソース上限: タスク合計{requested}バイトが{limit}バイトの上限を超えています ({adding}バイトの追加時)").into(),
        Msg::LimitEntries { requested, limit } => format!("リソース上限: エントリ数{requested}が上限の{limit}を超えています").into(),
        Msg::LimitDepth { requested, limit } => format!("リソース上限: ネスト深さ{requested}が上限の{limit}を超えています").into(),
        Msg::OutputNotRetained => "調査用の検査: 出力ファイルは保存されませんでした".into(),
        Msg::DryRunDiscarded => "ドライラン: 生成された出力は破棄されました".into(),
        Msg::TransformNoop => "変換を実行・検証しましたが、書き換えが必要な箇所はありませんでした".into(),
        Msg::CompanionUnmatched => "同じフォルダーに`._`ファイルがありますが、このスタブのペイロードではありません".into(),
        Msg::CompanionUnreadable { reason } => format!("同じフォルダーの`._`ファイルを読み取れませんでした: {reason}").into(),
        Msg::CompanionUnreadableUnknown => "同じフォルダーの`._`ファイルを読み取れませんでした".into(),
        Msg::MetadataLeftUntouched { version } => format!("非対応のメタデータバージョン{version}のため、変更せずにそのまま残しました").into(),
        Msg::UnexpectedPanic { message } => format!("予期しないパニック: {message}").into(),
        Msg::InputNotExamined => "入力を調査できませんでした".into(),
        Msg::NoCandidateValidated => "検証を通過した候補がありません".into(),
        Msg::NoModule0c => "v24.1メタデータ用のモジュール0x0Cがありません".into(),
        Msg::AmbiguousModule0c => "モジュール0x0Cの対応付けが曖昧です".into(),
        Msg::UnsafePackageEntry { package } => format!("パッケージ`{package}`内に安全でないエントリパスがあります").into(),
        Msg::UnsafeNestedEntry { path } => format!("`{path}`内に安全でないエントリパスがあります").into(),
        Msg::EntryStubTargetOutsideCode { branch, target } => format!("エントリポイントの{branch}先0x{target:X}が実行可能セクション外にあります (DD8の選択が誤っている可能性があります)").into(),
        Msg::MissingMz => "'MZ' DOSシグネチャがありません".into(),
        Msg::TruncatedDosHeader => "DOSヘッダーが切り詰められています (e_lfanewがありません)".into(),
        Msg::MissingPeSignature { offset } => format!("0x{offset:X}に'PE\\0\\0'シグネチャがありません").into(),
        Msg::TruncatedCoffHeader => "COFFヘッダーが切り詰められています".into(),
        Msg::TruncatedOptionalHeader => "オプショナルヘッダーが切り詰められています".into(),
        Msg::BadOptionalMagic { magic } => format!("不正なオプショナルヘッダーマジック0x{magic:X}").into(),
        Msg::ImplausibleSectionCount { count } => format!("セクション数{count}が不自然です").into(),
        Msg::ZeroSizeOfImage => "SizeOfImageがゼロです".into(),
        Msg::SectionTablePastEof => "セクションテーブルがファイル終端を超えています".into(),
        Msg::SectionRawPastEof { index, start, end, file_len } => format!("セクション#{index}のファイル内データ[0x{start:X}..0x{end:X}]がファイルサイズ0x{file_len:X}を超えています").into(),
        Msg::NoBaseRelocations => "ネイティブDLLにベース再配置テーブルがありません (DD[5]がゼロです) — 推奨ベース以外にロードされるとクラッシュします".into(),
        Msg::ZeroEntryPoint => "エントリポイントRVAがゼロです".into(),
        Msg::EntryUnmapped { rva } => format!("エントリポイントRVA 0x{rva:X}がどのセクションにもマップされていません").into(),
        Msg::EntryAllZeros { rva } => format!("RVA 0x{rva:X}のエントリポイントがすべてゼロです (スタブが復元されていません)").into(),
        Msg::EntryAllInt3 { rva } => format!("RVA 0x{rva:X}のエントリポイントがすべてint3パディングです (スタブが復元されていません)").into(),
        Msg::EntryNotExecutable { rva } => format!("エントリポイントRVA 0x{rva:X}が実行可能セクション内にありません").into(),
        Msg::ImportDirectoryUnmapped { rva } => format!("インポートディレクトリRVA 0x{rva:X}がどのセクションにもマップされていません").into(),
        Msg::ImportNameUnmapped { index, rva } => format!("インポート記述子{index}のDLL名RVA 0x{rva:X}がどのセクションにもマップされていません").into(),
        Msg::ImportNameUnreadable { index, rva } => format!("インポート記述子{index}のRVA 0x{rva:X}にあるDLL名が読み取り可能なASCIIではありません (インポートが暗号化されたままの可能性があります)").into(),
        Msg::ClrDirectoryUnmapped { rva } => format!("CLR (COR20) ディレクトリRVA 0x{rva:X}がどのセクションにもマップされていません").into(),
        Msg::ClrHeaderBadSize { rva, size } => format!("RVA 0x{rva:X}のCOR20ヘッダーのcbが0x{size:X}です (期待値は0x48) — CLRヘッダーが破損しています").into(),
        Msg::ClrMetadataUnmapped { rva } => format!("CLR MetaData RVA 0x{rva:X}がどのセクションにもマップされていません").into(),
        Msg::ClrMetadataNoBsjb { rva } => format!("RVA 0x{rva:X}のCLR MetaDataに'BSJB'シグネチャがありません (メタデータが破損しています — マネージドイメージはロードされません)").into(),
    }
}

pub(crate) fn step(step: &Step) -> Cow<'static, str> {
    match step {
        Step::DecryptHeader => "ファイルヘッダーを復号中...".into(),
        Step::DecryptPayload => "ペイロードを復号中...".into(),
        Step::LocateConfig => "構成レイアウトを特定中...".into(),
        Step::DecryptStage2 => "stage2を復号中...".into(),
        Step::DecryptStages3To5 => "ステージ3-5を復号中...".into(),
        Step::DecryptSections => "セクションデータを復号中...".into(),
        Step::DecryptSectionsNewLayout => "セクションデータを復号中 (新レイアウト)...".into(),
        Step::LoadSections => "セクションを読み込み・展開中...".into(),
        Step::DecryptImports => "インポート文字列を復号中...".into(),
        Step::RebuildHeaders => "PEヘッダーを再構築中...".into(),
        Step::Pe32LocateConfig => "構成レイアウトを特定中 (PE32)...".into(),
        Step::Pe32Stages => "ステージを復号中 (PE32)...".into(),
        Step::Pe32EighthStage => "eighthStageを復号中 (PE32)...".into(),
        Step::Pe32Load => "ファイルデータを読み込み・展開中 (PE32)...".into(),
        Step::Pe32Text { formula } => {
            format!(".textを復号中 (PE32 dd8, formula={formula})...").into()
        }
        Step::Pe32TextSkip => ".text dd8をスキップ中 (すでに平文)...".into(),
        Step::Pe32Imports => "インポート文字列を復号中 (PE32)...".into(),
        Step::Pe32Rebuild => "PEファイルレイアウトを再構築中 (PE32)...".into(),
        Step::InitKeys => "鍵を初期化中...".into(),
        Step::DecryptKeyTable => "鍵テーブルを復号中...".into(),
        Step::DecryptPrimary => "プライマリ記述子を復号中...".into(),
        Step::RelocsParams => "再配置と展開パラメーターを処理中...".into(),
        Step::DecryptBlock1 => "コードブロック1 (addr3) を復号中...".into(),
        Step::DecryptBlocks2To3 => "コードブロック2-3 (addr3b, addr4) を復号中...".into(),
        Step::DecryptBlock4 => "コードブロック4 (addr5) を復号中...".into(),
        Step::DllSections => "セクションを復号・展開中...".into(),
        Step::FixHeaders => "PEヘッダーとセクションテーブルを修正中...".into(),
        Step::AndroidPrimary => "プライマリ0x9D対象イメージコンテナーをデコード中...".into(),
        Step::AndroidAuxiliary => "補助0x9D ELF実体化コンテナーをデコード中...".into(),
        Step::AndroidTables => "静的ELF動的リンカーテーブルを再構築中...".into(),
        Step::WriteTo { dest } => format!("{dest}に書き込み").into(),
    }
}

pub(crate) fn term(term: &Term) -> Cow<'static, str> {
    match term {
        Term::Ok => "正常",
        Term::Suspect => "要注意",
        Term::Recognized => "認識済み",
        Term::NotRecognized => "未認識",
        Term::Skipped => "スキップ",
        Term::Error => "エラー",
        Term::Restored => "復元済み",
        Term::Duplicate => "重複",
        Term::NotTarget => "対象外",
        Term::Unchanged => "変更なし",
        Term::Inventoried => "記載のみ",
        Term::Failed => "失敗",
        Term::Blocked => "ブロック",
        Term::NotAttempted => "未試行",
        Term::Succeeded => "成功",
        Term::Rejected => "却下",
        Term::Clean => "問題なし",
        Term::Warnings => "警告あり",
        Term::NotRun => "未実行",
        Term::Absent => "なし",
        Term::Spliced => "連結済み",
        Term::Unmatched => "不一致",
        Term::Unreadable => "読み取り不能",
        Term::Detection => "検出",
        Term::ManifestInventory => "マニフェスト一覧化",
        Term::EntryProbe => "エントリプローブ",
        Term::Recovery => "復元",
        Term::StaticValidation => "静的検証",
        Term::OutputWrite => "出力書き込み",
        Term::SharedLibrary => "共有ライブラリ",
        Term::Metadata => "メタデータ",
        Term::ExeStyle => "EXE形式",
        Term::Dll => "DLL",
        Term::AndroidStaged => "Android段階型",
        Term::MetadataSeeded => "シード方式メタデータ",
        Term::MetadataStructural => "構造方式メタデータ",
        Term::MetadataMethodIndices => "メタデータメソッドインデックス",
        Term::WindowsPe => "Windows PE",
        Term::AndroidElf => "Android ELF",
        Term::Il2cppMetadata => "il2cppメタデータ",
        Term::NativeExe => "ネイティブEXE",
        Term::ManagedExe => "マネージドEXE",
        Term::NativeDll => "ネイティブDLL",
        Term::ManagedDll => "マネージドDLL",
        Term::HeaderMagic => "ヘッダーマジック",
        Term::ExternalCompanionDeclaration => "外部コンパニオン宣言",
        Term::CompanionSpliced => "コンパニオン連結",
        Term::PrivateSection => "専用セクション",
        Term::AesSchedule => "AES鍵スケジュール",
        Term::ValidatedMetadataTransform => "検証済みメタデータ変換",
        Term::Known => "既知",
        Term::ContextRequired => "コンテキストが必要",
        Term::Unverified => "未検証",
        Term::Original => "元ファイル",
        Term::SplicedCompanion => "連結コンパニオン",
    }
    .into()
}

pub(crate) fn cli(cli: &Cli) -> Cow<'static, str> {
    match cli {
        Cli::Error => "エラー".into(),
        Cli::Warning => "警告".into(),
        Cli::DoneIn { ms } => format!("{ms} msで完了").into(),
        Cli::PressEnter => "\nEnterキーを押して終了…".into(),
        Cli::ScanUnreadable { count } => format!("スキャン中に{count}個のファイルを読み取れませんでした。対象が見落とされた可能性があります").into(),
        Cli::Summary { unpacked, skipped, errors, suspect, metadata } => format!("アンパック済み {unpacked} · スキップ {skipped} · エラー {errors} · 要注意 {suspect} · メタデータ {metadata}").into(),
        Cli::SummaryPackages { packages } => format!(" · パッケージ {packages}").into(),
        Cli::IntegrityFailed => "整合性検査に失敗しました".into(),
        Cli::IntegrityFailedLikelyCrash => "! 整合性検査に失敗しました (実行時にクラッシュする可能性が高いです)".into(),
        Cli::MetadataLine { rel, dest, remapped } => format!("メタデータ  {rel}  ->  {dest}  (再マップされたメソッドフィールド: {remapped})").into(),
        Cli::MetadataVersionLine { version, dest, remapped } => format!("メタデータ v{version} -> {dest} (再マップされたメソッドフィールド: {remapped})").into(),
        Cli::MetadataAlreadyClean { version } => format!("メタデータ v{version}:").into(),
        Cli::MetadataNothingToDo => "難読化解除済みのため、処理は不要です".into(),
        Cli::EmbeddedMetadataLine { input, dest } => format!("メタデータ  {input} (埋め込み)  ->  {dest}").into(),
        Cli::EmbeddedMetadataFailed => "埋め込みメタデータ".into(),
        Cli::MetadataUnsupportedLine { version } => format!("非対応のメタデータバージョン{version}のため、変更せずにそのまま残しました").into(),
        Cli::OutRequiresDirectory => "--outにはディレクトリ引数が必要です".into(),
        Cli::UnknownOption { option } => format!("不明なオプション '{option}'").into(),
        Cli::MultipleInputs { first, second } => format!("複数の入力パスが指定されています ('{first}' と '{second}')").into(),
        Cli::SubcommandNeedsPath { subcommand } => format!("'{subcommand}' には入力パスが必要です").into(),
        Cli::InspectNoDryRun => "'inspect' は何も書き込まないため、--dry-runは不要です".into(),
        Cli::InspectNoOut => "'inspect' は何も書き込まないため、--outは指定できません".into(),
        Cli::DryRunNoOut => "--dry-runは何も出力しないため、--outは指定できません".into(),
        Cli::ColorRequiresMode => "--colorにはauto、always、またはneverが必要です".into(),
        Cli::ThreadsRequiresInteger => "--threadsには正の整数引数が必要です".into(),
        Cli::LimitRequiresInteger { flag } => format!("{flag}には符号なし整数引数が必要です").into(),
        Cli::LimitMustBePositive { flag } => format!("{flag}は0より大きい必要があります").into(),
        Cli::LimitTooLarge { flag } => format!("{flag}が対応バイト範囲を超えています").into(),
        Cli::UnknownLimit { flag } => format!("不明なリソースオプション '{flag}'").into(),
        Cli::HelpPath => "  <file|folder>\n\
             \x20              CrackProof PE (.exe/.dll)、il2cpp global-metadata.dat、\n\
             \x20              保護されたAndroid AArch64ライブラリ (.so)、Androidアプリ\n\
             \x20              パッケージ (.apk/.apks/.xapk)、またはそれらを含むフォルダー。\n\
             \x20              サブコマンド省略時は 'unpack' と同じです。"
            .into(),
        Cli::HelpInspect => "  inspect PATH\n\
             \x20              調査用に実際の静的復元を実行し、観測されたすべての内容を\n\
             \x20              報告します: 認識の根拠、試行した各ルートと却下理由、選択された\n\
             \x20              ルート、静的検証の判定、およびエンジン自身の構造的根拠\n\
             \x20              (保護ヘッダーフィールド、シード、モジュールレコード、復元\n\
             \x20              イメージの情報)。出力ファイル、ログ、一時ツリーは一切保存されず、\n\
             \x20              入力が実行されることもありません。"
            .into(),
        Cli::HelpUnpack => "  unpack PATH  検出と復元を行い、出力を書き込みます (既定)。".into(),
        Cli::HelpJson => "  --json       バージョン付きの機械可読レポート1件のみを標準出力に書き込みます。\n\
             \x20              quietおよび--no-logが暗黙に有効になります。"
            .into(),
        Cli::HelpDryRun => "  --dry-run    実際の復元を実行しますが、出力ツリーもログも保存しません。\n\
             \x20              Androidの抽出では専用の一時ワークスペースを使用しますが、\n\
             \x20              処理後に破棄されます。"
            .into(),
        Cli::HelpThreads => "  --threads N  この実行での正のワーカースレッド数上限。SENBEI_THREADSを\n\
             \x20              上書きし、1で逐次処理を選択します。環境変数は変更されません。"
            .into(),
        Cli::HelpColor => "  --color MODE auto (既定)、always、またはnever (--color=MODEも可)。\n\
             \x20              autoは、NO_COLORが空でない場合やTERM=dumbの場合を除き、\n\
             \x20              端末の標準出力と標準エラーを個別に色付けします。明示的な\n\
             \x20              always/neverはこれらの変数を上書きします。JSONと保存される\n\
             \x20              ログは常にプレーンテキストのままです。"
            .into(),
        Cli::HelpScanAll => "  --scan-all   サイズ下限未満の対象名 (.exe/.dll/.so/メタデータ) も\n\
             \x20              プローブします。それ以外のファイル名は引き続き除外されます。"
            .into(),
        Cli::HelpStrictIntegrity => "  --strict-integrity\n\
             \x20              いずれかの出力が静的整合性検査に失敗した場合 (要注意) または\n\
             \x20              ファイルエラー時に非ゼロで終了します。既定ではオフです:\n\
             \x20              要注意でもファイルは書き込まれ、エラーがない限り終了コード0で\n\
             \x20              終了します。quietレベルは変更されません。\n\
             \x20              'inspect' 時は調査用に復元されたイメージに対して検査を行い、\n\
             \x20              出力ファイルは保存されません。"
            .into(),
        Cli::HelpLimits { entry_mib, total_mib, entries, depth } => format!(
            "  Androidのリソース上限 (MiB = 1048576バイト):\n\
             \x20 --max-entry-mib N  単一アーカイブエントリ/デコード済みバッファー/出力 (既定 {entry_mib})\n\
             \x20 --max-total-mib N  累積アーカイブバイト数・エンジン別タスクバジェット (既定 {total_mib})\n\
             \x20 --max-entries N    アーカイブエントリ/ステージ2レコード数 (既定 {entries})\n\
             \x20 --max-depth N      ネスト深さ、ルート = 0 (既定 {depth})\n\
             \x20 上限は展開・割り当て前に検査されます。ピークRSSの上限ではありません。"
        )
        .into(),
        Cli::HelpLanguage => "  SENBEI_LANG  表示言語: en、zh-CN、zh-TW、ja、またはko。未設定時は\n\
             \x20              システムの言語を使用します。JSONと保存されるログは常に英語です。"
            .into(),
        Cli::HelpExitCodes => "  終了コード: 0 成功、1 対象の失敗 (--strict-integrity時の要注意を含む)、\n\
             \x20 2 コマンドライン引数の却下。"
            .into(),
        Cli::ReportScanHeading => "スキャン".into(),
        Cli::ReportScan { skipped, walk_errors, probe_errors } => format!("プローブした対象外 {skipped} · 走査エラー {walk_errors} · プローブエラー {probe_errors}").into(),
        Cli::ReportScanIncomplete => "解析が不完全です。一部のディレクトリ項目または選択したファイルを調査できませんでした".into(),
        Cli::AnalysisIncomplete => "解析不完全".into(),
        Cli::AnalysisIncompleteInput => "I/O、リソース上限、または基盤の問題により要求された処理を完了できませんでした".into(),
        Cli::AnalysisIncompleteEntry => "要求されたエントリの解析を完了できませんでした".into(),
        Cli::Source { size } => format!("入力: {size}バイト (0x{size:X})").into(),
        Cli::Target { platform, format, kind } => format!("対象: {platform} · {format} · {kind}").into(),
        Cli::FormatUnavailable => "フォーマット不明".into(),
        Cli::KindUnavailable => "種類は該当なしまたは不明".into(),
        Cli::ProtectionRecognition { status } => format!("保護認識: {status}").into(),
        Cli::Evidence { evidence } => format!("根拠: {evidence}").into(),
        Cli::Route { route, outcome } => format!("ルート {route}: {outcome}").into(),
        Cli::SelectedRoute { route } => format!("選択ルート: {route}").into(),
        Cli::StaticRecovery { status } => format!("静的復元: {status}").into(),
        Cli::OutputValidation { status } => format!("出力の静的検証: {status}").into(),
        Cli::Companion { state } => format!("コンパニオン: {state}").into(),
        Cli::CompanionIdentity { size, sha256 } => format!("{size}バイト · SHA-256 {sha256}").into(),
        Cli::InputView { view } => format!("解析入力ビュー: {view}").into(),
        Cli::InputViewSplicedNote => "0x1000未満のファイルオフセットはスタブを、0x1000以上のオフセットはコンパニオンのオフセット (ファイルオフセット - 0x1000) を指します".into(),
        Cli::MetadataIdentity { version, layout } => format!("IL2CPPメタデータバージョン: {version} · レイアウト定義 {layout}").into(),
        Cli::SeededTokens { value } => format!("シード方式のメソッドトークン: {}", yes_no(*value)).into(),
        Cli::StructuralTokens { value } => format!("構造方式のメソッドトークン: {}", yes_no(*value)).into(),
        Cli::MethodIndexRestore { value, context } => format!("メソッドインデックス復元: {} · アプリケーションコンテキストが必要: {}", yes_no(*value), yes_no(*context)).into(),
        Cli::Container { kind, entries, manifests } => format!("コンテナー: {kind} · エントリ {entries} · マニフェスト {manifests}").into(),
        Cli::Manifest { source, package, version } => format!("マニフェスト {source} → {package} {version}").into(),
        Cli::Unnamed => "<unnamed>".into(),
        Cli::Candidate { entry } => format!("候補: {entry}").into(),
        Cli::MetadataEvidence => "メタデータ変換の根拠".into(),
        Cli::Entry { name, status } => format!("エントリ {name}: {status}").into(),
        Cli::EntryRoute { route } => format!("ルート: {route}").into(),
        Cli::EntryMetadataVersion { version } => format!("メタデータバージョン: {version}").into(),
        Cli::EntryRemapped { remapped } => format!("再マップされたメソッドフィールド: {remapped}").into(),
        Cli::ModuleContextSource { source } => format!("モジュールコンテキストの取得元: {source}").into(),
        Cli::StageLine { stage, status } => format!("ステージ {stage}: {status}").into(),
        Cli::Recovered { size, sha256 } => format!("復元イメージ: {size}バイト · SHA-256 {sha256}").into(),
        Cli::InspectionStatus { status, ms } => format!("検査状態: {status} · {ms} ms").into(),
        Cli::DiagnosticWarning => "警告".into(),
        Cli::DiagnosticError => "エラー".into(),
        Cli::DiagnosticReason => "理由".into(),
        Cli::DiagnosticDetail => "詳細".into(),
        Cli::DiagnosticEnglish => "英語原文".into(),
    }
}

/// A capability flag as a word of this language.
fn yes_no(value: bool) -> &'static str {
    if value { "はい" } else { "いいえ" }
}
