//! Korean (`ko`) translations of Senbei console and report text.

use std::borrow::Cow;

use crate::{Cli, Msg, Step, Term};

pub(crate) fn msg(msg: &Msg) -> Cow<'static, str> {
    match msg {
        Msg::CompanionMissing => "컴패니언 파일이 누락되었습니까? 이 로더는 일치하는 <input>._ 페이로드를 필요로 합니다. 입력 파일 옆에 두고 다시 시도하십시오.".into(),
        Msg::CompanionMismatch => "컴패니언 파일이 일치하지 않습니다: 제공된 ._ 페이로드가 너무 짧거나 헤더가 로더의 헤더와 다릅니다. 동일한 빌드의 컴패니언 파일을 사용하십시오. 두 파일 중 하나가 손상되었을 수 있습니다.".into(),
        Msg::InputTooShort { actual, required } => format!(
            "입력이 너무 짧습니다 (최소 {required}바이트 필요, 실제 {actual}바이트)"
        )
        .into(),
        Msg::NotProtected => "CrackProof로 보호된 파일이 아닙니다".into(),
        Msg::InvalidPeOffset { offset, input_len } => format!(
            "{input_len}바이트 입력에 대해 잘못된 PE 헤더 오프셋 {offset}입니다"
        )
        .into(),
        Msg::DllNeedsPe32Plus { found } => format!(
            "DLL 파이프라인에는 PE32+ 선택적 헤더 매직이 필요하지만 0x{found:04X}이(가) 확인되었습니다"
        )
        .into(),
        Msg::LayoutUnsupported => {
            "stage5 마커를 찾을 수 없습니다 — 이 빌드의 레이아웃은 이 언패커에서 지원되지 않습니다"
                .into()
        }
        Msg::InternalPanic {
            file,
            line,
            column,
            message,
        } => format!("{file}:{line}:{column}에서 내부 패닉 발생: {message}").into(),
        Msg::DecodeFailed => "보호된 데이터가 예상대로 디코딩되지 않았습니다. 파일이 손상되었거나 이 빌드의 레이아웃이 지원되지 않습니다".into(),
        Msg::NotPe => "입력이 PE 이미지가 아닙니다".into(),
        Msg::NotElf64 => "입력이 ELF64 리틀 엔디안 이미지가 아닙니다".into(),
        Msg::NotAarch64 => "입력이 AArch64 이미지가 아닙니다".into(),
        Msg::NotMetadata => "il2cpp global-metadata.dat가 아닙니다".into(),
        Msg::NotIl2cppMetadata => "IL2CPP global-metadata.dat가 아닙니다".into(),
        Msg::UnsupportedMetadataVersion { version } => {
            format!("지원되지 않는 메타데이터 버전 {version}").into()
        }
        Msg::MetadataTransformFailed => "메타데이터 변환이 검증되지 않았습니다".into(),
        Msg::LimitEntry { requested, limit } => format!(
            "리소스 제한: {requested}바이트 항목이 {limit}바이트 상한을 초과합니다"
        )
        .into(),
        Msg::LimitTotal {
            requested,
            adding,
            limit,
        } => format!(
            "리소스 제한: 작업 합계 {requested}바이트가 {limit}바이트 상한을 초과합니다 ({adding}바이트 추가 시)"
        )
        .into(),
        Msg::LimitEntries { requested, limit } => {
            format!("리소스 제한: 항목 {requested}개가 상한 {limit}개를 초과합니다").into()
        }
        Msg::LimitDepth { requested, limit } => format!(
            "리소스 제한: 중첩 깊이 {requested}이(가) 상한 {limit}을(를) 초과합니다"
        )
        .into(),
        Msg::OutputNotRetained => "연구용 검사: 출력 파일이 유지되지 않았습니다".into(),
        Msg::DryRunDiscarded => "시험 실행: 생성된 출력이 폐기되었습니다".into(),
        Msg::TransformNoop => "변환이 실행되고 검증되었으며, 다시 기록할 필요가 없었습니다".into(),
        Msg::CompanionUnmatched => {
            "같은 위치에 `._` 파일이 존재하지만 이 스텁의 페이로드가 아닙니다".into()
        }
        Msg::CompanionUnreadable { reason } => {
            format!("같은 위치의 `._` 파일을 읽을 수 없습니다: {reason}").into()
        }
        Msg::CompanionUnreadableUnknown => "같은 위치의 `._` 파일을 읽을 수 없습니다".into(),
        Msg::MetadataLeftUntouched { version } => {
            format!("지원되지 않는 메타데이터 버전 {version}, 변경하지 않고 유지함").into()
        }
        Msg::UnexpectedPanic { message } => format!("예기치 않은 패닉: {message}").into(),
        Msg::InputNotExamined => "입력을 조사할 수 없었습니다".into(),
        Msg::NoCandidateValidated => "검증된 후보가 없습니다".into(),
        Msg::NoModule0c => "v24.1 메타데이터에 대한 모듈 0x0C가 없습니다".into(),
        Msg::AmbiguousModule0c => "모호한 모듈 0x0C 바인딩".into(),
        Msg::UnsafePackageEntry { package } => {
            format!("패키지 `{package}`에 안전하지 않은 항목 경로가 있습니다").into()
        }
        Msg::UnsafeNestedEntry { path } => {
            format!("`{path}`에 안전하지 않은 항목 경로가 있습니다").into()
        }
        Msg::EntryStubTargetOutsideCode { branch, target } => format!(
            "엔트리 포인트 {branch} 대상 0x{target:X}이(가) 실행 가능 섹션 외부에 있습니다 (DD8 선택이 잘못되었을 가능성이 높음)"
        )
        .into(),
        Msg::MissingMz => "'MZ' DOS 서명이 누락되었습니다".into(),
        Msg::TruncatedDosHeader => "잘린 DOS 헤더 (e_lfanew 없음)".into(),
        Msg::MissingPeSignature { offset } => {
            format!("0x{offset:X}에 'PE\\0\\0' 서명이 누락되었습니다").into()
        }
        Msg::TruncatedCoffHeader => "잘린 COFF 헤더".into(),
        Msg::TruncatedOptionalHeader => "잘린 선택적 헤더".into(),
        Msg::BadOptionalMagic { magic } => {
            format!("잘못된 선택적 헤더 매직 0x{magic:X}").into()
        }
        Msg::ImplausibleSectionCount { count } => format!("비정상적인 섹션 수 {count}").into(),
        Msg::ZeroSizeOfImage => "SizeOfImage가 0입니다".into(),
        Msg::SectionTablePastEof => "섹션 테이블이 파일 끝을 넘어 확장됩니다".into(),
        Msg::SectionRawPastEof {
            index,
            start,
            end,
            file_len,
        } => format!(
            "섹션 #{index} 원시 데이터 [0x{start:X}..0x{end:X}]이(가) 파일 크기 0x{file_len:X}을(를) 초과합니다"
        )
        .into(),
        Msg::NoBaseRelocations => "네이티브 DLL에 기준 재배치 테이블이 없습니다 (DD[5]가 0임) — 기본 주소가 아닌 위치에 로드될 때 충돌합니다".into(),
        Msg::ZeroEntryPoint => "엔트리 포인트 RVA가 0입니다".into(),
        Msg::EntryUnmapped { rva } => {
            format!("엔트리 포인트 RVA 0x{rva:X}이(가) 어느 섹션에도 매핑되지 않습니다").into()
        }
        Msg::EntryAllZeros { rva } => {
            format!("RVA 0x{rva:X}의 엔트리 포인트가 모두 0입니다 (스텁이 복원되지 않음)").into()
        }
        Msg::EntryAllInt3 { rva } => {
            format!("RVA 0x{rva:X}의 엔트리 포인트가 모두 int3 패딩입니다 (스텁이 복원되지 않음)").into()
        }
        Msg::EntryNotExecutable { rva } => {
            format!("엔트리 포인트 RVA 0x{rva:X}이(가) 실행 가능 섹션에 있지 않습니다").into()
        }
        Msg::ImportDirectoryUnmapped { rva } => {
            format!("임포트 디렉터리 RVA 0x{rva:X}이(가) 어느 섹션에도 매핑되지 않습니다").into()
        }
        Msg::ImportNameUnmapped { index, rva } => format!(
            "임포트 디스크립터 {index}의 DLL 이름 RVA 0x{rva:X}이(가) 어느 섹션에도 매핑되지 않습니다"
        )
        .into(),
        Msg::ImportNameUnreadable { index, rva } => format!(
            "RVA 0x{rva:X}에 있는 임포트 디스크립터 {index}의 DLL 이름이 읽을 수 있는 ASCII가 아닙니다 (임포트가 암호화된 채로 남았습니까?)"
        )
        .into(),
        Msg::ClrDirectoryUnmapped { rva } => {
            format!("CLR (COR20) 디렉터리 RVA 0x{rva:X}이(가) 어느 섹션에도 매핑되지 않습니다").into()
        }
        Msg::ClrHeaderBadSize { rva, size } => format!(
            "RVA 0x{rva:X}의 COR20 헤더 cb가 0x{size:X}입니다 (예상값 0x48) — CLR 헤더가 손상되었습니다"
        )
        .into(),
        Msg::ClrMetadataUnmapped { rva } => {
            format!("CLR MetaData RVA 0x{rva:X}이(가) 어느 섹션에도 매핑되지 않습니다").into()
        }
        Msg::ClrMetadataNoBsjb { rva } => format!(
            "RVA 0x{rva:X}의 CLR MetaData에 'BSJB' 서명이 없습니다 (메타데이터 손상 — 관리되는 이미지가 로드되지 않습니다)"
        )
        .into(),
    }
}

pub(crate) fn step(step: &Step) -> Cow<'static, str> {
    match step {
        Step::DecryptHeader => "파일 헤더 복호화 중...".into(),
        Step::DecryptPayload => "페이로드 복호화 중...".into(),
        Step::LocateConfig => "구성 레이아웃 탐색 중...".into(),
        Step::DecryptStage2 => "stage2 복호화 중...".into(),
        Step::DecryptStages3To5 => "단계 3-5 복호화 중...".into(),
        Step::DecryptSections => "섹션 데이터 복호화 중...".into(),
        Step::DecryptSectionsNewLayout => "섹션 데이터 복호화 중 (새 레이아웃)...".into(),
        Step::LoadSections => "섹션 로드 및 압축 해제 중...".into(),
        Step::DecryptImports => "임포트 문자열 복호화 중...".into(),
        Step::RebuildHeaders => "PE 헤더 재구성 중...".into(),
        Step::Pe32LocateConfig => "구성 레이아웃 탐색 중 (PE32)...".into(),
        Step::Pe32Stages => "단계 복호화 중 (PE32)...".into(),
        Step::Pe32EighthStage => "eighthStage 복호화 중 (PE32)...".into(),
        Step::Pe32Load => "파일 데이터 로드 및 압축 해제 중 (PE32)...".into(),
        Step::Pe32Text { formula } => {
            format!(".text 복호화 중 (PE32 dd8, formula={formula})...").into()
        }
        Step::Pe32TextSkip => ".text dd8 건너뛰는 중 (이미 평문)...".into(),
        Step::Pe32Imports => "임포트 문자열 복호화 중 (PE32)...".into(),
        Step::Pe32Rebuild => "PE 파일 레이아웃 재구성 중 (PE32)...".into(),
        Step::InitKeys => "키 초기화 중...".into(),
        Step::DecryptKeyTable => "키 테이블 복호화 중...".into(),
        Step::DecryptPrimary => "기본 디스크립터 복호화 중...".into(),
        Step::RelocsParams => "재배치 및 압축 해제 매개변수 처리 중...".into(),
        Step::DecryptBlock1 => "코드 블록 1 (addr3) 복호화 중...".into(),
        Step::DecryptBlocks2To3 => "코드 블록 2-3 (addr3b, addr4) 복호화 중...".into(),
        Step::DecryptBlock4 => "코드 블록 4 (addr5) 복호화 중...".into(),
        Step::DllSections => "섹션 복호화 및 압축 해제 중...".into(),
        Step::FixHeaders => "PE 헤더 및 섹션 테이블 보정 중...".into(),
        Step::AndroidPrimary => "기본 0x9D 대상 이미지 컨테이너 디코딩 중...".into(),
        Step::AndroidAuxiliary => "보조 0x9D ELF 구체화 컨테이너 디코딩 중...".into(),
        Step::AndroidTables => "정적 ELF 동적 링커 테이블 재구성 중...".into(),
        Step::WriteTo { dest } => format!("{dest}(으)로 기록").into(),
    }
}

pub(crate) fn term(term: &Term) -> Cow<'static, str> {
    match term {
        Term::Ok => "정상",
        Term::Suspect => "의심됨",
        Term::Recognized => "인식됨",
        Term::NotRecognized => "인식되지 않음",
        Term::Skipped => "건너뜀",
        Term::Error => "오류",
        Term::Restored => "복원됨",
        Term::Duplicate => "중복",
        Term::NotTarget => "비대상",
        Term::Unchanged => "변경 없음",
        Term::Inventoried => "목록화됨",
        Term::Failed => "실패함",
        Term::Blocked => "차단됨",
        Term::NotAttempted => "시도 안 함",
        Term::Succeeded => "성공함",
        Term::Rejected => "거부됨",
        Term::Clean => "정상",
        Term::Warnings => "경고",
        Term::NotRun => "미실행",
        Term::Absent => "없음",
        Term::Spliced => "결합됨",
        Term::Unmatched => "일치하지 않음",
        Term::Unreadable => "읽을 수 없음",
        Term::Detection => "탐지",
        Term::ManifestInventory => "매니페스트 목록화",
        Term::EntryProbe => "항목 프로브",
        Term::Recovery => "복원",
        Term::StaticValidation => "정적 검증",
        Term::OutputWrite => "출력 기록",
        Term::SharedLibrary => "공유 라이브러리",
        Term::Metadata => "메타데이터",
        Term::ExeStyle => "EXE 스타일",
        Term::Dll => "DLL",
        Term::AndroidStaged => "Android 단계별",
        Term::MetadataSeeded => "메타데이터 시드 기반",
        Term::MetadataStructural => "메타데이터 구조적",
        Term::MetadataMethodIndices => "메타데이터 메서드 인덱스",
        Term::WindowsPe => "Windows PE",
        Term::AndroidElf => "Android ELF",
        Term::Il2cppMetadata => "il2cpp 메타데이터",
        Term::NativeExe => "네이티브 EXE",
        Term::ManagedExe => ".NET EXE",
        Term::NativeDll => "네이티브 DLL",
        Term::ManagedDll => ".NET DLL",
        Term::HeaderMagic => "헤더 매직",
        Term::ExternalCompanionDeclaration => "외부 컴패니언 파일 선언",
        Term::CompanionSpliced => "컴패니언 파일 결합됨",
        Term::PrivateSection => "전용 섹션",
        Term::AesSchedule => "AES 키 스케줄",
        Term::ValidatedMetadataTransform => "검증된 메타데이터 변환",
        Term::Known => "알려짐",
        Term::ContextRequired => "애플리케이션 컨텍스트 필요",
        Term::Unverified => "미검증",
        Term::Original => "원본",
        Term::SplicedCompanion => "결합된 컴패니언 파일",
    }
    .into()
}

pub(crate) fn cli(cli: &Cli) -> Cow<'static, str> {
    match cli {
        Cli::Error => "오류".into(),
        Cli::Warning => "경고".into(),
        Cli::DoneIn { ms } => format!("{ms} ms 만에 완료").into(),
        Cli::PressEnter => "\n종료하려면 Enter 키를 누르십시오…".into(),
        Cli::ScanUnreadable { count } => {
            format!("스캔 중 {count}개의 파일을 읽을 수 없어 대상이 누락되었을 수 있습니다").into()
        }
        Cli::Summary {
            unpacked,
            skipped,
            errors,
            suspect,
            metadata,
        } => format!(
            "언패킹 {unpacked} · 건너뜀 {skipped} · 오류 {errors} · 의심됨 {suspect} · 메타데이터 {metadata}"
        )
        .into(),
        Cli::SummaryPackages { packages } => format!(" · 패키지 {packages}").into(),
        Cli::IntegrityFailed => "무결성 검사 실패".into(),
        Cli::IntegrityFailedLikelyCrash => "! 무결성 검사 실패 (런타임에 충돌할 가능성이 높음)".into(),
        Cli::MetadataLine {
            rel,
            dest,
            remapped,
        } => format!("메타데이터  {rel}  ->  {dest}  (재매핑된 메서드 필드: {remapped})").into(),
        Cli::MetadataVersionLine {
            version,
            dest,
            remapped,
        } => format!("메타데이터 v{version} -> {dest} (재매핑된 메서드 필드: {remapped})").into(),
        Cli::MetadataAlreadyClean { version } => format!("메타데이터 v{version}:").into(),
        Cli::MetadataNothingToDo => "이미 난독화 해제됨, 수행할 작업 없음".into(),
        Cli::EmbeddedMetadataLine { input, dest } => {
            format!("메타데이터  {input} (내장됨)  ->  {dest}").into()
        }
        Cli::EmbeddedMetadataFailed => "내장 메타데이터".into(),
        Cli::MetadataUnsupportedLine { version } => {
            format!("지원되지 않는 메타데이터 버전 {version}, 변경하지 않고 유지함").into()
        }
        Cli::OutRequiresDirectory => "--out에는 디렉터리 인수가 필요합니다".into(),
        Cli::UnknownOption { option } => format!("알 수 없는 옵션 '{option}'").into(),
        Cli::MultipleInputs { first, second } => {
            format!("여러 입력 경로가 지정되었습니다 ('{first}' 및 '{second}')").into()
        }
        Cli::SubcommandNeedsPath { subcommand } => {
            format!("'{subcommand}'에는 입력 경로가 필요합니다").into()
        }
        Cli::InspectNoDryRun => {
            "'inspect'는 아무것도 기록하지 않습니다. --dry-run을 제거하십시오".into()
        }
        Cli::InspectNoOut => {
            "'inspect'는 아무것도 기록하지 않습니다. --out은 허용되지 않습니다".into()
        }
        Cli::DryRunNoOut => "--dry-run은 출력을 기록하지 않습니다. --out은 허용되지 않습니다".into(),
        Cli::ColorRequiresMode => "--color에는 auto, always 또는 never가 필요합니다".into(),
        Cli::ThreadsRequiresInteger => "--threads에는 양의 정수 인수가 필요합니다".into(),
        Cli::LimitRequiresInteger { flag } => {
            format!("{flag}에는 부호 없는 정수 인수가 필요합니다").into()
        }
        Cli::LimitMustBePositive { flag } => format!("{flag}은(는) 0보다 커야 합니다").into(),
        Cli::LimitTooLarge { flag } => {
            format!("{flag}이(가) 지원되는 바이트 범위를 초과합니다").into()
        }
        Cli::UnknownLimit { flag } => format!("알 수 없는 리소스 옵션 '{flag}'").into(),
        Cli::HelpPath => "  <file|folder>\n\
             \x20              CrackProof PE (.exe/.dll), il2cpp global-metadata.dat, 보호된\n\
             \x20              Android AArch64 라이브러리 (.so), Android 앱 패키지\n\
             \x20              (.apk/.apks/.xapk) 또는 이를 포함하는 폴더입니다. 하위 명령을\n\
             \x20              생략하면 'unpack'과 동일합니다."
            .into(),
        Cli::HelpInspect => "  inspect PATH\n\
             \x20              연구를 위해 실제 정적 복원을 실행하고 관측된 모든 내용을\n\
             \x20              보고합니다: 인식 근거, 시도된 각 경로와 거부 이유, 선택된\n\
             \x20              경로, 정적 검사 판정, 엔진 자체의 구조적 근거 (보호 헤더\n\
             \x20              필드, 시드, 모듈 레코드, 복원된 이미지 정보). 출력 파일,\n\
             \x20              로그, 임시 트리는 일절 유지되지 않으며 입력은 절대 실행되지\n\
             \x20              않습니다."
            .into(),
        Cli::HelpUnpack => "  unpack PATH  탐지 및 복원을 수행하고 출력을 기록합니다 (기본값).".into(),
        Cli::HelpJson => "  --json       버전이 지정된 기계 판독 가능 보고서 하나를 stdout에 기록하고\n\
             \x20              다른 내용은 출력하지 않습니다. quiet 및 --no-log를 암시합니다."
            .into(),
        Cli::HelpDryRun => "  --dry-run    실제 복원을 실행하되 출력 트리와 로그를 일절 유지하지\n\
             \x20              않습니다. Android 추출은 여전히 자체 임시 작업 공간을\n\
             \x20              사용하며 작업 후 폐기됩니다."
            .into(),
        Cli::HelpThreads => "  --threads N  이번 실행의 양수 작업자 스레드 상한입니다. SENBEI_THREADS보다\n\
             \x20              우선하며, 1은 순차 경로를 선택합니다. 환경 변수는 변경되지\n\
             \x20              않습니다."
            .into(),
        Cli::HelpColor => "  --color MODE auto (기본값), always 또는 never. --color=MODE도 작동합니다.\n\
             \x20              auto는 NO_COLOR가 비어 있지 않거나 TERM=dumb가 아닌 한 터미널\n\
             \x20              stdout/stderr에 개별적으로 색상을 적용합니다. 명시적\n\
             \x20              always/never는 이 변수들보다 우선합니다. JSON 및 저장된 로그는\n\
             \x20              일반 텍스트로 유지됩니다."
            .into(),
        Cli::HelpScanAll => "  --scan-all   최소 크기 기준 미만인 지정된 .exe/.dll/.so/메타데이터 이름을\n\
             \x20              프로브합니다. 다른 파일 이름은 계속 제외됩니다."
            .into(),
        Cli::HelpStrictIntegrity => "  --strict-integrity\n\
             \x20              출력이 정적 무결성 검사에 실패하거나 (의심됨) 파일에 오류가\n\
             \x20              발생하면 0이 아닌 코드로 종료합니다. 기본값은 해제 상태이며,\n\
             \x20              의심됨 항목도 파일로 기록되고 파일 오류가 없는 한 프로세스는\n\
             \x20              0으로 종료합니다. quiet 수준은 변경되지 않습니다.\n\
             \x20              'inspect'와 함께 사용하면 연구를 위해 실제로 복원된 이미지에\n\
             \x20              검사가 적용되며 출력 파일은 유지되지 않습니다."
            .into(),
        Cli::HelpLimits {
            entry_mib,
            total_mib,
            entries,
            depth,
        } => format!(
            "  Android 리소스 제한 (MiB = 1048576바이트):\n\
             \x20 --max-entry-mib N  단일 아카이브 항목/디코딩된 버퍼/출력 (기본값 {entry_mib})\n\
             \x20 --max-total-mib N  누적 아카이브 바이트 및 엔진당 작업 한도 (기본값 {total_mib})\n\
             \x20 --max-entries N    아카이브 항목/단계 2 레코드 (기본값 {entries})\n\
             \x20 --max-depth N      중첩 깊이, 루트 = 0 (기본값 {depth})\n\
             \x20 제한은 추출/할당 전에 확인되며 최대 RSS 상한선이 아닙니다."
        )
        .into(),
        Cli::HelpLanguage => "  SENBEI_LANG  표시 언어: en, zh-CN, zh-TW, ja 또는 ko. 설정하지 않으면\n\
             \x20              시스템 언어를 사용합니다. JSON 및 저장된 로그는 영어로\n\
             \x20              유지됩니다."
            .into(),
        Cli::HelpExitCodes => "  종료 코드: 0 성공, 1 대상 실패 (--strict-integrity 사용 시 의심됨 포함),\n\
             \x20 2 명령줄이 거부됨."
            .into(),
        Cli::ReportScanHeading => "스캔".into(),
        Cli::ReportScan {
            skipped,
            walk_errors,
            probe_errors,
        } => format!("프로브한 비대상 {skipped} · 탐색 오류 {walk_errors} · 프로브 오류 {probe_errors}").into(),
        Cli::ReportScanIncomplete => {
            "분석이 불완전합니다: 일부 디렉터리 항목 또는 선택한 파일을 조사할 수 없었습니다".into()
        }
        Cli::AnalysisIncomplete => "분석 미완료".into(),
        Cli::AnalysisIncompleteInput => {
            "I/O, 리소스 제한 또는 인프라 문제로 인해 요청된 작업을 수행하지 못했습니다".into()
        }
        Cli::AnalysisIncompleteEntry => "요청된 항목 분석을 완료할 수 없었습니다".into(),
        Cli::Source { size } => format!("소스: {size}바이트 (0x{size:X})").into(),
        Cli::Target {
            platform,
            format,
            kind,
        } => format!("대상: {platform} · {format} · {kind}").into(),
        Cli::FormatUnavailable => "형식 사용 불가".into(),
        Cli::KindUnavailable => "종류 해당 없음 또는 사용 불가".into(),
        Cli::ProtectionRecognition { status } => format!("보호 인식: {status}").into(),
        Cli::Evidence { evidence } => format!("근거: {evidence}").into(),
        Cli::Route { route, outcome } => format!("경로 {route}: {outcome}").into(),
        Cli::SelectedRoute { route } => format!("선택된 경로: {route}").into(),
        Cli::StaticRecovery { status } => format!("정적 복원: {status}").into(),
        Cli::OutputValidation { status } => format!("출력 정적 검증: {status}").into(),
        Cli::Companion { state } => format!("컴패니언 파일: {state}").into(),
        Cli::CompanionIdentity { size, sha256 } => {
            format!("{size}바이트 · SHA-256 {sha256}").into()
        }
        Cli::InputView { view } => format!("분석 입력 보기: {view}").into(),
        Cli::InputViewSplicedNote => "0x1000 미만의 파일 오프셋은 스텁을 가리키며, 0x1000 이상의 오프셋은 컴패니언 파일 오프셋 (파일 오프셋 - 0x1000)을 가리킵니다".into(),
        Cli::MetadataIdentity { version, layout } => {
            format!("IL2CPP 메타데이터 버전: {version} · 레이아웃 정의 {layout}").into()
        }
        Cli::SeededTokens { value } => format!("시드 기반 메서드 토큰: {}", yes_no(*value)).into(),
        Cli::StructuralTokens { value } => format!("구조적 메서드 토큰: {}", yes_no(*value)).into(),
        Cli::MethodIndexRestore { value, context } => format!(
            "메서드 인덱스 복원: {} · 애플리케이션 컨텍스트 필요: {}",
            yes_no(*value),
            yes_no(*context)
        )
        .into(),
        Cli::Container {
            kind,
            entries,
            manifests,
        } => format!("컨테이너: {kind} · 항목 {entries} · 매니페스트 {manifests}").into(),
        Cli::Manifest {
            source,
            package,
            version,
        } => format!("매니페스트 {source} → {package} {version}").into(),
        Cli::Unnamed => "<unnamed>".into(),
        Cli::Candidate { entry } => format!("후보: {entry}").into(),
        Cli::MetadataEvidence => "메타데이터 변환 근거".into(),
        Cli::Entry { name, status } => format!("항목 {name}: {status}").into(),
        Cli::EntryRoute { route } => format!("경로: {route}").into(),
        Cli::EntryMetadataVersion { version } => format!("메타데이터 버전: {version}").into(),
        Cli::EntryRemapped { remapped } => format!("재매핑된 메서드 필드: {remapped}").into(),
        Cli::ModuleContextSource { source } => format!("모듈 컨텍스트 출처: {source}").into(),
        Cli::StageLine { stage, status } => format!("단계 {stage}: {status}").into(),
        Cli::Recovered { size, sha256 } => {
            format!("복원됨: {size}바이트 · SHA-256 {sha256}").into()
        }
        Cli::InspectionStatus { status, ms } => format!("검사 상태: {status} · {ms} ms").into(),
        Cli::DiagnosticWarning => "경고".into(),
        Cli::DiagnosticError => "오류".into(),
        Cli::DiagnosticReason => "원인".into(),
        Cli::DiagnosticDetail => "세부 정보".into(),
        Cli::DiagnosticEnglish => "영어 원문".into(),
    }
}

/// A capability flag as a word of this language.
fn yes_no(value: bool) -> &'static str {
    if value { "예" } else { "아니요" }
}
