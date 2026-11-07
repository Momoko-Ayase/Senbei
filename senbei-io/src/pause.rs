pub fn should_pause() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::GetConsoleProcessList;
        let mut buf = [0u32; 4];
        let n = unsafe { GetConsoleProcessList(&mut buf) };
        n == 1
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn maybe_pause(force_skip: bool) {
    if force_skip || !should_pause() {
        return;
    }
    use senbei_i18n::Localize;
    use std::io::Write;
    eprint!(
        "{}",
        senbei_i18n::Cli::PressEnter.localize(senbei_i18n::current())
    );
    let _ = std::io::stderr().flush();
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}
