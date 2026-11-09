//! The Senbei desktop window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    native::run()
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::sync::Arc;

    use senbei_gui::Workbench;
    use senbei_gui::native::{NativeBackend, SystemFonts, debug_variables};
    use senbei_gui::settings::Settings;

    const SETTINGS_KEY: &str = "settings";
    const ICON_256: &[u8] = include_bytes!("../assets/icon-256.png");
    const ICON_64: &[u8] = include_bytes!("../assets/icon-64.png");

    /// An RGBA image from an embedded PNG.
    fn decode(png_bytes: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
        let mut decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
        decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::ALPHA);
        let mut reader = decoder.read_info().ok()?;
        let mut buffer = vec![0; reader.output_buffer_size()?];
        let info = reader.next_frame(&mut buffer).ok()?;
        if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
            return None;
        }
        buffer.truncate(info.buffer_size());
        Some((buffer, info.width, info.height))
    }

    struct App {
        workbench: Workbench,
    }

    impl eframe::App for App {
        fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.workbench.logic(ctx);
        }

        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            self.workbench.ui(ui);
        }

        fn save(&mut self, storage: &mut dyn eframe::Storage) {
            eframe::set_value(storage, SETTINGS_KEY, &self.workbench.settings);
        }
    }

    pub fn run() -> eframe::Result {
        let detected = senbei_io::locale::detect();
        let window_icon = decode(ICON_256).map(|(rgba, width, height)| egui::IconData {
            rgba,
            width,
            height,
        });
        let mut viewport = egui::ViewportBuilder::default()
            .with_title("Senbei")
            .with_app_id("senbei")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 600.0])
            .with_drag_and_drop(true);
        if let Some(icon) = window_icon {
            viewport = viewport.with_icon(Arc::new(icon));
        }
        let options = eframe::NativeOptions {
            viewport,
            // The window loads the display language's system fonts itself.
            system_font_fallback: false,
            ..Default::default()
        };
        eframe::run_native(
            "Senbei",
            options,
            Box::new(move |cc| {
                let settings: Settings = cc
                    .storage
                    .and_then(|storage| eframe::get_value(storage, SETTINGS_KEY))
                    .unwrap_or_default();
                let lang = settings.lang(detected);
                cc.egui_ctx.add_font_provider(Arc::new(
                    egui_system_font_provider::SystemFontProvider::new()
                        .with_locale(Some(lang.tag())),
                ));
                let mut fonts = SystemFonts::new();
                let icon = decode(ICON_64).map(|(rgba, width, height)| {
                    egui::ColorImage::from_rgba_unmultiplied(
                        [width as usize, height as usize],
                        &rgba,
                    )
                });
                let workbench = Workbench::new(
                    Box::new(NativeBackend::new(cc.egui_ctx.clone())),
                    settings,
                    detected,
                    Some(Box::new(move |lang| fonts.set_for(lang))),
                    debug_variables(),
                    icon,
                );
                Ok(Box::new(App { workbench }))
            }),
        )
    }
}
