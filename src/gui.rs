use eframe::egui;
use std::os::fd::FromRawFd;
use std::sync::OnceLock;

fn capture_stdout<F>(f: F) -> Vec<String>
where
    F: FnOnce(),
{
    unsafe {
        let orig = libc::dup(1);
        let mut pipe = [0i32; 2];
        libc::pipe(pipe.as_mut_ptr());
        libc::dup2(pipe[1], 1);
        libc::close(pipe[1]);

        let reader = std::thread::spawn(move || {
            use std::io::BufRead;
            let file = std::fs::File::from_raw_fd(pipe[0]);
            std::io::BufReader::new(file)
                .lines()
                .filter_map(|l| l.ok())
                .collect::<Vec<_>>()
        });

        f();

        libc::dup2(orig, 1);
        libc::close(orig);
        reader.join().unwrap_or_default()
    }
}

struct Theme {
    bg: egui::Color32,
    bg2: egui::Color32,
    border: egui::Color32,
    fg: egui::Color32,
    accent: egui::Color32,
    muted: egui::Color32,
    ok: egui::Color32,
    err: egui::Color32,
}

static THEME: OnceLock<Theme> = OnceLock::new();

fn theme() -> &'static Theme {
    THEME.get().unwrap()
}

impl Theme {
    fn from_settings(s: &ps4save_rs::settings::Settings) -> Self {
        Self {
            bg: egui::Color32::from_rgb(s.bg[0], s.bg[1], s.bg[2]),
            bg2: egui::Color32::from_rgb(s.bg2[0], s.bg2[1], s.bg2[2]),
            border: egui::Color32::from_rgb(s.border[0], s.border[1], s.border[2]),
            fg: egui::Color32::from_rgb(s.fg[0], s.fg[1], s.fg[2]),
            accent: egui::Color32::from_rgb(s.accent[0], s.accent[1], s.accent[2]),
            muted: egui::Color32::from_rgb(s.muted[0], s.muted[1], s.muted[2]),
            ok: egui::Color32::from_rgb(s.ok[0], s.ok[1], s.ok[2]),
            err: egui::Color32::from_rgb(s.err[0], s.err[1], s.err[2]),
        }
    }
}

fn ansi_to_layout(text: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mono = egui::FontId::monospace(13.0);
    let default_color = theme().fg;

    let mut current_color = default_color;
    let mut chars = text.chars().peekable();
    let mut segment = String::new();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Flush current segment
            if !segment.is_empty() {
                let fmt = egui::TextFormat::simple(mono.clone(), current_color);
                job.append(&segment, 0.0, fmt);
                segment.clear();
            }
            // Parse ANSI escape sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // skip '['
                let mut params = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_alphabetic() {
                        chars.next();
                        break;
                    }
                    params.push(ch);
                    chars.next();
                }
                // Apply SGR parameters
                for param in params.split(';') {
                    match param.parse::<u8>() {
                        Ok(0) => {
                            current_color = default_color;
                        }
                        Ok(32) => current_color = egui::Color32::from_rgb(74, 222, 128),  // green
                        Ok(33) => current_color = egui::Color32::from_rgb(250, 222, 108), // yellow
                        Ok(34) => current_color = egui::Color32::from_rgb(90, 140, 250),  // blue
                        Ok(35) => current_color = egui::Color32::from_rgb(220, 130, 250), // magenta
                        Ok(31) => current_color = egui::Color32::from_rgb(248, 113, 113), // red
                        Ok(36) => current_color = egui::Color32::from_rgb(108, 220, 230), // cyan
                        _ => {}
                    }
                }
            }
        } else {
            segment.push(c);
        }
    }
    // Flush remaining
    if !segment.is_empty() {
        let fmt = egui::TextFormat::simple(mono, current_color);
        job.append(&segment, 0.0, fmt);
    }
    job
}

pub fn run() -> eframe::Result {
    let settings = ps4save_rs::settings::Settings::load();
    THEME.set(Theme::from_settings(&settings)).ok();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 600.0])
            .with_title("PS4 Save Tool"),
        ..Default::default()
    };
    eframe::run_native(
        "PS4 Save Tool",
        options,
        Box::new(|cc| {
            setup_theme(&cc.egui_ctx, settings.zoom);
            Ok(Box::new(App::new(&settings)))
        }),
    )
}

fn setup_theme(ctx: &egui::Context, zoom: f32) {
    let mut visuals = egui::Visuals::dark();
    visuals.dark_mode = true;
    visuals.override_text_color = Some(theme().fg);
    visuals.window_corner_radius = egui::CornerRadius::ZERO;
    visuals.panel_fill = theme().bg;
    visuals.window_fill = theme().bg2;
    visuals.widgets.noninteractive.bg_fill = theme().bg2;
    visuals.widgets.noninteractive.weak_bg_fill = theme().bg2;
    visuals.widgets.inactive.bg_fill = theme().bg2;
    visuals.widgets.inactive.weak_bg_fill = theme().bg2;
    visuals.widgets.hovered.bg_fill = theme().border;
    visuals.widgets.hovered.weak_bg_fill = theme().border;
    visuals.widgets.active.bg_fill = theme().accent;
    visuals.widgets.active.weak_bg_fill = theme().accent;
    visuals.selection.bg_fill = theme().accent;
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, theme().bg);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::ZERO;
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::ZERO;
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::ZERO;
    visuals.widgets.active.corner_radius = egui::CornerRadius::ZERO;
    visuals.window_corner_radius = egui::CornerRadius::ZERO;
    let style = egui::Style {
        spacing: egui::style::Spacing {
            item_spacing: egui::vec2(3.0, 2.0),
            window_margin: egui::Margin::same(4),
            ..Default::default()
        },
        ..Default::default()
    };
    ctx.set_style(style);
    ctx.set_visuals(visuals);
    if zoom != 1.0 {
        ctx.set_pixels_per_point(zoom);
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Resign,
    Decrypt,
    Encrypt,
    Reregion,
    Inspect,
}

impl Tab {
    fn all() -> &'static [Tab] {
        &[Tab::Decrypt, Tab::Encrypt, Tab::Resign, Tab::Reregion, Tab::Inspect]
    }

    fn label(self) -> &'static str {
        match self {
            Tab::Resign => "Resign",
            Tab::Decrypt => "Decrypt",
            Tab::Encrypt => "Encrypt",
            Tab::Reregion => "Reregion",
            Tab::Inspect => "Inspect",
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum StatusKind {
    Ok,
    Err,
    Loading,
}

struct App {
    active_tab: Tab,
    config_path: String,
    input_path: String,
    output_path: String,
    sample_path: String,
    account_id: String,
    inspect_text: String,
    progress: Vec<String>,
    status: Option<(StatusKind, String)>,
    working: bool,

}

impl App {
    fn new(settings: &ps4save_rs::settings::Settings) -> Self {
        Self {
            active_tab: Tab::Decrypt,
            config_path: settings.config_path.clone(),
            input_path: settings.save_path.clone(),
            output_path: settings.output_path.clone(),
            sample_path: settings.sample_path.clone(),
            account_id: settings.account_id.clone(),
            inspect_text: String::new(),
            progress: Vec::new(),
            status: None,
            working: false,
        }
    }

    fn do_resign(&mut self, ctx: &egui::Context) {
        if self.input_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select a save first".into()));
            return;
        }
        self.working = true;
        self.status = Some((StatusKind::Loading, "Resigning...".into()));
        self.progress.clear();
        ctx.request_repaint();
        let input = self.input_path.clone();
        let output = self.output_path.clone();
        let account_id = self.account_id.clone();
        let config_path = self.config_path.clone();
        let result = std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<String>, String> {
                let out_opt = if output.is_empty() { None } else { Some(output.as_str()) };
                let lines = capture_stdout(|| {
                    let _ = ps4save_rs::commands::run_resign(&config_path, &input, &account_id, out_opt, false);
                });
                if lines.iter().any(|l| l.contains("error")) {
                    Err(lines.join("\n"))
                } else {
                    Ok(lines)
                }
            }).join().unwrap()
        });
        self.working = false;
        match result {
            Ok(lines) => {
                self.progress = lines;
                self.status = Some((StatusKind::Ok, "resigned".into()));
            }
            Err(msg) => self.status = Some((StatusKind::Err, msg)),
        }
    }

    fn do_decrypt(&mut self, ctx: &egui::Context) {
        if self.input_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select a save first".into()));
            return;
        }
        self.working = true;
        self.status = Some((StatusKind::Loading, "Decrypting...".into()));
        self.progress.clear();
        ctx.request_repaint();
        let input = self.input_path.clone();
        let output = self.output_path.clone();
        let config_path = self.config_path.clone();
        let result = std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<String>, String> {
                let out_opt = if output.is_empty() { None } else { Some(output.as_str()) };
                let lines = capture_stdout(|| {
                    let _ = ps4save_rs::commands::run_decrypt(&config_path, &input, out_opt);
                });
                if lines.iter().any(|l| l.contains("error")) {
                    Err(lines.join("\n"))
                } else {
                    Ok(lines)
                }
            }).join().unwrap()
        });
        self.working = false;
        match result {
            Ok(lines) => {
                self.progress = lines;
                self.status = Some((StatusKind::Ok, "decrypted".into()));
            }
            Err(msg) => self.status = Some((StatusKind::Err, msg)),
        }
    }

    fn do_encrypt(&mut self, ctx: &egui::Context) {
        if self.input_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select a decrypted folder".into()));
            return;
        }
        self.working = true;
        self.status = Some((StatusKind::Loading, "Encrypting...".into()));
        self.progress.clear();
        ctx.request_repaint();
        let input = self.input_path.clone();
        let output = self.output_path.clone();
        let config_path = self.config_path.clone();
        let result = std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<String>, String> {
                let out_opt = if output.is_empty() { None } else { Some(output.as_str()) };
                let lines = capture_stdout(|| {
                    let _ = ps4save_rs::commands::run_encrypt(&config_path, &input, out_opt, None, None, None, false);
                });
                if lines.iter().any(|l| l.contains("error")) {
                    Err(lines.join("\n"))
                } else {
                    Ok(lines)
                }
            }).join().unwrap()
        });
        self.working = false;
        match result {
            Ok(lines) => {
                self.progress = lines;
                self.status = Some((StatusKind::Ok, "encrypted".into()));
            }
            Err(msg) => self.status = Some((StatusKind::Err, msg)),
        }
    }

    fn do_reregion(&mut self, ctx: &egui::Context) {
        if self.input_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select the source save".into()));
            return;
        }
        if self.sample_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select the target region sample save".into()));
            return;
        }
        self.working = true;
        self.status = Some((StatusKind::Loading, "Reregioning...".into()));
        self.progress.clear();
        ctx.request_repaint();
        let input = self.input_path.clone();
        let sample = self.sample_path.clone();
        let output = self.output_path.clone();
        let account_id = self.account_id.clone();
        let config_path = self.config_path.clone();
        let result = std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<String>, String> {
                let out_opt = if output.is_empty() { None } else { Some(output.as_str()) };
                let acc_opt = if account_id.is_empty() { None } else { Some(account_id.as_str()) };
                let lines = capture_stdout(|| {
                    let _ = ps4save_rs::commands::reregion_from_paths(
                        &config_path,
                        &input,
                        &sample,
                        acc_opt,
                        out_opt,
                        false,
                    );
                });
                if lines.iter().any(|l| l.contains("error")) {
                    Err(lines.join("\n"))
                } else {
                    Ok(lines)
                }
            }).join().unwrap()
        });
        self.working = false;
        match result {
            Ok(lines) => {
                self.progress = lines;
                self.status = Some((StatusKind::Ok, "reregioned".into()));
            }
            Err(msg) => self.status = Some((StatusKind::Err, msg)),
        }
    }

    fn do_inspect(&mut self, ctx: &egui::Context) {
        if self.input_path.is_empty() {
            self.status = Some((StatusKind::Err, "Drop or select a save first".into()));
            return;
        }
        self.working = true;
        self.status = Some((StatusKind::Loading, "Inspecting...".into()));
        self.inspect_text.clear();
        ctx.request_repaint();

        let save = self.input_path.clone();
        let config_path = self.config_path.clone();
        let result = std::thread::scope(|s| {
            s.spawn(|| -> Result<String, String> {
                ps4save_rs::commands::inspect_to_string_from_path(&config_path, &save).map_err(err_str)
            }).join().unwrap()
        });

        self.working = false;
        match result {
            Ok(text) => {
                self.inspect_text = text;
                self.status = None;
            }
            Err(msg) => {
                self.status = Some((StatusKind::Err, msg));
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(path) = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone())) {
            self.input_path = path.display().to_string();
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for tab in Tab::all() {
                    let is_active = self.active_tab == *tab;
                    if ui.selectable_label(is_active, egui::RichText::new(tab.label()).strong()).clicked() {
                        self.active_tab = *tab;
                        self.status = None;
                        self.progress.clear();
                        self.inspect_text.clear();
                    }
                }
            });
        });

        if let Some((kind, msg)) = &self.status {
            let (bg, border, text_color) = match kind {
                StatusKind::Ok => (theme().bg2, theme().ok, theme().ok),
                StatusKind::Err => (theme().bg2, theme().err, theme().err),
                StatusKind::Loading => (theme().bg2, theme().accent, theme().accent),
            };
            egui::TopBottomPanel::bottom("status").exact_height(22.0).frame(
                egui::Frame::new().fill(bg).stroke(egui::Stroke::new(1.0_f32, border)).inner_margin(egui::Margin::same(4)),
            ).show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(msg.as_str())
                        .color(text_color)
                        .monospace()
                        .size(10.0),
                );
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {

            // Input row
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("In").color(theme().muted).size(11.0));
                ui.add(egui::TextEdit::singleline(&mut self.input_path)
                    .desired_width(ui.available_width() - 48.0)
                    .hint_text("save path..."));
                if ui.small_button("...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.input_path = path.display().to_string();
                    }
                }
            });

            // Sample row (only on Reregion tab)
            if self.active_tab == Tab::Reregion {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Sample").color(theme().muted).size(11.0));
                    ui.add(egui::TextEdit::singleline(&mut self.sample_path)
                        .desired_width(ui.available_width() - 48.0)
                        .hint_text("target region save..."));
                    if ui.small_button("...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.sample_path = path.display().to_string();
                        }
                    }
                });
            }

            // Output row (hidden on Inspect tab)
            if self.active_tab != Tab::Inspect {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Out").color(theme().muted).size(11.0));
                    ui.add(egui::TextEdit::singleline(&mut self.output_path)
                        .desired_width(ui.available_width() - 48.0)
                        .hint_text("auto"));
                    if ui.small_button("...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.output_path = path.display().to_string();
                        }
                    }
                });
            }

            ui.separator();

            match self.active_tab {
                Tab::Resign => {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Acct ID").color(theme().muted).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.account_id)
                            .desired_width(120.0)
                            .hint_text("0000000000000000"));
                    });
                    if ui.add_enabled(!self.working,
                        egui::Button::new(egui::RichText::new("Resign").size(11.0))
                            .fill(theme().accent),
                    ).clicked() {
                        self.do_resign(ctx);
                    }
                }
                Tab::Decrypt => {
                    if ui.add_enabled(!self.working,
                        egui::Button::new(egui::RichText::new("Decrypt").size(11.0))
                            .fill(theme().accent),
                    ).clicked() {
                        self.do_decrypt(ctx);
                    }
                }
                Tab::Encrypt => {
                    if ui.add_enabled(!self.working,
                        egui::Button::new(egui::RichText::new("Encrypt").size(11.0))
                            .fill(theme().accent),
                    ).clicked() {
                        self.do_encrypt(ctx);
                    }
                }
                Tab::Reregion => {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Acct ID").color(theme().muted).size(11.0));
                        ui.add(egui::TextEdit::singleline(&mut self.account_id)
                            .desired_width(120.0)
                            .hint_text("0000000000000000"));
                    });
                    if ui.add_enabled(!self.working,
                        egui::Button::new(egui::RichText::new("Reregion").size(11.0))
                            .fill(theme().accent),
                    ).clicked() {
                        self.do_reregion(ctx);
                    }
                }
                Tab::Inspect => {
                    if ui.add_enabled(!self.working,
                        egui::Button::new(egui::RichText::new("Inspect").size(11.0))
                            .fill(theme().accent),
                    ).clicked() {
                        self.do_inspect(ctx);
                    }
                }
            }

            // Output area — fills remaining space
            ui.add_space(2.0);
            let remaining = ui.available_height();
            if remaining > 0.0 {
                if self.inspect_text.is_empty() && self.progress.is_empty() {
                } else {
                    egui::ScrollArea::both()
                        .max_height(remaining)
                        .auto_shrink(false)
                        .show(ui, |ui| {
                            if !self.inspect_text.is_empty() {
                                let layout = ansi_to_layout(&self.inspect_text);
                                ui.add(egui::Label::new(layout).wrap_mode(egui::TextWrapMode::Extend));
                            } else {
                                let progress_text = self.progress.join("\n");
                                ui.label(
                                    egui::RichText::new(progress_text)
                                        .monospace()
                                        .size(11.0)
                                        .color(theme().muted),
                                );
                            }
                            ui.add_space(20.0);
                        });
                }
            }
        });
    }
}

fn err_str(e: ps4save_rs::Error) -> String {
    e.to_string()
}
