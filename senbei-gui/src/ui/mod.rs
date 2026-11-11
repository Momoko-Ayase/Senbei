//! The workbench window: inputs on the left, the selected input on the right.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use egui::{Context, Frame, Margin, Panel, Ui};
use senbei_i18n::{Lang, Message, Step};
use senbei_io::report::{CompanionState, InputReport, Mode, Report, StageStatus};

use crate::backend::{
    Backend, Capabilities, Event, GroupId, ItemId, Job, JobId, Output, Pick, Produced, Request,
    Source, Unit,
};
use crate::model::{
    Counts, Filter, Group, GroupKind, GroupRun, Item, ItemResult, Level, LogBody, LogLine,
    RunState, Sel, Verdict, is_target_entry,
};
use crate::settings::Settings;
use crate::theme::{self, FontSet, Tone};

mod compare;
mod detail;
mod dialogs;
mod hex;
mod inputs;
mod logview;
mod research;
mod table;
mod widgets;

// ------------------------------------------------------------------ state

/// Every added input, grouped as it was added.
#[derive(Default)]
pub struct Session {
    pub groups: Vec<Group>,
    next_id: u64,
}

impl Session {
    fn next(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    pub fn group(&self, id: GroupId) -> Option<&Group> {
        self.groups.iter().find(|group| group.id == id)
    }

    fn group_mut(&mut self, id: GroupId) -> Option<&mut Group> {
        self.groups.iter_mut().find(|group| group.id == id)
    }

    pub fn item(&self, id: ItemId) -> Option<(&Group, &Item)> {
        self.groups.iter().find_map(|group| {
            group
                .items
                .iter()
                .find(|item| item.id == id)
                .map(|item| (group, item))
        })
    }

    fn item_mut(&mut self, id: ItemId) -> Option<&mut Item> {
        self.groups
            .iter_mut()
            .flat_map(|group| group.items.iter_mut())
            .find(|item| item.id == id)
    }

    fn items(&self) -> impl Iterator<Item = &Item> {
        self.groups.iter().flat_map(|group| group.items.iter())
    }

    fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// The detail pane's tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Research,
    Hex,
    Compare,
    Log,
    Entries,
}

/// Which bytes the hex view shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HexView {
    #[default]
    Original,
    Spliced,
    Restored,
}

#[derive(Debug, Clone, Default)]
pub struct HexState {
    pub view: Option<HexView>,
    pub focus: Option<u64>,
    pub highlight: Option<(u64, u64)>,
    pub goto: String,
    pub goto_rva: bool,
    pub find: String,
    pub note: Option<String>,
    /// Scroll the focus into view on the next frame.
    pub reveal: bool,
    /// The first row on screen.
    pub top: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFilter {
    #[default]
    All,
    NoSteps,
    Problems,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    General,
    Processing,
    Android,
    Memory,
    About,
}

/// What the window shows, apart from the session itself.
#[derive(Default)]
pub struct ViewState {
    pub selected: Option<Sel>,
    pub multi: Vec<Sel>,
    pub filter: Filter,
    pub search: String,
    pub tab: Tab,
    pub research_section: Option<String>,
    pub hex: HexState,
    pub compare_section: Option<String>,
    pub compare_diff: Option<usize>,
    pub log_filter: LogFilter,
    pub show_non_targets: bool,
    pub settings_open: bool,
    pub settings_tab: SettingsTab,
    pub legal_open: bool,
    pub close_confirm: bool,
}

impl ViewState {
    fn select(&mut self, sel: Sel) {
        if self.selected != Some(sel) {
            self.hex = HexState::default();
            self.research_section = None;
            self.compare_diff = None;
        }
        self.selected = Some(sel);
    }
}

/// The job that is running and the jobs waiting behind it.
#[derive(Default)]
pub struct Jobs {
    pub running: Option<RunningJob>,
    pub queued: VecDeque<JobPlan>,
    next_id: JobId,
}

#[derive(Debug, Clone)]
pub struct JobPlan {
    pub id: JobId,
    pub mode: Mode,
    pub units: Vec<UnitPlan>,
}

#[derive(Debug, Clone)]
pub struct UnitPlan {
    pub group: GroupId,
    pub items: Vec<ItemId>,
    pub folder: bool,
}

pub struct RunningJob {
    pub plan: JobPlan,
    pub total: usize,
    pub done: usize,
    pub current: Option<ItemId>,
    pub step: Option<(Option<(u8, u8)>, Step)>,
    pub input_started: Instant,
    pub cancel_requested: bool,
    /// Lines of the input being processed.
    pub live: Vec<LogLine>,
    /// Bytes produced for each finished input, by its path.
    produced: HashMap<PathBuf, ProducedBytes>,
    /// Group-level logs and run facts of this job.
    group_runs: HashMap<GroupId, GroupRun>,
    /// When the running folder unit's scan finished, for its log line.
    scan_at: Option<String>,
    /// Inputs this job finished, by group.
    finished: Vec<(GroupId, ItemId)>,
}

/// The restored image and entry outputs of one input.
type ProducedBytes = (Option<Produced>, Vec<(String, Produced)>);

/// Bytes loaded for the hex view.
#[derive(Debug, Clone)]
pub enum Loaded {
    Loading,
    Ready(Arc<[u8]>),
    Failed(crate::backend::LoadError),
}

/// A message for the status bar.
#[derive(Debug, Clone)]
pub struct Notice {
    pub text: String,
    pub tone: Tone,
}

/// What a drawing pass asks to change.
#[derive(Debug, Clone)]
pub enum Action {
    Pick(Pick),
    Run(Mode),
    RunItem(Mode, ItemId),
    Cancel,
    Select {
        sel: Sel,
        toggle: bool,
    },
    Fold(Sel),
    ShowEntries(ItemId),
    Tab(Tab),
    /// Show `offset` of an address space in the hex view.
    Jump {
        space: String,
        offset: u64,
    },
    /// Show `offset` of one hex view.
    JumpView {
        view: HexView,
        offset: u64,
    },
    Load(Source),
    Reveal(PathBuf),
    Remove(ItemId),
    Clear,
    Export {
        sel: Sel,
        json: bool,
    },
    SetOutput(Output),
    SetLanguage(Option<Lang>),
    AcceptLegal,
    Quit,
    StopAndClose,
}

/// Read-only state a drawing pass needs.
pub struct Draw<'a> {
    pub session: &'a Session,
    pub jobs: &'a Jobs,
    pub bytes: &'a HashMap<Source, Loaded>,
    pub settings: &'a Settings,
    pub caps: Capabilities,
    pub actions: &'a mut Vec<Action>,
}

impl Draw<'_> {
    fn act(&mut self, action: Action) {
        self.actions.push(action);
    }
}

/// A [`Draw`] over the workbench's parts, so the view state can be borrowed
/// mutably beside it.
fn draw_of<'a>(
    session: &'a Session,
    jobs: &'a Jobs,
    bytes: &'a HashMap<Source, Loaded>,
    settings: &'a Settings,
    caps: Capabilities,
    actions: &'a mut Vec<Action>,
) -> Draw<'a> {
    Draw {
        session,
        jobs,
        bytes,
        settings,
        caps,
        actions,
    }
}

pub struct Workbench {
    backend: Box<dyn Backend>,
    caps: Capabilities,
    session: Session,
    view: ViewState,
    pub settings: Settings,
    detected_lang: Lang,
    fonts: Option<Box<dyn FnMut(Lang) -> FontSet>>,
    font_lang: Option<Lang>,
    debug_vars: Vec<String>,
    jobs: Jobs,
    bytes: HashMap<Source, Loaded>,
    notice: Option<Notice>,
    close_after_job: bool,
    closing: bool,
    styled: bool,
    icon: Option<egui::ColorImage>,
    icon_texture: Option<egui::TextureHandle>,
}

impl Workbench {
    /// A workbench on `backend`. `fonts` returns the system fonts for a
    /// language; `debug_vars` names set debug environment variables.
    pub fn new(
        backend: Box<dyn Backend>,
        settings: Settings,
        detected_lang: Lang,
        fonts: Option<Box<dyn FnMut(Lang) -> FontSet>>,
        debug_vars: Vec<String>,
        icon: Option<egui::ColorImage>,
    ) -> Self {
        let caps = backend.capabilities();
        let mut settings = settings;
        if !caps.unpack {
            settings.output = Output::Beside;
        }
        Self {
            backend,
            caps,
            session: Session::default(),
            view: ViewState::default(),
            settings,
            detected_lang,
            fonts,
            font_lang: None,
            debug_vars,
            jobs: Jobs::default(),
            bytes: HashMap::new(),
            notice: None,
            close_after_job: false,
            closing: false,
            styled: false,
            icon,
            icon_texture: None,
        }
    }

    pub fn lang(&self) -> Lang {
        self.settings.lang(self.detected_lang)
    }

    /// True while the window waits on the backend: a job, a folder scan, an
    /// identification, or bytes for the hex view.
    pub fn is_busy(&self) -> bool {
        self.jobs.running.is_some()
            || !self.jobs.queued.is_empty()
            || self
                .session
                .groups
                .iter()
                .any(|group| group.scanning.is_some())
            || self
                .session
                .items()
                .any(|item| item.identity.is_none() && item.result.is_none())
            || self
                .bytes
                .values()
                .any(|loaded| matches!(loaded, Loaded::Loading))
    }

    /// Work that does not paint: events, language, window close.
    pub fn logic(&mut self, ctx: &Context) {
        let lang = self.lang();
        senbei_i18n::set_current(lang);
        if self.font_lang != Some(lang) {
            self.apply_fonts(ctx, lang);
        }
        if !self.styled {
            ctx.global_style_mut(|style| *style = theme::style(style));
            self.styled = true;
        }
        while let Some(event) = self.backend.poll() {
            self.on_event(ctx, event);
        }
        self.guard_close(ctx);
        if self.jobs.running.is_some() || self.session.groups.iter().any(|g| g.scanning.is_some()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn apply_fonts(&mut self, ctx: &Context, lang: Lang) {
        let set = match &mut self.fonts {
            Some(load) => load(lang),
            None => FontSet::default(),
        };
        ctx.set_fonts(theme::font_definitions(&set));
        self.font_lang = Some(lang);
    }

    fn guard_close(&mut self, ctx: &Context) {
        if !ctx.input(|input| input.viewport().close_requested()) || self.closing {
            return;
        }
        if self.jobs.running.is_some() || !self.jobs.queued.is_empty() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.view.close_confirm = true;
        } else {
            self.closing = true;
        }
    }

    /// Draw the whole window.
    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.icon_texture.is_none()
            && let Some(image) = self.icon.take()
        {
            self.icon_texture =
                Some(ctx.load_texture("senbei-icon", image, egui::TextureOptions::LINEAR));
        }
        self.take_drops(&ctx);
        self.shortcuts(&ctx);
        let mut actions = Vec::new();
        let legal_pending = !self.settings.legal_accepted;
        let bar = dialogs::TopBar {
            targets: self.target_count(),
            has_selection: !self.view.multi.is_empty() || self.view.selected.is_some(),
            icon: self.icon_texture.as_ref(),
        };
        let icon = self.icon_texture.as_ref();

        Panel::top("topbar")
            .frame(
                Frame::new()
                    .fill(theme::PANEL)
                    .inner_margin(Margin::symmetric(10, 6)),
            )
            .show(ui, |ui| {
                let mut draw = draw_of(
                    &self.session,
                    &self.jobs,
                    &self.bytes,
                    &self.settings,
                    self.caps,
                    &mut actions,
                );
                dialogs::topbar(ui, &mut draw, &mut self.view, bar);
            });
        if !self.debug_vars.is_empty() {
            Panel::top("banner")
                .frame(
                    Frame::new()
                        .fill(theme::accent_soft())
                        .inner_margin(Margin::symmetric(12, 5)),
                )
                .show(ui, |ui| dialogs::banner(ui, &self.debug_vars));
        }
        Panel::bottom("statusbar")
            .frame(
                Frame::new()
                    .fill(theme::PANEL)
                    .inner_margin(Margin::symmetric(12, 4)),
            )
            .show(ui, |ui| {
                let mut draw = draw_of(
                    &self.session,
                    &self.jobs,
                    &self.bytes,
                    &self.settings,
                    self.caps,
                    &mut actions,
                );
                dialogs::statusbar(ui, &mut draw, self.notice.as_ref());
            });
        if self.session.is_empty() {
            egui::CentralPanel::default()
                .frame(Frame::new().fill(theme::BG))
                .show(ui, |ui| {
                    let mut draw = draw_of(
                        &self.session,
                        &self.jobs,
                        &self.bytes,
                        &self.settings,
                        self.caps,
                        &mut actions,
                    );
                    dialogs::empty_state(ui, &mut draw, icon);
                });
        } else {
            let narrow = ui.available_width() < 1360.0;
            Panel::left("inputs")
                .resizable(true)
                .default_size(if narrow { 300.0 } else { 340.0 })
                .size_range(220.0..=640.0)
                .frame(Frame::new().fill(theme::PANEL))
                .show(ui, |ui| {
                    let mut draw = draw_of(
                        &self.session,
                        &self.jobs,
                        &self.bytes,
                        &self.settings,
                        self.caps,
                        &mut actions,
                    );
                    inputs::panel(ui, &mut draw, &mut self.view);
                });
            egui::CentralPanel::default()
                .frame(Frame::new().fill(theme::BG))
                .show(ui, |ui| {
                    let mut draw = draw_of(
                        &self.session,
                        &self.jobs,
                        &self.bytes,
                        &self.settings,
                        self.caps,
                        &mut actions,
                    );
                    detail::pane(ui, &mut draw, &mut self.view);
                });
        }

        let mut settings = self.settings.clone();
        {
            let mut draw = draw_of(
                &self.session,
                &self.jobs,
                &self.bytes,
                &self.settings,
                self.caps,
                &mut actions,
            );
            dialogs::overlays(
                &ctx,
                &mut draw,
                &mut self.view,
                &mut settings,
                dialogs::Overlays {
                    legal_pending,
                    icon,
                    detected: self.detected_lang,
                },
            );
        }
        if settings != self.settings {
            self.settings = settings;
        }
        for action in actions {
            self.apply(&ctx, action);
        }
    }

    // ------------------------------------------------------------ input

    fn take_drops(&mut self, ctx: &Context) {
        let dropped: Vec<PathBuf> = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .collect()
        });
        if !dropped.is_empty() && self.settings.legal_accepted {
            self.add_paths(dropped);
        }
    }

    fn shortcuts(&mut self, ctx: &Context) {
        if !self.settings.legal_accepted {
            return;
        }
        let open = egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::O);
        if ctx.input_mut(|input| input.consume_shortcut(&open)) {
            self.backend.send(Request::Pick(Pick::Files));
        }
        let typing = ctx.egui_wants_keyboard_input();
        if !typing
            && ctx.input(|input| input.key_pressed(egui::Key::Delete))
            && let Some(Sel::Item(id)) = self.view.selected
            && self.jobs.running.is_none()
        {
            self.remove_item(id);
        }
        if ctx.input(|input| input.key_pressed(egui::Key::F3)) {
            self.find_next();
        }
    }

    /// Add files and folders: files join "Added files", each folder is a
    /// group of its own.
    pub fn add_paths(&mut self, paths: Vec<PathBuf>) {
        let mut identify = Vec::new();
        for path in paths {
            if path.is_dir() {
                if !self.caps.folders {
                    continue;
                }
                if self
                    .session
                    .groups
                    .iter()
                    .any(|group| group.root() == Some(path.as_path()))
                {
                    continue;
                }
                let id = self.session.next();
                let mut group = Group::new(id, GroupKind::Folder(path.clone()));
                group.scanning = Some(0);
                self.session.groups.push(group);
                self.backend.send(Request::Scan {
                    group: id,
                    root: path,
                    scan_all: self.settings.scan_all,
                    limits: self.settings.limits(),
                });
                self.view.select(Sel::Group(id));
                continue;
            }
            // A dropped `x.exe._` stands for its loader `x.exe`.
            let path = match companion_stub(&path) {
                Some(stub) => stub,
                None => path,
            };
            let files = match self
                .session
                .groups
                .iter()
                .position(|group| group.kind == GroupKind::Files)
            {
                Some(index) => index,
                None => {
                    let id = self.session.next();
                    self.session
                        .groups
                        .insert(0, Group::new(id, GroupKind::Files));
                    0
                }
            };
            if self.session.groups[files]
                .items
                .iter()
                .any(|item| item.path == path)
            {
                continue;
            }
            let id = self.session.next();
            self.session.groups[files]
                .items
                .push(Item::new(id, path.clone()));
            identify.push((id, path));
            if self.view.selected.is_none() {
                self.view.select(Sel::Item(id));
            }
        }
        if let Some((first, _)) = identify.first()
            && !matches!(self.view.selected, Some(Sel::Item(_)))
        {
            self.view.select(Sel::Item(*first));
        }
        if !identify.is_empty() {
            self.backend.send(Request::Identify {
                items: identify,
                limits: self.settings.limits(),
            });
        }
    }

    fn remove_item(&mut self, id: ItemId) {
        for group in &mut self.session.groups {
            group.items.retain(|item| item.id != id);
        }
        self.session
            .groups
            .retain(|group| !(group.kind == GroupKind::Files && group.items.is_empty()));
        if matches!(self.view.selected, Some(Sel::Item(item) | Sel::Entry(item, _)) if item == id) {
            self.view.selected = None;
        }
        self.view
            .multi
            .retain(|sel| !matches!(sel, Sel::Item(item) | Sel::Entry(item, _) if *item == id));
    }

    // ------------------------------------------------------------- runs

    /// The inputs an action applies to: the multi-selection, else the
    /// selection, else everything. An entry stands for its package.
    fn targets(&self) -> Vec<(GroupId, Vec<ItemId>, bool)> {
        let picked: Vec<Sel> = if !self.view.multi.is_empty() {
            self.view.multi.clone()
        } else if let Some(sel) = self.view.selected {
            vec![sel]
        } else {
            self.session
                .groups
                .iter()
                .map(|group| Sel::Group(group.id))
                .collect()
        };
        let mut out: Vec<(GroupId, Vec<ItemId>, bool)> = Vec::new();
        let mut entry = |group: GroupId, item: Option<ItemId>| {
            let index = match out.iter().position(|(id, _, _)| *id == group) {
                Some(index) => index,
                None => {
                    out.push((group, Vec::new(), false));
                    out.len() - 1
                }
            };
            match item {
                None => out[index].2 = true,
                Some(item) if !out[index].1.contains(&item) => out[index].1.push(item),
                Some(_) => {}
            }
        };
        for sel in picked {
            match sel {
                Sel::Group(group) => entry(group, None),
                Sel::Item(item) | Sel::Entry(item, _) => {
                    if let Some((group, _)) = self.session.item(item) {
                        entry(group.id, Some(item));
                    }
                }
            }
        }
        for (group, items, whole) in &mut out {
            let Some(group) = self.session.group(*group) else {
                continue;
            };
            if *whole || (group.root().is_some() && items.len() == group.items.len()) {
                *whole = true;
                *items = group.items.iter().map(|item| item.id).collect();
            }
        }
        out
    }

    /// How many inputs a run of the current targets covers.
    pub fn target_count(&self) -> usize {
        self.targets().iter().map(|(_, items, _)| items.len()).sum()
    }

    fn plan_units(&self) -> Vec<(Unit, UnitPlan)> {
        let mut units = Vec::new();
        for (group_id, items, whole) in self.targets() {
            let Some(group) = self.session.group(group_id) else {
                continue;
            };
            if let (Some(root), true) = (group.root(), whole) {
                if group.scanning.is_some() {
                    continue;
                }
                units.push((
                    Unit::Folder {
                        root: root.to_path_buf(),
                        out_dir: self.out_dir(group, None),
                    },
                    UnitPlan {
                        group: group_id,
                        items: items.clone(),
                        folder: true,
                    },
                ));
                continue;
            }
            for id in items {
                let Some(item) = group.items.iter().find(|item| item.id == id) else {
                    continue;
                };
                units.push((
                    Unit::File {
                        path: item.path.clone(),
                        out_dir: self.out_dir(group, Some(&item.path)),
                    },
                    UnitPlan {
                        group: group_id,
                        items: vec![id],
                        folder: false,
                    },
                ));
            }
        }
        units
    }

    /// Where an unpack of `item` (or of the whole group) writes.
    fn out_dir(&self, group: &Group, item: Option<&Path>) -> PathBuf {
        let relative = |root: &Path, path: &Path| -> PathBuf {
            path.parent()
                .and_then(|parent| parent.strip_prefix(root).ok())
                .map(Path::to_path_buf)
                .unwrap_or_default()
        };
        match (&self.settings.output, group.root(), item) {
            (Output::Beside, Some(root), None) => senbei_io::job::default_out_root_for_folder(root),
            (Output::Beside, Some(root), Some(path)) => {
                senbei_io::job::default_out_root_for_folder(root).join(relative(root, path))
            }
            (Output::Beside, None, Some(path)) => senbei_io::job::default_out_root_for_file(path),
            (Output::Folder(dir), Some(root), Some(path)) => dir.join(relative(root, path)),
            (Output::Folder(dir), _, _) => dir.clone(),
            (Output::Beside, None, None) => PathBuf::from("unpack"),
        }
    }

    fn start(&mut self, mode: Mode, units: Vec<(Unit, UnitPlan)>) {
        if units.is_empty() || (mode == Mode::Unpack && !self.caps.unpack) {
            return;
        }
        self.jobs.next_id += 1;
        let id = self.jobs.next_id;
        let (units, plans): (Vec<Unit>, Vec<UnitPlan>) = units.into_iter().unzip();
        for plan in &plans {
            for item in &plan.items {
                if let Some(item) = self.session.item_mut(*item) {
                    item.run = RunState::Queued;
                }
            }
        }
        self.jobs.queued.push_back(JobPlan {
            id,
            mode,
            units: plans,
        });
        self.backend.send(Request::Run(Box::new(Job {
            id,
            mode,
            units,
            options: self.settings.run_options(),
        })));
    }

    fn run_item(&mut self, mode: Mode, id: ItemId) {
        let Some((group, item)) = self.session.item(id) else {
            return;
        };
        let unit = Unit::File {
            path: item.path.clone(),
            out_dir: self.out_dir(group, Some(&item.path)),
        };
        let plan = UnitPlan {
            group: group.id,
            items: vec![id],
            folder: false,
        };
        self.start(mode, vec![(unit, plan)]);
    }

    // ----------------------------------------------------------- events

    fn on_event(&mut self, ctx: &Context, event: Event) {
        match event {
            Event::Identified(id, identity) => {
                if let Some(item) = self.session.item_mut(id) {
                    item.identity = Some(*identity);
                }
            }
            Event::ScanProgress { group, found } => {
                if let Some(group) = self.session.group_mut(group)
                    && group.scanning.is_some()
                {
                    group.scanning = Some(found);
                }
            }
            Event::Scanned {
                group,
                targets,
                scan,
            } => {
                let ids: Vec<ItemId> = targets.iter().map(|_| self.session.next()).collect();
                if let Some(group) = self.session.group_mut(group) {
                    group.scanning = None;
                    group.scan = Some(scan);
                    for ((path, identity), id) in targets.into_iter().zip(ids) {
                        let mut item = Item::new(id, path);
                        item.identity = Some(*identity);
                        group.items.push(item);
                    }
                }
            }
            Event::UnitStarted { job, unit, at } => self.unit_started(job, unit, at),
            Event::UnitScanned {
                job,
                unit,
                inputs,
                at,
            } => {
                if let Some(running) = &mut self.jobs.running
                    && running.plan.id == job
                    && let Some(plan) = running.plan.units.get(unit)
                {
                    let planned = plan.items.len();
                    running.total = running.total + inputs - planned.min(running.total);
                    running.scan_at = Some(at);
                    // The run's own scan is the count the log reports.
                    if let Some(group_run) = running.group_runs.get_mut(&plan.group)
                        && let Some(LogBody::RunStarted { inputs: total, .. }) =
                            group_run.log.first_mut().map(|line| &mut line.body)
                    {
                        *total = *total + inputs - planned.min(*total);
                    }
                }
            }
            Event::InputStarted {
                job,
                unit,
                path,
                at,
            } => self.input_started(job, unit, &path, at),
            Event::Step {
                job,
                step,
                position,
                at,
            } => {
                if let Some(running) = self.running(job) {
                    running.live.push(LogLine::new(
                        at,
                        Level::Step,
                        LogBody::Step {
                            position,
                            step: step.clone(),
                        },
                    ));
                    if !matches!(step, Step::WriteTo { .. }) {
                        running.step = Some((position, step));
                    }
                }
            }
            Event::Detail { job, text, at } => {
                if let Some(running) = self.running(job) {
                    running
                        .live
                        .push(LogLine::new(at, Level::Detail, LogBody::Detail(text)));
                }
            }
            Event::Produced {
                job,
                path,
                restored,
                entries,
            } => {
                if let Some(running) = self.running(job) {
                    running.produced.insert(path, (restored, entries));
                }
            }
            Event::InputFinished {
                job,
                unit,
                report,
                at,
            } => self.input_finished(job, unit, *report, at),
            Event::UnitFinished {
                job,
                unit,
                report,
                at,
            } => self.unit_finished(job, unit, *report, at),
            Event::JobFinished { job, cancelled } => self.job_finished(ctx, job, cancelled),
            Event::Loaded { source, result } => {
                self.bytes.insert(
                    source,
                    match result {
                        Ok(bytes) => Loaded::Ready(bytes),
                        Err(error) => Loaded::Failed(error),
                    },
                );
            }
            Event::Picked(pick, paths) => match pick {
                Pick::Files | Pick::Folder => self.add_paths(paths),
                Pick::Output => {
                    if let Some(folder) = paths.into_iter().next() {
                        self.settings.recent_output = Some(folder.clone());
                        self.settings.output = Output::Folder(folder);
                    }
                }
            },
            Event::Saved(result) => {
                self.notice = Some(match result {
                    Ok(path) => Notice {
                        text: path.display().to_string(),
                        tone: Tone::Ok,
                    },
                    Err(error) => Notice {
                        text: error,
                        tone: Tone::Err,
                    },
                });
            }
            Event::Failed(error) => {
                self.notice = Some(Notice {
                    text: error,
                    tone: Tone::Err,
                });
            }
        }
    }

    fn running(&mut self, job: JobId) -> Option<&mut RunningJob> {
        self.jobs
            .running
            .as_mut()
            .filter(|running| running.plan.id == job)
    }

    fn unit_started(&mut self, job: JobId, unit: usize, at: String) {
        if self.jobs.running.as_ref().map(|running| running.plan.id) != Some(job) {
            let Some(index) = self.jobs.queued.iter().position(|plan| plan.id == job) else {
                return;
            };
            let plan = self.jobs.queued.remove(index).expect("index");
            let total = plan.units.iter().map(|unit| unit.items.len()).sum();
            self.jobs.running = Some(RunningJob {
                plan,
                total,
                done: 0,
                current: None,
                step: None,
                input_started: Instant::now(),
                cancel_requested: false,
                live: Vec::new(),
                produced: HashMap::new(),
                group_runs: HashMap::new(),
                scan_at: None,
                finished: Vec::new(),
            });
        }
        let Some(running) = self.jobs.running.as_mut() else {
            return;
        };
        let Some(plan) = running.plan.units.get(unit).cloned() else {
            return;
        };
        let mode = running.plan.mode;
        let inputs = running
            .plan
            .units
            .iter()
            .filter(|unit| unit.group == plan.group)
            .map(|unit| unit.items.len())
            .sum();
        running
            .group_runs
            .entry(plan.group)
            .or_insert_with(|| GroupRun {
                mode,
                duration_ms: 0,
                errors: Vec::new(),
                cancelled: false,
                log: vec![LogLine::new(
                    at.clone(),
                    Level::Info,
                    LogBody::RunStarted { mode, inputs },
                )],
                report: None,
            });
    }

    fn input_started(&mut self, job: JobId, unit: usize, path: &Path, at: String) {
        let Some(running) = self
            .jobs
            .running
            .as_ref()
            .filter(|running| running.plan.id == job)
        else {
            return;
        };
        let Some(plan) = running.plan.units.get(unit).cloned() else {
            return;
        };
        let mode = running.plan.mode;
        // A folder run may find inputs the add-time scan did not.
        let item_id = match self.find_in_group(plan.group, path) {
            Some(id) => id,
            None => {
                let id = self.session.next();
                if let Some(group) = self.session.group_mut(plan.group) {
                    group.items.push(Item::new(id, path.to_path_buf()));
                }
                id
            }
        };
        if let Some(item) = self.session.item_mut(item_id) {
            item.run = RunState::Running;
        }
        let Some(running) = self.jobs.running.as_mut() else {
            return;
        };
        // Inputs are numbered across their group, as one run of it, even
        // when each added file runs as a unit of its own.
        let (index, total) = running
            .group_runs
            .get(&plan.group)
            .map_or((1, 1), |group_run| next_position(&group_run.log));
        running.current = Some(item_id);
        running.step = None;
        running.input_started = Instant::now();
        let started = LogLine::new(
            at.clone(),
            Level::Info,
            LogBody::InputStarted {
                index,
                total,
                path: path.display().to_string(),
            },
        );
        running.live = vec![
            LogLine::new(
                at,
                Level::Info,
                LogBody::RunStarted {
                    mode,
                    inputs: total,
                },
            ),
            started.clone(),
        ];
        if let Some(group_run) = running.group_runs.get_mut(&plan.group) {
            group_run.log.push(started);
        }
    }

    fn find_in_group(&self, group: GroupId, path: &Path) -> Option<ItemId> {
        self.session
            .group(group)?
            .items
            .iter()
            .find(|item| item.path == path)
            .map(|item| item.id)
    }

    fn input_finished(&mut self, job: JobId, unit: usize, report: InputReport, at: String) {
        let Some(running) = self
            .jobs
            .running
            .as_ref()
            .filter(|running| running.plan.id == job)
        else {
            return;
        };
        let Some(plan) = running.plan.units.get(unit).cloned() else {
            return;
        };
        let mode = running.plan.mode;
        let path = PathBuf::from(&report.path);
        let item_id = match running.current {
            Some(current)
                if self
                    .session
                    .item(current)
                    .is_some_and(|(_, item)| item.path == path) =>
            {
                Some(current)
            }
            _ => self.find_in_group(plan.group, &path),
        };
        let item_id = match item_id {
            Some(id) => id,
            None => {
                let id = self.session.next();
                if let Some(group) = self.session.group_mut(plan.group) {
                    group.items.push(Item::new(id, path.clone()));
                }
                id
            }
        };
        let running = self.jobs.running.as_mut().expect("running");
        let mut log = std::mem::take(&mut running.live);
        if log.is_empty() {
            // Finished without a start event: number it like the others.
            let (index, total) = running
                .group_runs
                .get(&plan.group)
                .map_or((1, 1), |group_run| next_position(&group_run.log));
            let started = LogLine::new(
                at.clone(),
                Level::Info,
                LogBody::InputStarted {
                    index,
                    total,
                    path: report.path.clone(),
                },
            );
            if let Some(group_run) = running.group_runs.get_mut(&plan.group) {
                group_run.log.push(started.clone());
            }
            log.push(started);
        }
        finish_log(&mut log, &report, &at);
        let verdict = Verdict::of_input(&report);
        if let Some(group_run) = running.group_runs.get_mut(&plan.group) {
            group_run.log.push(LogLine::new(
                at,
                level_of(verdict),
                LogBody::Finished {
                    verdict,
                    duration: report.duration_ms,
                },
            ));
        }
        let (restored, entries) = running.produced.remove(&path).unwrap_or_default();
        running.done += 1;
        running.finished.push((plan.group, item_id));
        if running.current == Some(item_id) {
            running.current = None;
            running.step = None;
        }
        if let Some(item) = self.session.item_mut(item_id) {
            item.run = RunState::Idle;
            item.result = Some(ItemResult {
                mode,
                report,
                log,
                restored,
                entries,
            });
        }
        // New bytes replace what the hex view had for these paths.
        self.bytes.retain(
            |source, _| !matches!(source, Source::Entry { package, .. } if *package == path),
        );
    }

    fn unit_finished(&mut self, job: JobId, unit: usize, report: Report, at: String) {
        let Some(running) = self
            .jobs
            .running
            .as_mut()
            .filter(|running| running.plan.id == job)
        else {
            return;
        };
        let Some(plan) = running.plan.units.get(unit).cloned() else {
            return;
        };
        if let Some(group_run) = running.group_runs.get_mut(&plan.group) {
            group_run.duration_ms += report.duration_ms;
            group_run.cancelled |= report.cancelled;
            for error in &report.errors {
                group_run.log.push(LogLine::new(
                    at.clone(),
                    Level::Error,
                    LogBody::Message(error.clone()),
                ));
            }
            group_run.errors.extend(report.errors.iter().cloned());
            if plan.folder {
                if let Some(scan) = report.scan {
                    group_run.log.insert(
                        1.min(group_run.log.len()),
                        LogLine::new(
                            running.scan_at.take().unwrap_or_else(|| at.clone()),
                            Level::Info,
                            LogBody::Scan {
                                candidates: report.summary.inputs,
                                skipped: scan.non_target_skipped,
                            },
                        ),
                    );
                    if scan.walk_errors > 0 || scan.probe_errors > 0 {
                        group_run.log.push(LogLine::new(
                            at.clone(),
                            Level::Warn,
                            LogBody::ScanIncomplete,
                        ));
                    }
                }
                group_run.report = Some(report.clone());
            }
        }
        if plan.folder
            && let Some(scan) = report.scan
            && let Some(group) = self.session.group_mut(plan.group)
        {
            group.scan = Some(scan);
        }
    }

    fn job_finished(&mut self, ctx: &Context, job: JobId, cancelled: bool) {
        let (units, group_runs, finished) = match self.jobs.running.take() {
            Some(running) if running.plan.id == job => {
                (running.plan.units, running.group_runs, running.finished)
            }
            other => {
                self.jobs.running = other;
                // A job cancelled before it started.
                match self.jobs.queued.iter().position(|plan| plan.id == job) {
                    Some(index) => match self.jobs.queued.remove(index) {
                        Some(plan) => (plan.units, HashMap::new(), Vec::new()),
                        None => return,
                    },
                    None => return,
                }
            }
        };
        for plan in &units {
            for id in &plan.items {
                if let Some(item) = self.session.item_mut(*id)
                    && matches!(
                        item.run,
                        RunState::Queued | RunState::Running | RunState::WillNotRun
                    )
                {
                    // An earlier result still stands for an input the
                    // cancelled job never reached.
                    item.run = if cancelled && item.result.is_none() {
                        RunState::WillNotRun
                    } else {
                        RunState::Idle
                    };
                }
            }
        }
        for (group_id, mut group_run) in group_runs {
            let Some(group) = self.session.group_mut(group_id) else {
                continue;
            };
            let mut counts = Counts::default();
            for (_, id) in finished.iter().filter(|(group, _)| *group == group_id) {
                if let Some(verdict) = group
                    .items
                    .iter()
                    .find(|item| item.id == *id)
                    .and_then(Item::verdict)
                {
                    counts.inputs += 1;
                    counts.add(verdict);
                }
            }
            group_run.cancelled |= cancelled;
            group_run.log.push(LogLine::new(
                senbei_io::logfile::local_clock(),
                Level::Info,
                LogBody::Summary(counts),
            ));
            group.last_run = Some(group_run);
        }
        if self.close_after_job && self.jobs.running.is_none() && self.jobs.queued.is_empty() {
            self.closing = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    // ---------------------------------------------------------- actions

    fn apply(&mut self, ctx: &Context, action: Action) {
        match action {
            Action::Pick(pick) => self.backend.send(Request::Pick(pick)),
            Action::Run(mode) => {
                let units = self.plan_units();
                self.start(mode, units);
            }
            Action::RunItem(mode, id) => self.run_item(mode, id),
            Action::Cancel => {
                if let Some(running) = &mut self.jobs.running {
                    running.cancel_requested = true;
                }
                // Queued jobs still start, see the cancelled token, and end
                // at once; their inputs will not run.
                for plan in &self.jobs.queued {
                    for unit in &plan.units {
                        for id in &unit.items {
                            if let Some(item) = self.session.item_mut(*id)
                                && item.result.is_none()
                            {
                                item.run = RunState::WillNotRun;
                            }
                        }
                    }
                }
                self.backend.send(Request::Cancel);
            }
            Action::Select { sel, toggle } => {
                if toggle {
                    if let Some(current) = self.view.selected
                        && !self.view.multi.contains(&current)
                        && !matches!(current, Sel::Group(_))
                    {
                        self.view.multi.push(current);
                    }
                    if let Some(index) = self.view.multi.iter().position(|known| *known == sel) {
                        self.view.multi.remove(index);
                    } else {
                        self.view.multi.push(sel);
                    }
                } else {
                    self.view.multi.clear();
                }
                self.view.select(sel);
            }
            Action::Fold(sel) => match sel {
                Sel::Group(id) => {
                    if let Some(group) = self.session.group_mut(id) {
                        group.folded = !group.folded;
                    }
                }
                Sel::Item(id) | Sel::Entry(id, _) => {
                    if let Some(item) = self.session.item_mut(id) {
                        item.folded = !item.folded;
                    }
                }
            },
            Action::ShowEntries(id) => {
                self.view.multi.clear();
                self.view.select(Sel::Item(id));
                self.view.tab = Tab::Entries;
                self.view.show_non_targets = true;
            }
            Action::Tab(tab) => self.view.tab = tab,
            Action::Jump { space, offset } => self.jump(&space, offset),
            Action::JumpView { view, offset } => {
                self.view.hex.view = Some(view);
                self.view.hex.focus = Some(offset);
                self.view.hex.highlight = Some((offset, offset + 16));
                self.view.hex.note = None;
                self.view.hex.reveal = true;
                self.view.tab = Tab::Hex;
            }
            Action::Load(source) => {
                if !self.bytes.contains_key(&source) {
                    self.bytes.insert(source.clone(), Loaded::Loading);
                    self.backend.send(Request::Load {
                        source,
                        limits: self.settings.limits(),
                    });
                }
            }
            Action::Reveal(path) => self.backend.send(Request::Reveal(path)),
            Action::Remove(id) => {
                if self.jobs.running.is_none() {
                    self.remove_item(id);
                }
            }
            Action::Clear => {
                if self.jobs.running.is_none() && self.jobs.queued.is_empty() {
                    self.session.groups.clear();
                    self.view = ViewState {
                        settings_open: self.view.settings_open,
                        ..ViewState::default()
                    };
                    self.bytes.clear();
                }
            }
            Action::Export { sel, json } => self.export(sel, json),
            Action::SetOutput(output) => {
                if let Output::Folder(folder) = &output {
                    self.settings.recent_output = Some(folder.clone());
                }
                self.settings.output = output;
            }
            Action::SetLanguage(lang) => {
                self.settings.language = lang.map(|lang| lang.tag().to_owned());
                senbei_i18n::set_current(self.lang());
            }
            Action::AcceptLegal => {
                self.settings.legal_accepted = true;
                self.view.legal_open = false;
            }
            Action::Quit => {
                self.closing = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Action::StopAndClose => {
                self.view.close_confirm = false;
                self.close_after_job = true;
                self.apply(ctx, Action::Cancel);
            }
        }
    }

    /// Show an address in the hex view. Working-image RVAs address the image
    /// being rebuilt, so they open the restored image when one exists.
    fn jump(&mut self, space: &str, offset: u64) {
        let id = match self.view.selected {
            Some(Sel::Item(id)) => id,
            // Entry offsets address the extracted entry.
            Some(Sel::Entry(..)) => {
                self.view.hex.view = Some(HexView::Original);
                self.view.hex.focus = Some(offset);
                self.view.hex.highlight = Some((offset, offset + 16));
                self.view.hex.note = None;
                self.view.hex.reveal = true;
                self.view.tab = Tab::Hex;
                return;
            }
            _ => return,
        };
        let Some((_, item)) = self.session.item(id) else {
            return;
        };
        let research = item
            .result
            .as_ref()
            .and_then(|result| result.report.research.as_ref());
        let rva = match space {
            "working_image_rva" => Some(offset),
            "decoded_payload_offset" => research
                .and_then(|research| research.input.protection.as_ref())
                .and_then(|protection| protection.payload.as_ref())
                .map(|payload| u64::from(payload.destination_rva) + offset),
            _ => None,
        };
        let (view, target) = match rva {
            Some(rva) => match research.and_then(|research| research.restored.as_ref()) {
                Some(restored) => (
                    HexView::Restored,
                    hex::rva_to_offset(restored.pe.as_ref(), rva).unwrap_or(rva),
                ),
                None => (
                    HexView::Original,
                    research
                        .and_then(|research| hex::rva_to_offset(research.input.pe.as_ref(), rva))
                        .unwrap_or(rva),
                ),
            },
            None => (
                if research.is_some_and(|research| {
                    research.input_view == senbei_io::report::ResearchInputView::SplicedCompanion
                }) {
                    HexView::Spliced
                } else {
                    HexView::Original
                },
                offset,
            ),
        };
        self.view.hex.view = Some(view);
        self.view.hex.focus = Some(target);
        self.view.hex.highlight = Some((target, target + 16));
        self.view.hex.note = None;
        self.view.hex.reveal = true;
        self.view.tab = Tab::Hex;
    }

    fn find_next(&mut self) {
        if self.view.tab != Tab::Hex {
            return;
        }
        let draw_bytes = hex::current_bytes(&self.session, &self.bytes, &self.view);
        if let Some(bytes) = draw_bytes {
            hex::find(&bytes, &mut self.view.hex);
        }
    }

    fn export(&mut self, sel: Sel, json: bool) {
        let Some((report, name)) = self.export_report(sel) else {
            return;
        };
        let contents = if json {
            report.to_json()
        } else {
            report.render_text_in(senbei_io::ui::Palette::plain(), self.lang())
        };
        let extension = if json { "json" } else { "txt" };
        self.backend.send(Request::Save {
            name: format!("{name}.senbei.{extension}"),
            contents: contents.into_bytes(),
        });
    }

    /// A versioned report of the selection, as `--json` would write it.
    fn export_report(&self, sel: Sel) -> Option<(Report, String)> {
        let (group, items, run): (&Group, Vec<&Item>, Option<&GroupRun>) = match sel {
            Sel::Group(id) => {
                let group = self.session.group(id)?;
                (group, group.items.iter().collect(), group.last_run.as_ref())
            }
            Sel::Item(id) | Sel::Entry(id, _) => {
                let (group, item) = self.session.item(id)?;
                (group, vec![item], None)
            }
        };
        let results: Vec<&ItemResult> = items
            .iter()
            .filter_map(|item| item.result.as_ref())
            .collect();
        let mode = run
            .map(|run| run.mode)
            .or_else(|| results.first().map(|result| result.mode))?;
        let inputs: Vec<InputReport> = results.iter().map(|result| result.report.clone()).collect();
        let mut report = match run.and_then(|run| run.report.clone()) {
            Some(report) => report,
            None => {
                let mut collector = senbei_io::report::Collector::new(mode);
                for input in &inputs {
                    collector.push(input.clone());
                }
                let mut report = collector.finish();
                report.duration_ms = inputs.iter().map(|input| input.duration_ms).sum();
                report
            }
        };
        report.inputs = inputs;
        let name = match sel {
            Sel::Group(_) => group.title().into_owned(),
            _ => items
                .first()
                .map(|item| item.name.clone())
                .unwrap_or_default(),
        };
        Some((report, name))
    }
}

/// `x.exe` for a dropped `x.exe._` whose loader exists.
fn companion_stub(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let stub = name.strip_suffix("._")?;
    let stub = path.with_file_name(stub);
    stub.is_file().then_some(stub)
}

fn level_of(verdict: Verdict) -> Level {
    match verdict.tone() {
        Tone::Err => Level::Error,
        Tone::Warn => Level::Warn,
        _ => Level::Info,
    }
}

/// The next input's position in its group's run and the run's input count.
fn next_position(log: &[LogLine]) -> (usize, usize) {
    let index = 1 + log
        .iter()
        .filter(|line| matches!(line.body, LogBody::InputStarted { .. }))
        .count();
    let total = log
        .iter()
        .find_map(|line| match line.body {
            LogBody::RunStarted { inputs, .. } => Some(inputs),
            _ => None,
        })
        .unwrap_or(index);
    (index, total.max(index))
}

/// Close an input's log: companion, stages, messages, entries, outcome.
fn finish_log(log: &mut Vec<LogLine>, report: &InputReport, at: &str) {
    if let Some(companion) = &report.companion
        && companion.state == CompanionState::Spliced
    {
        let name = companion
            .path
            .as_deref()
            .map(crate::format::base_name)
            .unwrap_or_default()
            .to_owned();
        let at_companion = log.get(1).map_or(at.to_owned(), |line| line.at.clone());
        log.insert(
            2.min(log.len()),
            LogLine::new(at_companion, Level::Info, LogBody::Companion { name }),
        );
    }
    let skipped = report.status == senbei_io::report::InputStatus::Skipped;
    for stage in &report.stages {
        let status = if skipped && stage.status == StageStatus::Failed {
            StageStatus::Skipped
        } else {
            stage.status
        };
        log.push(LogLine::new(
            at,
            if status == StageStatus::Failed {
                Level::Error
            } else {
                Level::Info
            },
            LogBody::Stage {
                stage: stage.stage,
                status,
                duration: stage.duration_ms,
                detail: stage.detail.clone(),
            },
        ));
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |log: &mut Vec<LogLine>, level: Level, message: &Message| {
        if seen.insert(message.text().to_owned()) && !crate::labels::message(message).quiet {
            log.push(LogLine::new(at, level, LogBody::Message(message.clone())));
        }
    };
    for message in &report.errors {
        push(log, Level::Error, message);
    }
    for message in &report.warnings {
        push(log, Level::Warn, message);
    }
    if let Some(profile) = &report.profile {
        for message in &profile.errors {
            push(log, Level::Error, message);
        }
        for message in &profile.warnings {
            push(log, Level::Warn, message);
        }
    }
    for entry in report.entries.iter().filter(|entry| is_target_entry(entry)) {
        let verdict = Verdict::of_entry(entry);
        log.push(LogLine::new(
            at,
            if verdict.tone() == Tone::Err {
                Level::Error
            } else {
                Level::Info
            },
            LogBody::Entry {
                label: crate::model::entry_inner(&entry.name).to_owned(),
                verdict,
            },
        ));
    }
    let verdict = Verdict::of_input(report);
    log.push(LogLine::new(
        at,
        level_of(verdict),
        LogBody::Finished {
            verdict,
            duration: report.duration_ms,
        },
    ));
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    struct RecordingBackend(Rc<RefCell<Vec<Request>>>);

    impl Backend for RecordingBackend {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                folders: true,
                unpack: true,
                reveal: true,
            }
        }

        fn send(&self, request: Request) {
            self.0.borrow_mut().push(request);
        }

        fn poll(&self) -> Option<Event> {
            None
        }
    }

    #[test]
    fn file_identification_uses_current_resource_limits() {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let settings = Settings {
            max_entry_mib: 1,
            max_total_mib: 3,
            max_entries: 7,
            max_depth: 2,
            ..Settings::default()
        };
        let mut workbench = Workbench::new(
            Box::new(RecordingBackend(requests.clone())),
            settings,
            Lang::En,
            None,
            Vec::new(),
            None,
        );
        let first = PathBuf::from("identification-limit-first.apk");
        let first_limits = workbench.settings.limits();
        workbench.add_paths(vec![first.clone()]);

        workbench.settings.max_entry_mib = 5;
        workbench.settings.max_entries = 11;
        let second = PathBuf::from("identification-limit-second.apk");
        let second_limits = workbench.settings.limits();
        workbench.add_paths(vec![second.clone()]);

        let requests = requests.borrow();
        assert_eq!(requests.len(), 2);
        for (request, path, expected_limits) in [
            (&requests[0], first, first_limits),
            (&requests[1], second, second_limits),
        ] {
            let Request::Identify { items, limits } = request else {
                panic!("expected an identification request");
            };
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].1, path);
            assert_eq!(*limits, expected_limits);
        }
    }
}
