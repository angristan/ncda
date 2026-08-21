pub mod app;
pub mod filter;
pub mod flat_view;
pub mod footer;
pub mod header;
pub mod input;
pub mod layout;
pub mod tree_view;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Terminal;

use self::app::{AppState, PaneFocus, ViewMode, ViewState};

/// Restores terminal state on success, errors, and unwinding panics.
trait RestoreTerminal {
    fn restore(&mut self);
}

struct CrosstermRestore;

impl RestoreTerminal for CrosstermRestore {
    fn restore(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    }
}

struct TerminalRestoreGuard<R: RestoreTerminal> {
    restorer: R,
}

impl TerminalRestoreGuard<CrosstermRestore> {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        Ok(Self {
            restorer: CrosstermRestore,
        })
    }
}

impl<R: RestoreTerminal> Drop for TerminalRestoreGuard<R> {
    fn drop(&mut self) {
        self.restorer.restore();
    }
}

/// Run the TUI event loop.
pub fn run(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let _restore_terminal = TerminalRestoreGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut view = ViewState::new();
    let mut selected_file_path = None;
    let tick_rate = Duration::from_millis(250);

    loop {
        // Reconcile by path before every render so a live re-sort does not
        // silently move the selection to another file.
        {
            let state = state.lock().unwrap();
            reconcile_file_selection(&state, &mut view, &mut selected_file_path);
            terminal.draw(|f| draw(f, &state, &view))?;
        }

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Flat drill-in needs tree access. Help remains a true modal,
                // so its first key must never reach this pre-handler path.
                if is_flat_drill_key(key)
                    && !view.show_help
                    && view.mode == ViewMode::Flat
                    && view.focus == PaneFocus::Files
                    && view.filter_input.is_none()
                {
                    let state = state.lock().unwrap();
                    let rows = flat_view::visible_rows(
                        &state.tree,
                        &view.cwd,
                        view.sort_by,
                        view.sort_desc,
                        &view.filter,
                        &state.process_table,
                    );
                    if let Some(row) = rows.get(view.cursor) {
                        if row.is_dir {
                            view.cwd.push(row.name.clone());
                            view.cursor = 0;
                            selected_file_path = selection_identity(&state, &view);
                        }
                    }
                    continue;
                }

                let (flat_count, tree_lines, process_pids) = {
                    let state = state.lock().unwrap();
                    let flat_count = flat_view::visible_rows(
                        &state.tree,
                        &view.cwd,
                        view.sort_by,
                        view.sort_desc,
                        &view.filter,
                        &state.process_table,
                    )
                    .len();
                    let tree_lines = tree_view::flatten(
                        &state.tree,
                        &view.expanded,
                        view.sort_by,
                        view.sort_desc,
                        &view.filter,
                        &state.process_table,
                    );
                    let process_pids = visible_processes(&state, &view)
                        .into_iter()
                        .map(|process| process.pid)
                        .collect::<Vec<_>>();
                    (flat_count, tree_lines, process_pids)
                };
                view.reconcile_process_selection(&process_pids);

                let file_navigation = view.focus == PaneFocus::Files
                    && view.filter_input.is_none()
                    && is_file_navigation_key(key);
                let old_mode = view.mode;
                let size = terminal.size()?;
                let page_height =
                    visible_page_height(size.width, size.height, view.show_processes, view.focus);
                let mut should_reset = false;
                let quit = input::handle_key_with_page_height(
                    key,
                    &mut view,
                    flat_count,
                    &tree_lines,
                    &process_pids,
                    page_height,
                    &mut should_reset,
                );

                if should_reset {
                    let mut state = state.lock().unwrap();
                    state.reset();
                    view.cursor = 0;
                    selected_file_path = None;
                } else {
                    let state = state.lock().unwrap();
                    if view.mode != old_mode {
                        selected_file_path = None;
                    }
                    if file_navigation {
                        selected_file_path = selection_identity(&state, &view);
                    } else {
                        reconcile_file_selection(&state, &mut view, &mut selected_file_path);
                    }
                }

                let updated_process_pids = {
                    let state = state.lock().unwrap();
                    visible_processes(&state, &view)
                        .into_iter()
                        .map(|process| process.pid)
                        .collect::<Vec<_>>()
                };
                view.reconcile_process_selection(&updated_process_pids);

                if quit {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn is_flat_drill_key(key: KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')
    )
}

fn is_file_navigation_key(key: KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Backspace
            | KeyCode::Enter
            | KeyCode::Char('j' | 'k' | 'g' | 'G' | 'h' | 'l')
    )
}

fn selection_identity(state: &AppState, view: &ViewState) -> Option<String> {
    match view.mode {
        ViewMode::Flat => flat_view::visible_rows(
            &state.tree,
            &view.cwd,
            view.sort_by,
            view.sort_desc,
            &view.filter,
            &state.process_table,
        )
        .get(view.cursor)
        .map(|row| row.path.clone()),
        ViewMode::Tree => tree_view::flatten(
            &state.tree,
            &view.expanded,
            view.sort_by,
            view.sort_desc,
            &view.filter,
            &state.process_table,
        )
        .get(view.cursor)
        .map(|line| line.display_path.clone()),
    }
}

fn reconcile_file_selection(
    state: &AppState,
    view: &mut ViewState,
    selected_path: &mut Option<String>,
) {
    let paths = match view.mode {
        ViewMode::Flat => flat_view::visible_rows(
            &state.tree,
            &view.cwd,
            view.sort_by,
            view.sort_desc,
            &view.filter,
            &state.process_table,
        )
        .into_iter()
        .map(|row| row.path)
        .collect::<Vec<_>>(),
        ViewMode::Tree => tree_view::flatten(
            &state.tree,
            &view.expanded,
            view.sort_by,
            view.sort_desc,
            &view.filter,
            &state.process_table,
        )
        .into_iter()
        .map(|line| line.display_path)
        .collect::<Vec<_>>(),
    };

    if paths.is_empty() {
        view.cursor = 0;
        *selected_path = None;
        return;
    }
    if let Some(index) = selected_path
        .as_ref()
        .and_then(|selected| paths.iter().position(|path| path == selected))
    {
        view.cursor = index;
    } else {
        view.cursor = view.cursor.min(paths.len() - 1);
        *selected_path = Some(paths[view.cursor].clone());
    }
}

fn visible_page_height(width: u16, height: u16, show_processes: bool, focus: PaneFocus) -> usize {
    let body_height = height.saturating_sub(2);
    let body = compute_body_areas(Rect::new(0, 0, width, body_height), show_processes);
    let height = if focus == PaneFocus::Processes {
        body.processes
            .map(|area| {
                Block::default()
                    .borders(body.process_borders)
                    .inner(area)
                    .height
            })
            .unwrap_or(body.main.height)
    } else {
        body.main.height
    };
    usize::from(height).max(1)
}

fn draw(f: &mut ratatui::Frame, state: &AppState, view: &ViewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // column headers
            Constraint::Min(1),    // main content
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    header::draw(f, chunks[0], view);

    let body_area = Rect::new(
        chunks[1].x,
        chunks[1].y,
        chunks[1].width,
        chunks[1].height.saturating_add(chunks[2].height),
    );
    let body = compute_body_areas(body_area, view.show_processes);
    if let Some(process_area) = body.processes {
        draw_process_panel(f, process_area, state, view, body.process_borders);
    }
    let columns_area = body.columns;
    let main_area = body.main;

    match view.mode {
        ViewMode::Flat => {
            flat_view::draw_columns(f, columns_area);
            flat_view::draw(
                f,
                main_area,
                &state.tree,
                &state.process_table,
                &state.event_log,
                view,
            );
        }
        ViewMode::Tree => {
            tree_view::draw_columns(f, columns_area);
            let lines = tree_view::flatten(
                &state.tree,
                &view.expanded,
                view.sort_by,
                view.sort_desc,
                &view.filter,
                &state.process_table,
            );
            tree_view::draw_with_focus(
                f,
                main_area,
                &lines,
                view.cursor,
                view.focus == PaneFocus::Files,
                &state.event_log,
                &view.filter,
                &state.process_table,
            );
        }
    }

    let rate = state.global_rate.rate_bps();
    footer::draw(
        f,
        chunks[3],
        &state.tree.root.agg_stats,
        rate,
        footer::Diagnostics {
            total_events: state.total_events,
            dropped_events: state.dropped_events,
            attribution_failures: state.attribution_failures,
            failed_io_events: state.failed_io_events,
            zero_byte_io_events: state.zero_byte_io_events,
        },
    );

    // Help overlay
    if view.show_help {
        draw_help_overlay(f);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyAreas {
    columns: Rect,
    main: Rect,
    processes: Option<Rect>,
    process_borders: Borders,
}

fn compute_body_areas(area: Rect, show_processes: bool) -> BodyAreas {
    if !show_processes {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);
        return BodyAreas {
            columns: rows[0],
            main: rows[1],
            processes: None,
            process_borders: Borders::NONE,
        };
    }

    if area.width >= 110 {
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(panes[0]);
        BodyAreas {
            columns: rows[0],
            main: rows[1],
            processes: Some(panes[1]),
            process_borders: Borders::LEFT,
        }
    } else {
        let panes = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(panes[0]);
        BodyAreas {
            columns: rows[0],
            main: rows[1],
            processes: Some(panes[1]),
            process_borders: Borders::TOP,
        }
    }
}

fn visible_processes<'a>(
    state: &'a AppState,
    view: &ViewState,
) -> Vec<&'a crate::process::ProcessInfo> {
    let matching = filter::matching_pids(&state.tree, &view.filter, &state.process_table);
    state
        .process_table
        .sorted(view.process_sort, view.process_sort_desc)
        .into_iter()
        .filter(|process| matching.contains(&process.pid))
        .collect()
}

fn draw_process_panel(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &AppState,
    view: &ViewState,
    borders: Borders,
) {
    let focused = view.focus == PaneFocus::Processes;
    let sort_arrow = if view.process_sort_desc { "▼" } else { "▲" };
    let block = Block::default()
        .title(format!(
            " {}Processes {}{} ",
            if focused { "▶ " } else { "" },
            view.process_sort.label(),
            sort_arrow
        ))
        .title_style(Style::default().fg(if focused {
            Color::LightMagenta
        } else {
            Color::DarkGray
        }))
        .border_style(Style::default().fg(if focused {
            Color::Magenta
        } else {
            Color::DarkGray
        }))
        .borders(borders);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let top = visible_processes(state, view);
    let comm_width = process_name_width(inner.width);
    let visible_height = inner.height as usize;
    if top.is_empty() {
        let message = if view.filter.is_empty() {
            " (no process activity recorded)"
        } else {
            " (no processes match the filter)"
        };
        f.render_widget(
            Paragraph::new(layout::truncate_display(message, usize::from(inner.width)))
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    let start = view
        .process_cursor
        .saturating_add(1)
        .saturating_sub(visible_height);
    let items: Vec<Line> = top
        .into_iter()
        .skip(start)
        .take(visible_height)
        .enumerate()
        .map(|(offset, p)| {
            let index = start + offset;
            let selected = index == view.process_cursor;
            let style = Style::default();
            let identity = match &p.container {
                Some(container) => format!("{}@{container}", p.comm),
                None => p.comm.clone(),
            };
            let (metric, metric_color) = process_metric(p, view.process_sort);
            let mut spans = vec![
                Span::styled(format!("{:>6} ", p.pid), style.fg(Color::Yellow)),
                Span::styled(
                    format!("{} ", layout::fit_display(&identity, comm_width)),
                    style.fg(Color::White),
                ),
                Span::styled(
                    layout::fit_display(&metric, PROCESS_METRIC_WIDTH),
                    style.fg(metric_color),
                ),
            ];
            if selected {
                if focused {
                    layout::highlight_selected(&mut spans);
                } else {
                    layout::highlight_inactive_selected(&mut spans);
                }
            }
            Line::from(spans)
        })
        .collect();

    let paragraph = Paragraph::new(items);
    f.render_widget(paragraph, inner);
}

fn draw_help_overlay(f: &mut ratatui::Frame) {
    let area = f.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    let width = area.width.saturating_sub(2).clamp(1, 52);
    let height = area.height.saturating_sub(2).clamp(1, 23);
    let popup_area = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    f.render_widget(Clear, popup_area);

    let entries = [
        " j/↓        Move down",
        " k/↑        Move up",
        " Enter/→/l  Drill in / expand",
        " ←/h/Bksp   Go up / collapse",
        " Tab        Toggle flat/tree view",
        " s / S      Sort / reverse sort",
        " p / P      Toggle / focus processes",
        " Enter      Filter selected process",
        " /          Edit activity filter",
        " Esc        Cancel editor / leave pane / clear filter",
        " r          Reset all counters",
        " g/G        Jump to top/bottom",
        " PgUp/PgDn  Scroll one page",
        " ?          This help",
        " q/Ctrl-C   Quit",
    ];
    let inner_height = usize::from(height.saturating_sub(2));
    let mut help_text = Vec::new();
    if inner_height > 1 {
        help_text.push(Line::from(Span::styled(
            " ncda - Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
    }
    let entry_slots = inner_height.saturating_sub(help_text.len() + 1);
    help_text.extend(
        entries
            .iter()
            .take(entry_slots)
            .map(|entry| Line::from(*entry)),
    );
    if inner_height > 0 {
        help_text.push(Line::from(Span::styled(
            " Press any key to close",
            Style::default().fg(Color::Yellow),
        )));
    }

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));
    f.render_widget(
        Paragraph::new(help_text)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup_area,
    );
}

const PROCESS_METRIC_WIDTH: usize = 10;

fn process_name_width(area_width: u16) -> usize {
    // PID and separator consume 7 cells; metric and separator consume 11.
    usize::from(area_width).saturating_sub(7 + 1 + PROCESS_METRIC_WIDTH)
}

fn process_metric(
    process: &crate::process::ProcessInfo,
    sort: crate::process::ProcessSort,
) -> (String, Color) {
    use crate::process::ProcessSort;

    match sort {
        ProcessSort::TotalBytes => (
            format!("T:{}", footer::format_bytes(process.stats.total_bytes())),
            Color::Yellow,
        ),
        ProcessSort::ReadBytes => (
            format!("R:{}", footer::format_bytes(process.stats.read_bytes)),
            Color::Cyan,
        ),
        ProcessSort::WriteBytes => (
            format!("W:{}", footer::format_bytes(process.stats.write_bytes)),
            Color::Red,
        ),
        ProcessSort::Operations => (
            format!("O:{}", footer::format_count(process.stats.total_ops())),
            Color::Yellow,
        ),
        ProcessSort::Latency => (
            format!(
                "L:{}",
                footer::format_latency(process.stats.avg_latency_ns())
            ),
            Color::Green,
        ),
        ProcessSort::Pid => (format!("PID:{}", process.pid), Color::Yellow),
        ProcessSort::Name => ("NAME".to_string(), Color::White),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ratatui::backend::TestBackend;

    use crate::model::{NodeStats, OpKind, SortBy};
    use crate::process::{ProcessInfo, ProcessSort};

    use super::*;

    struct RecordingRestore(Arc<AtomicUsize>);

    impl RestoreTerminal for RecordingRestore {
        fn restore(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn terminal_guard_restores_on_error_and_panic() {
        let restorations = Arc::new(AtomicUsize::new(0));
        let error_path = || -> Result<(), &'static str> {
            let _guard = TerminalRestoreGuard {
                restorer: RecordingRestore(Arc::clone(&restorations)),
            };
            Err("render failed")
        };
        assert!(error_path().is_err());
        assert_eq!(restorations.load(Ordering::SeqCst), 1);

        let panic_result = std::panic::catch_unwind({
            let restorations = Arc::clone(&restorations);
            move || {
                let _guard = TerminalRestoreGuard {
                    restorer: RecordingRestore(restorations),
                };
                panic!("input failed");
            }
        });
        assert!(panic_result.is_err());
        assert_eq!(restorations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn process_name_column_fills_wide_panels() {
        let width = 60;
        assert_eq!(18 + process_name_width(width), usize::from(width));
    }

    #[test]
    fn process_panel_moves_below_narrow_tables() {
        let narrow = compute_body_areas(Rect::new(0, 0, 80, 20), true);
        assert_eq!(narrow.process_borders, Borders::TOP);
        assert!(narrow.processes.unwrap().y > narrow.main.y);

        let wide = compute_body_areas(Rect::new(0, 0, 140, 20), true);
        assert_eq!(wide.process_borders, Borders::LEFT);
        assert!(wide.processes.unwrap().x > wide.main.x);
        assert!(
            visible_page_height(80, 20, true, PaneFocus::Files)
                < visible_page_height(80, 20, false, PaneFocus::Files)
        );
        assert!(
            visible_page_height(80, 20, true, PaneFocus::Processes)
                < visible_page_height(80, 20, true, PaneFocus::Files)
        );
    }

    #[test]
    fn selection_reconciles_by_path_after_live_sorting() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        state.tree.record("/a", 1, OpKind::Read, 10, 1);
        state.tree.record("/b", 1, OpKind::Read, 20, 1);
        let mut view = ViewState::new();
        view.sort_by = SortBy::TotalBytes;
        view.sort_desc = true;
        view.cursor = 1;
        let mut selected = Some("/a".to_string());

        state.tree.record("/a", 1, OpKind::Read, 20, 1);
        reconcile_file_selection(&state, &mut view, &mut selected);
        assert_eq!(selection_identity(&state, &view).as_deref(), Some("/a"));
        assert_eq!(view.cursor, 0);
    }

    #[test]
    fn short_help_overlay_keeps_close_hint_visible() {
        let backend = TestBackend::new(32, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(draw_help_overlay).unwrap();
        let mut rendered = String::new();
        for y in 0..8 {
            for x in 0..32 {
                rendered.push_str(terminal.backend().buffer()[(x, y)].symbol());
            }
        }
        assert!(rendered.contains("Press any key to close"));
    }

    #[test]
    fn process_metric_matches_current_sort() {
        let process = ProcessInfo {
            pid: 42,
            comm: "worker".into(),
            container: None,
            stats: NodeStats {
                read_bytes: 1024,
                write_bytes: 2048,
                read_ops: 3,
                write_ops: 4,
                ..NodeStats::default()
            },
        };
        assert_eq!(process_metric(&process, ProcessSort::ReadBytes).0, "R:1.0K");
        assert_eq!(
            process_metric(&process, ProcessSort::WriteBytes).0,
            "W:2.0K"
        );
        assert_eq!(process_metric(&process, ProcessSort::Operations).0, "O:7");
    }
}
