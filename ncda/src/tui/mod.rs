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

use crossterm::event::{self, Event, KeyEventKind};
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

/// Run the TUI event loop.
pub fn run(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut view = ViewState::new();
    let tick_rate = Duration::from_millis(250);

    loop {
        // Render
        {
            let state = state.lock().unwrap();
            terminal.draw(|f| draw(f, &state, &view))?;
        }

        // Poll for input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Handle flat-mode drill-in specially (needs tree access)
                if matches!(
                    key.code,
                    crossterm::event::KeyCode::Enter
                        | crossterm::event::KeyCode::Right
                        | crossterm::event::KeyCode::Char('l')
                ) && view.mode == ViewMode::Flat
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
                        }
                    }
                    continue;
                }

                let flat_count = {
                    let state = state.lock().unwrap();
                    flat_view::visible_rows(
                        &state.tree,
                        &view.cwd,
                        view.sort_by,
                        view.sort_desc,
                        &view.filter,
                        &state.process_table,
                    )
                    .len()
                };

                let tree_lines = {
                    let state = state.lock().unwrap();
                    tree_view::flatten(
                        &state.tree,
                        &view.expanded,
                        view.sort_by,
                        view.sort_desc,
                        &view.filter,
                        &state.process_table,
                    )
                };

                let process_pids = {
                    let state = state.lock().unwrap();
                    visible_processes(&state, &view)
                        .into_iter()
                        .map(|process| process.pid)
                        .collect::<Vec<_>>()
                };
                view.reconcile_process_selection(&process_pids);

                let mut should_reset = false;
                let quit = input::handle_key(
                    key,
                    &mut view,
                    flat_count,
                    &tree_lines,
                    &process_pids,
                    &mut should_reset,
                );
                let updated_process_pids = {
                    let state = state.lock().unwrap();
                    visible_processes(&state, &view)
                        .into_iter()
                        .map(|process| process.pid)
                        .collect::<Vec<_>>()
                };
                view.reconcile_process_selection(&updated_process_pids);

                if should_reset {
                    let mut state = state.lock().unwrap();
                    state.reset();
                    view.cursor = 0;
                }

                if quit {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
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
            tree_view::draw(
                f,
                main_area,
                &lines,
                view.cursor,
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
        state.total_events,
        state.dropped_events,
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
    let sort_arrow = if view.process_sort_desc { "▼" } else { "▲" };
    let block = Block::default()
        .title(format!(
            " Processes {}{} ",
            view.process_sort.label(),
            sort_arrow
        ))
        .borders(borders);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let top = visible_processes(state, view);
    let comm_width = process_name_width(inner.width);
    let visible_height = inner.height as usize;
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
            let selected = view.focus == PaneFocus::Processes && index == view.process_cursor;
            let style = if selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let identity = match &p.container {
                Some(container) => format!("{}@{container}", p.comm),
                None => p.comm.clone(),
            };
            Line::from(vec![
                Span::styled(format!("{:>6} ", p.pid), style.fg(Color::Yellow)),
                Span::styled(
                    format!("{} ", layout::fit_display(&identity, comm_width)),
                    style.fg(Color::White),
                ),
                Span::styled(
                    format!("R:{:>6}", footer::format_bytes(p.stats.read_bytes)),
                    style.fg(Color::Cyan),
                ),
                Span::styled(" ", style),
                Span::styled(
                    format!("W:{:>6}", footer::format_bytes(p.stats.write_bytes)),
                    style.fg(Color::Red),
                ),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(items);
    f.render_widget(paragraph, inner);
}

fn draw_help_overlay(f: &mut ratatui::Frame) {
    let area = f.area();
    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 22u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let popup_area = Rect::new(x, y, width, height);

    f.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled(
            " ncda - Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(" j/↓        Move down"),
        Line::from(" k/↑        Move up"),
        Line::from(" Enter/→/l  Drill in / Expand"),
        Line::from(" ←/h/Bksp   Go up / Collapse"),
        Line::from(" Tab        Toggle flat/tree view"),
        Line::from(" s          Cycle sort mode"),
        Line::from(" S          Reverse sort direction"),
        Line::from(" p          Toggle process panel"),
        Line::from(" P          Focus process panel"),
        Line::from(" Enter      Filter selected process"),
        Line::from(" /          Filter activity"),
        Line::from(" Esc        Clear active filter"),
        Line::from(" r          Reset all counters"),
        Line::from(" g/Home     Jump to top"),
        Line::from(" G/End      Jump to bottom"),
        Line::from(" PgUp/PgDn  Scroll page"),
        Line::from(" ?          This help"),
        Line::from(" q          Quit"),
        Line::from(""),
        Line::from(" Press any key to close"),
    ];

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));

    let paragraph = Paragraph::new(help_text)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, popup_area);
}

fn process_name_width(area_width: u16) -> usize {
    // PID, separators, and the read/write metrics consume 25 columns.
    usize::from(area_width).saturating_sub(25).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_name_column_fills_wide_panels() {
        let width = 60;
        assert_eq!(25 + process_name_width(width), usize::from(width));
    }

    #[test]
    fn process_panel_moves_below_narrow_tables() {
        let narrow = compute_body_areas(Rect::new(0, 0, 80, 20), true);
        assert_eq!(narrow.process_borders, Borders::TOP);
        assert!(narrow.processes.unwrap().y > narrow.main.y);

        let wide = compute_body_areas(Rect::new(0, 0, 140, 20), true);
        assert_eq!(wide.process_borders, Borders::LEFT);
        assert!(wide.processes.unwrap().x > wide.main.x);
    }
}
