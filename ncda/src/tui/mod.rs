pub mod app;
pub mod flat_view;
pub mod footer;
pub mod header;
pub mod input;
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

use self::app::{AppState, ViewMode, ViewState};

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
                {
                    let state = state.lock().unwrap();
                    if let Some(node) = state.tree.get_node(&view.cwd) {
                        let children = node.sorted_children(view.sort_by, view.sort_desc);
                        if let Some(child) = children.get(view.cursor) {
                            if child.is_dir {
                                view.cwd.push(child.name.clone());
                                view.cursor = 0;
                            }
                        }
                    }
                    continue;
                }

                let flat_count = {
                    let state = state.lock().unwrap();
                    flat_view::child_count(&state.tree, &view.cwd)
                };

                let tree_lines = {
                    let state = state.lock().unwrap();
                    tree_view::flatten(&state.tree, &view.expanded, view.sort_by, view.sort_desc)
                };

                let mut should_reset = false;
                let quit =
                    input::handle_key(key, &mut view, flat_count, &tree_lines, &mut should_reset);

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

    let (columns_area, main_area) = if view.show_processes {
        // Split the complete table body so its header stays aligned with the
        // main rows and the process panel can use the full body height.
        let body_area = Rect::new(
            chunks[1].x,
            chunks[1].y,
            chunks[1].width,
            chunks[1].height.saturating_add(chunks[2].height),
        );
        let body_columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(body_area);
        let main_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(body_columns[0]);

        draw_process_panel(f, body_columns[1], state);
        (main_rows[0], main_rows[1])
    } else {
        (chunks[1], chunks[2])
    };

    match view.mode {
        ViewMode::Flat => {
            flat_view::draw_columns(f, columns_area);
            flat_view::draw(f, main_area, &state.tree, view, |prefix| {
                state.event_log.rate_for_prefix(prefix)
            });
        }
        ViewMode::Tree => {
            tree_view::draw_columns(f, columns_area);
            let lines =
                tree_view::flatten(&state.tree, &view.expanded, view.sort_by, view.sort_desc);
            tree_view::draw(f, main_area, &lines, view.cursor);
        }
    }

    let rate = state.global_rate.clone_rate();
    footer::draw(
        f,
        chunks[3],
        &state.tree.root.agg_stats,
        rate,
        state.total_events,
    );

    // Help overlay
    if view.show_help {
        draw_help_overlay(f);
    }
}

fn draw_process_panel(f: &mut ratatui::Frame, area: Rect, state: &AppState) {
    let block = Block::default().title(" Processes ").borders(Borders::LEFT);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let top = state.process_table.top_by_bytes(inner.height as usize);
    let comm_width = process_name_width(inner.width);
    let items: Vec<Line> = top
        .iter()
        .map(|p| {
            Line::from(vec![
                Span::styled(format!("{:>6} ", p.pid), Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!(
                        "{:<width$} ",
                        truncate_str(&p.comm, comm_width),
                        width = comm_width
                    ),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("R:{:>6}", footer::format_bytes(p.stats.read_bytes)),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("W:{:>6}", footer::format_bytes(p.stats.write_bytes)),
                    Style::default().fg(Color::Red),
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
    let height = 18u16.min(area.height.saturating_sub(4));
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

fn truncate_str(s: &str, max: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else if max > 1 {
        let prefix: String = s.chars().take(max - 1).collect();
        format!("{prefix}~")
    } else {
        "~".to_string()
    }
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
    fn process_name_truncation_is_unicode_safe() {
        assert_eq!(truncate_str("téléchargement", 6), "téléc~");
    }
}
