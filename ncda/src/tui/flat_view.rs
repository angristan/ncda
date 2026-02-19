use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::FileTree;
use crate::tui::app::ViewState;
use crate::tui::footer::{format_bytes, format_count, format_latency};

/// Render the flat (ncdu-style) view of a single directory's children.
pub fn draw(
    f: &mut Frame,
    area: Rect,
    tree: &FileTree,
    view: &ViewState,
    rate_fn: impl Fn(&str) -> f64,
) {
    let node = match tree.get_node(&view.cwd) {
        Some(n) => n,
        None => {
            // Current directory doesn't exist in the tree yet
            let empty =
                List::new(Vec::<ListItem>::new()).block(Block::default().borders(Borders::NONE));
            f.render_widget(empty, area);
            return;
        }
    };

    let children = node.sorted_children(view.sort_by, view.sort_desc);

    if children.is_empty() {
        let empty = List::new(vec![ListItem::new("  (no file activity recorded)")])
            .block(Block::default().borders(Borders::NONE));
        f.render_widget(empty, area);
        return;
    }

    // Find the maximum total bytes among children for the bar graph
    let max_bytes = children
        .iter()
        .map(|c| c.agg_stats.total_bytes())
        .max()
        .unwrap_or(1)
        .max(1);

    let items: Vec<ListItem> = children
        .iter()
        .enumerate()
        .map(|(i, child)| {
            let prefix = if child.is_dir { "▸ " } else { "  " };
            let name = if child.is_dir {
                format!("{}/", child.name)
            } else {
                child.name.clone()
            };

            // Bar graph (10 chars wide)
            let bar_width = 10;
            let fraction = child.agg_stats.total_bytes() as f64 / max_bytes as f64;
            let filled = (fraction * bar_width as f64) as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);

            // Rate for this path
            let child_path = if view.cwd.is_empty() {
                format!("/{}", child.name)
            } else {
                format!("/{}/{}", view.cwd.join("/"), child.name)
            };
            let rate = rate_fn(&child_path);
            let rate_str = if rate > 0.0 {
                format!("{}/s", crate::tui::footer::format_bytes_raw(rate as u64))
            } else {
                "0B/s".to_string()
            };

            let stats = &child.agg_stats;
            let is_selected = i == view.cursor;

            let style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!("{:<20}", truncate(&name, 20)),
                    style.fg(if child.is_dir {
                        Color::Blue
                    } else {
                        Color::White
                    }),
                ),
                Span::styled(bar, style.fg(Color::Cyan)),
                Span::styled(
                    format!("  R:{:>7}", format_bytes(stats.read_bytes)),
                    style.fg(Color::Cyan),
                ),
                Span::styled(
                    format!("  W:{:>7}", format_bytes(stats.write_bytes)),
                    style.fg(Color::Red),
                ),
                Span::styled(
                    format!("  {:>6}", format_count(stats.total_ops())),
                    style.fg(Color::Yellow),
                ),
                Span::styled(format!("  {:>8}", rate_str), style.fg(Color::Green)),
                if stats.avg_latency_ns() > 0 {
                    Span::styled(
                        format!("  {:>7}", format_latency(stats.avg_latency_ns())),
                        style.fg(if stats.avg_latency_ns() > 10_000_000 {
                            Color::Red
                        } else if stats.avg_latency_ns() > 1_000_000 {
                            Color::Yellow
                        } else {
                            Color::White
                        }),
                    )
                } else {
                    Span::raw("")
                },
            ]);

            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(view.cursor));

    let list = List::new(items).block(Block::default().borders(Borders::NONE));
    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw column headers for the flat view.
pub fn draw_columns(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            format!("  {:<20}", "Name"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!("{:<10}", "Graph"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled("    Read   ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("   Write   ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("    Ops", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("      Rate", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("  Latency", Style::default().add_modifier(Modifier::DIM)),
    ]);

    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max - 1])
    }
}

/// Get the number of children of the current directory.
pub fn child_count(tree: &FileTree, cwd: &[String]) -> usize {
    tree.get_node(cwd).map(|n| n.children.len()).unwrap_or(0)
}
