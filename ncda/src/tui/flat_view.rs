use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{FileTree, NodeStats, SortBy};
use crate::process::ProcessTable;
use crate::tui::app::ViewState;
use crate::tui::filter::{filtered_stats, join_path, FilterQuery};
use crate::tui::footer::{format_bytes, format_count, format_latency};

// Everything except the flexible name column: icon, graph, and metrics.
const FIXED_COLUMNS_WIDTH: usize = 61;

#[derive(Debug, Clone)]
pub struct FlatRow {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub stats: NodeStats,
}

pub fn visible_rows(
    tree: &FileTree,
    cwd: &[String],
    sort_by: SortBy,
    sort_desc: bool,
    filter: &FilterQuery,
    processes: &ProcessTable,
) -> Vec<FlatRow> {
    let Some(node) = tree.get_node(cwd) else {
        return Vec::new();
    };
    let parent_path = if cwd.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", cwd.join("/"))
    };

    let mut rows: Vec<FlatRow> = node
        .children
        .values()
        .filter_map(|child| {
            let path = join_path(&parent_path, &child.name);
            let stats = filtered_stats(child, &path, filter, processes)?;
            Some(FlatRow {
                name: child.name.clone(),
                path,
                is_dir: child.is_dir,
                stats,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let order = match sort_by {
            SortBy::TotalBytes => a.stats.total_bytes().cmp(&b.stats.total_bytes()),
            SortBy::ReadBytes => a.stats.read_bytes.cmp(&b.stats.read_bytes),
            SortBy::WriteBytes => a.stats.write_bytes.cmp(&b.stats.write_bytes),
            SortBy::Frequency => a.stats.total_ops().cmp(&b.stats.total_ops()),
            SortBy::Latency => a.stats.avg_latency_ns().cmp(&b.stats.avg_latency_ns()),
            SortBy::Name => a.name.cmp(&b.name),
        };
        let order = if sort_desc { order.reverse() } else { order };
        order.then_with(|| a.name.cmp(&b.name))
    });
    rows
}

/// Render the flat (ncdu-style) view of a single directory's children.
pub fn draw(
    f: &mut Frame,
    area: Rect,
    tree: &FileTree,
    processes: &ProcessTable,
    view: &ViewState,
    rate_fn: impl Fn(&str) -> f64,
) {
    let rows = visible_rows(
        tree,
        &view.cwd,
        view.sort_by,
        view.sort_desc,
        &view.filter,
        processes,
    );
    if rows.is_empty() {
        let message = if view.filter.is_empty() {
            "  (no file activity recorded)"
        } else {
            "  (no activity matches the filter)"
        };
        let empty =
            List::new(vec![ListItem::new(message)]).block(Block::default().borders(Borders::NONE));
        f.render_widget(empty, area);
        return;
    }

    let name_width = name_column_width(area.width);
    let max_bytes = rows
        .iter()
        .map(|row| row.stats.total_bytes())
        .max()
        .unwrap_or(1)
        .max(1);

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let prefix = if row.is_dir { "▸ " } else { "  " };
            let name = if row.is_dir {
                format!("{}/", row.name)
            } else {
                row.name.clone()
            };
            let bar_width = 10;
            let fraction = row.stats.total_bytes() as f64 / max_bytes as f64;
            let filled = (fraction * bar_width as f64) as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
            let rate = rate_fn(&row.path);
            let rate_str = if rate > 0.0 {
                format!("{}/s", crate::tui::footer::format_bytes_raw(rate as u64))
            } else {
                "0B/s".to_string()
            };
            let style = if index == view.cursor {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!(
                        "{:<width$}",
                        truncate(&name, name_width),
                        width = name_width
                    ),
                    style.fg(if row.is_dir {
                        Color::Blue
                    } else {
                        Color::White
                    }),
                ),
                Span::styled(bar, style.fg(Color::Cyan)),
                Span::styled(
                    format!("  R:{:>7}", format_bytes(row.stats.read_bytes)),
                    style.fg(Color::Cyan),
                ),
                Span::styled(
                    format!("  W:{:>7}", format_bytes(row.stats.write_bytes)),
                    style.fg(Color::Red),
                ),
                Span::styled(
                    format!("  {:>6}", format_count(row.stats.total_ops())),
                    style.fg(Color::Yellow),
                ),
                Span::styled(format!("  {:>8}", rate_str), style.fg(Color::Green)),
                if row.stats.avg_latency_ns() > 0 {
                    Span::styled(
                        format!("  {:>7}", format_latency(row.stats.avg_latency_ns())),
                        style.fg(if row.stats.avg_latency_ns() > 10_000_000 {
                            Color::Red
                        } else if row.stats.avg_latency_ns() > 1_000_000 {
                            Color::Yellow
                        } else {
                            Color::White
                        }),
                    )
                } else {
                    Span::styled(" ".repeat(9), style)
                },
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(view.cursor.min(rows.len().saturating_sub(1))));
    let list = List::new(items).block(Block::default().borders(Borders::NONE));
    f.render_stateful_widget(list, area, &mut list_state);
}

pub fn draw_columns(f: &mut Frame, area: Rect) {
    let name_width = name_column_width(area.width);
    let line = Line::from(vec![
        Span::styled(
            format!("  {:<width$}", "Name", width = name_width),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!("{:<10}", "Graph"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled("    Read   ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("   Write   ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("     Ops", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("      Rate", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("  Latency", Style::default().add_modifier(Modifier::DIM)),
    ]);
    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
}

fn name_column_width(area_width: u16) -> usize {
    usize::from(area_width)
        .saturating_sub(FIXED_COLUMNS_WIDTH)
        .max(1)
}

fn truncate(s: &str, max: usize) -> String {
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
    use crate::model::OpKind;

    #[test]
    fn flexible_name_column_fills_wide_areas() {
        let width = 120;
        let rendered_width = 2 + name_column_width(width) + 10 + 11 + 11 + 8 + 10 + 9;
        assert_eq!(rendered_width, usize::from(width));
    }

    #[test]
    fn truncation_is_unicode_safe() {
        assert_eq!(truncate("données", 5), "donn~");
    }

    #[test]
    fn visible_rows_use_the_same_filter_and_sort_projection() {
        let mut tree = FileTree::new();
        tree.record("/var/a", 1, OpKind::Read, 5, 1);
        tree.record("/var/b", 2, OpKind::Read, 9, 1);
        let mut processes = ProcessTable::new();
        processes.record(1, OpKind::Read, 5, 1);
        processes.record(2, OpKind::Read, 9, 1);
        let rows = visible_rows(
            &tree,
            &["var".to_string()],
            SortBy::TotalBytes,
            true,
            &FilterQuery::parse("pid:1").unwrap(),
            &processes,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "a");
    }
}
