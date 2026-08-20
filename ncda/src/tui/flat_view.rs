use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{FileTree, NodeStats, SortBy};
use crate::process::ProcessTable;
use crate::rate::EventLog;
use crate::tui::app::ViewState;
use crate::tui::filter::{filtered_stats, join_path, FilterQuery};
use crate::tui::footer::{format_bytes, format_bytes_raw, format_count, format_latency};
use crate::tui::layout::{
    activity_cell, fit_display, highlight_selected, TableColumns, WidthProfile,
};

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

pub fn draw(
    f: &mut Frame,
    area: Rect,
    tree: &FileTree,
    processes: &ProcessTable,
    event_log: &EventLog,
    view: &ViewState,
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
        f.render_widget(
            List::new(vec![ListItem::new(message)]).block(Block::default().borders(Borders::NONE)),
            area,
        );
        return;
    }

    let columns = TableColumns::for_width(area.width);
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
            let rate = event_log.rate_for_prefix(&row.path, &view.filter, processes);
            let rate_str = if rate > 0.0 {
                format!("{}/s", format_bytes_raw(rate as u64))
            } else {
                "0B/s".to_string()
            };
            let selected = index == view.cursor;
            let style = Style::default();
            let mut spans = vec![
                Span::styled(prefix, style),
                Span::styled(
                    fit_display(&name, columns.name),
                    style.fg(if row.is_dir {
                        Color::Blue
                    } else {
                        Color::White
                    }),
                ),
            ];
            match columns.profile {
                WidthProfile::Full => {
                    spans.extend([
                        Span::styled(
                            activity_cell(row.stats.total_bytes(), max_bytes, columns.graph),
                            style.fg(Color::Cyan),
                        ),
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
                        latency_span(&row.stats, style),
                    ]);
                }
                WidthProfile::Compact => {
                    spans.extend([
                        Span::styled(
                            activity_cell(row.stats.total_bytes(), max_bytes, columns.graph),
                            style.fg(Color::Cyan),
                        ),
                        Span::styled(
                            format!("  {:>8}", format_bytes(row.stats.total_bytes())),
                            style.fg(Color::Yellow),
                        ),
                        Span::styled(format!("  {:>8}", rate_str), style.fg(Color::Green)),
                    ]);
                }
                WidthProfile::Minimal => spans.push(Span::styled(
                    format!("  {:>8}", format_bytes(row.stats.total_bytes())),
                    style.fg(Color::Yellow),
                )),
            }
            if selected {
                highlight_selected(&mut spans);
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(view.cursor.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(items).block(Block::default().borders(Borders::NONE)),
        area,
        &mut list_state,
    );
}

fn latency_span(stats: &NodeStats, style: Style) -> Span<'static> {
    if stats.avg_latency_ns() == 0 {
        return Span::styled(" ".repeat(9), style);
    }
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
}

pub fn draw_columns(f: &mut Frame, area: Rect) {
    let columns = TableColumns::for_width(area.width);
    let mut spans = vec![Span::styled(
        format!("  {}", fit_display("Name", columns.name)),
        Style::default().add_modifier(Modifier::DIM),
    )];
    match columns.profile {
        WidthProfile::Full => spans.extend([
            Span::styled(
                fit_display("Activity", columns.graph),
                Style::default().add_modifier(Modifier::DIM),
            ),
            Span::styled("    Read   ", Style::default().add_modifier(Modifier::DIM)),
            Span::styled("   Write   ", Style::default().add_modifier(Modifier::DIM)),
            Span::styled("     Ops", Style::default().add_modifier(Modifier::DIM)),
            Span::styled("      Rate", Style::default().add_modifier(Modifier::DIM)),
            Span::styled("  Latency", Style::default().add_modifier(Modifier::DIM)),
        ]),
        WidthProfile::Compact => spans.extend([
            Span::styled(
                fit_display("Activity", columns.graph),
                Style::default().add_modifier(Modifier::DIM),
            ),
            Span::styled("     Total", Style::default().add_modifier(Modifier::DIM)),
            Span::styled("      Rate", Style::default().add_modifier(Modifier::DIM)),
        ]),
        WidthProfile::Minimal => spans.push(Span::styled(
            "     Total",
            Style::default().add_modifier(Modifier::DIM),
        )),
    }
    f.render_widget(ratatui::widgets::Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpKind;

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
