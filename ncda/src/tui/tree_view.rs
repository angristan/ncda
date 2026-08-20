use std::collections::HashSet;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{FileTree, NodeStats, SortBy, TreeNode};
use crate::process::ProcessTable;
use crate::rate::EventLog;
use crate::tui::filter::{filtered_stats, join_path, FilterQuery};
use crate::tui::footer::{format_bytes, format_bytes_raw, format_count, format_latency};
use crate::tui::layout::{activity_cell, fit_display, TableColumns, WidthProfile};

pub struct TreeLine {
    pub depth: usize,
    pub path: Vec<String>,
    pub display_path: String,
    pub name: String,
    pub is_dir: bool,
    pub is_expanded: bool,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub total_ops: u64,
    pub avg_latency_ns: u64,
    pub total_bytes: u64,
}

pub fn flatten(
    tree: &FileTree,
    expanded: &HashSet<Vec<String>>,
    sort_by: SortBy,
    sort_desc: bool,
    filter: &FilterQuery,
    processes: &ProcessTable,
) -> Vec<TreeLine> {
    let mut lines = Vec::new();
    let mut path = Vec::new();
    flatten_recurse(
        &tree.root, &mut path, "/", 0, expanded, sort_by, sort_desc, filter, processes, &mut lines,
    );
    lines
}

#[allow(clippy::too_many_arguments)]
fn flatten_recurse(
    node: &TreeNode,
    path: &mut Vec<String>,
    display_path: &str,
    depth: usize,
    expanded: &HashSet<Vec<String>>,
    sort_by: SortBy,
    sort_desc: bool,
    filter: &FilterQuery,
    processes: &ProcessTable,
    lines: &mut Vec<TreeLine>,
) {
    let mut children: Vec<(&TreeNode, String, NodeStats)> = node
        .children
        .values()
        .filter_map(|child| {
            let child_path = join_path(display_path, &child.name);
            let stats = filtered_stats(child, &child_path, filter, processes)?;
            Some((child, child_path, stats))
        })
        .collect();
    children.sort_by(|(a, _, a_stats), (b, _, b_stats)| {
        let order = match sort_by {
            SortBy::TotalBytes => a_stats.total_bytes().cmp(&b_stats.total_bytes()),
            SortBy::ReadBytes => a_stats.read_bytes.cmp(&b_stats.read_bytes),
            SortBy::WriteBytes => a_stats.write_bytes.cmp(&b_stats.write_bytes),
            SortBy::Frequency => a_stats.total_ops().cmp(&b_stats.total_ops()),
            SortBy::Latency => a_stats.avg_latency_ns().cmp(&b_stats.avg_latency_ns()),
            SortBy::Name => a.name.cmp(&b.name),
        };
        let order = if sort_desc { order.reverse() } else { order };
        order.then_with(|| a.name.cmp(&b.name))
    });

    for (child, child_display_path, stats) in children {
        path.push(child.name.clone());
        let is_expanded = expanded.contains(path);
        lines.push(TreeLine {
            depth,
            path: path.clone(),
            display_path: child_display_path.clone(),
            name: child.name.clone(),
            is_dir: child.is_dir,
            is_expanded,
            read_bytes: stats.read_bytes,
            write_bytes: stats.write_bytes,
            total_ops: stats.total_ops(),
            avg_latency_ns: stats.avg_latency_ns(),
            total_bytes: stats.total_bytes(),
        });
        if child.is_dir && is_expanded {
            flatten_recurse(
                child,
                path,
                &child_display_path,
                depth + 1,
                expanded,
                sort_by,
                sort_desc,
                filter,
                processes,
                lines,
            );
        }
        path.pop();
    }
}

pub fn draw(
    f: &mut Frame,
    area: Rect,
    lines: &[TreeLine],
    cursor: usize,
    event_log: &EventLog,
    filter: &FilterQuery,
    processes: &ProcessTable,
) {
    if lines.is_empty() {
        f.render_widget(
            List::new(vec![ListItem::new("  (no activity matches)")])
                .block(Block::default().borders(Borders::NONE)),
            area,
        );
        return;
    }

    let columns = TableColumns::for_width(area.width);
    let tree_name_width = columns.name + 2;
    let max_bytes = lines
        .iter()
        .map(|line| line.total_bytes)
        .max()
        .unwrap_or(1)
        .max(1);
    let items: Vec<ListItem> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let indent_width = (line.depth * 2).min(tree_name_width.saturating_sub(3));
            let icon = if line.is_dir {
                if line.is_expanded {
                    "▾ "
                } else {
                    "▸ "
                }
            } else {
                "  "
            };
            let name = if line.is_dir {
                format!("{}/", line.name)
            } else {
                line.name.clone()
            };
            let name_width = tree_name_width.saturating_sub(indent_width + 2).max(1);
            let style = if index == cursor {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let rate = event_log.rate_for_prefix(&line.display_path, filter, processes);
            let rate_str = if rate > 0.0 {
                format!("{}/s", format_bytes_raw(rate as u64))
            } else {
                "0B/s".to_string()
            };
            let mut spans = vec![
                Span::styled(" ".repeat(indent_width), style),
                Span::styled(icon, style),
                Span::styled(
                    fit_display(&name, name_width),
                    style.fg(if line.is_dir {
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
                            activity_cell(line.total_bytes, max_bytes, columns.graph),
                            style.fg(Color::Cyan),
                        ),
                        Span::styled(
                            format!("  R:{:>7}", format_bytes(line.read_bytes)),
                            style.fg(Color::Cyan),
                        ),
                        Span::styled(
                            format!("  W:{:>7}", format_bytes(line.write_bytes)),
                            style.fg(Color::Red),
                        ),
                        Span::styled(
                            format!("  {:>6}", format_count(line.total_ops)),
                            style.fg(Color::Yellow),
                        ),
                        Span::styled(format!("  {:>8}", rate_str), style.fg(Color::Green)),
                        latency_span(line.avg_latency_ns, style),
                    ]);
                }
                WidthProfile::Compact => {
                    spans.extend([
                        Span::styled(
                            activity_cell(line.total_bytes, max_bytes, columns.graph),
                            style.fg(Color::Cyan),
                        ),
                        Span::styled(
                            format!("  {:>8}", format_bytes(line.total_bytes)),
                            style.fg(Color::Yellow),
                        ),
                        Span::styled(format!("  {:>8}", rate_str), style.fg(Color::Green)),
                    ]);
                }
                WidthProfile::Minimal => spans.push(Span::styled(
                    format!("  {:>8}", format_bytes(line.total_bytes)),
                    style.fg(Color::Yellow),
                )),
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(cursor.min(lines.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(items).block(Block::default().borders(Borders::NONE)),
        area,
        &mut state,
    );
}

fn latency_span(latency_ns: u64, style: Style) -> Span<'static> {
    if latency_ns == 0 {
        Span::styled(" ".repeat(9), style)
    } else {
        Span::styled(
            format!("  {:>7}", format_latency(latency_ns)),
            style.fg(Color::White),
        )
    }
}

pub fn draw_columns(f: &mut Frame, area: Rect) {
    let columns = TableColumns::for_width(area.width);
    let mut spans = vec![Span::styled(
        fit_display("  Name", columns.name + 2),
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
    fn filtered_flatten_keeps_matching_ancestors() {
        let mut tree = FileTree::new();
        tree.record("/var/log/a", 1, OpKind::Read, 5, 1);
        tree.record("/home/b", 2, OpKind::Read, 7, 1);
        let mut processes = ProcessTable::new();
        processes.record(1, OpKind::Read, 5, 1);
        processes.record(2, OpKind::Read, 7, 1);
        let lines = flatten(
            &tree,
            &HashSet::new(),
            SortBy::Name,
            false,
            &FilterQuery::parse("path:log").unwrap(),
            &processes,
        );
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].name, "var");
    }
}
