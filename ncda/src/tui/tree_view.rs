use std::collections::HashSet;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{FileTree, NodeStats, SortBy, TreeNode};
use crate::process::ProcessTable;
use crate::tui::filter::{filtered_stats, join_path, FilterQuery};
use crate::tui::footer::{format_bytes, format_count, format_latency};

const FIXED_COLUMNS_WIDTH: usize = 44;

pub struct TreeLine {
    pub depth: usize,
    pub path: Vec<String>,
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

pub fn draw(f: &mut Frame, area: Rect, lines: &[TreeLine], cursor: usize) {
    if lines.is_empty() {
        let empty = List::new(vec![ListItem::new("  (no activity matches)")])
            .block(Block::default().borders(Borders::NONE));
        f.render_widget(empty, area);
        return;
    }

    let name_column_width = name_column_width(area.width);
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
            let indent_width = (line.depth * 2).min(name_column_width.saturating_sub(3));
            let indent = " ".repeat(indent_width);
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
            let bar_width = 8;
            let fraction = line.total_bytes as f64 / max_bytes as f64;
            let filled = (fraction * bar_width as f64) as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
            let style = if index == cursor {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let max_name_width = name_column_width.saturating_sub(indent_width + 2).max(1);

            ListItem::new(Line::from(vec![
                Span::styled(indent, style),
                Span::styled(icon, style),
                Span::styled(
                    format!(
                        "{:<width$}",
                        truncate(&name, max_name_width),
                        width = max_name_width
                    ),
                    style.fg(if line.is_dir {
                        Color::Blue
                    } else {
                        Color::White
                    }),
                ),
                Span::styled(" ", style),
                Span::styled(bar, style.fg(Color::Cyan)),
                Span::styled(
                    format!(" R:{:>7}", format_bytes(line.read_bytes)),
                    style.fg(Color::Cyan),
                ),
                Span::styled(
                    format!(" W:{:>7}", format_bytes(line.write_bytes)),
                    style.fg(Color::Red),
                ),
                Span::styled(
                    format!(" {:>6}", format_count(line.total_ops)),
                    style.fg(Color::Yellow),
                ),
                if line.avg_latency_ns > 0 {
                    Span::styled(
                        format!(" {:>7}", format_latency(line.avg_latency_ns)),
                        style.fg(Color::White),
                    )
                } else {
                    Span::styled(" ".repeat(8), style)
                },
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(cursor.min(lines.len().saturating_sub(1))));
    let list = List::new(items).block(Block::default().borders(Borders::NONE));
    f.render_stateful_widget(list, area, &mut state);
}

pub fn draw_columns(f: &mut Frame, area: Rect) {
    let name_column_width = name_column_width(area.width);
    let line = Line::from(vec![
        Span::styled(
            format!("{:<width$}", "  Name", width = name_column_width),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!(" {:<8}", "Graph"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled("     Read ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("    Write ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("    Ops", Style::default().add_modifier(Modifier::DIM)),
        Span::styled(" Latency", Style::default().add_modifier(Modifier::DIM)),
    ]);
    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
}

fn name_column_width(area_width: u16) -> usize {
    usize::from(area_width)
        .saturating_sub(FIXED_COLUMNS_WIDTH)
        .max(3)
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
        let rendered_width = name_column_width(width) + 9 + 10 + 10 + 7 + 8;
        assert_eq!(rendered_width, usize::from(width));
    }

    #[test]
    fn deep_indentation_keeps_room_for_a_name() {
        let column_width = name_column_width(80);
        let indent_width = (100 * 2).min(column_width.saturating_sub(3));
        assert!(column_width.saturating_sub(indent_width + 2) >= 1);
    }

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
