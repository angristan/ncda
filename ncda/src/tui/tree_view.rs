use std::collections::HashSet;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{FileTree, SortBy, TreeNode};
use crate::tui::footer::{format_bytes, format_count, format_latency};

/// A flattened tree line for rendering.
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

/// Flatten the tree into a list of visible lines based on which nodes are expanded.
pub fn flatten(
    tree: &FileTree,
    expanded: &HashSet<Vec<String>>,
    sort_by: SortBy,
    sort_desc: bool,
) -> Vec<TreeLine> {
    let mut lines = Vec::new();
    let mut path = Vec::new();
    flatten_recurse(
        &tree.root, &mut path, 0, expanded, sort_by, sort_desc, &mut lines,
    );
    lines
}

fn flatten_recurse(
    node: &TreeNode,
    path: &mut Vec<String>,
    depth: usize,
    expanded: &HashSet<Vec<String>>,
    sort_by: SortBy,
    sort_desc: bool,
    lines: &mut Vec<TreeLine>,
) {
    let children = node.sorted_children(sort_by, sort_desc);

    for child in children {
        path.push(child.name.clone());
        let is_exp = expanded.contains(path);

        lines.push(TreeLine {
            depth,
            path: path.clone(),
            name: child.name.clone(),
            is_dir: child.is_dir,
            is_expanded: is_exp,
            read_bytes: child.agg_stats.read_bytes,
            write_bytes: child.agg_stats.write_bytes,
            total_ops: child.agg_stats.total_ops(),
            avg_latency_ns: child.agg_stats.avg_latency_ns(),
            total_bytes: child.agg_stats.total_bytes(),
        });

        if child.is_dir && is_exp {
            flatten_recurse(child, path, depth + 1, expanded, sort_by, sort_desc, lines);
        }

        path.pop();
    }
}

/// Render the tree view.
pub fn draw(f: &mut Frame, area: Rect, lines: &[TreeLine], cursor: usize) {
    if lines.is_empty() {
        let empty = List::new(vec![ListItem::new("  (no file activity recorded)")])
            .block(Block::default().borders(Borders::NONE));
        f.render_widget(empty, area);
        return;
    }

    let max_bytes = lines
        .iter()
        .map(|l| l.total_bytes)
        .max()
        .unwrap_or(1)
        .max(1);

    let items: Vec<ListItem> = lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let indent = "  ".repeat(line.depth);
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

            // Bar graph
            let bar_width = 8;
            let fraction = line.total_bytes as f64 / max_bytes as f64;
            let filled = (fraction * bar_width as f64) as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);

            let is_selected = i == cursor;
            let style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let max_name_width = 24usize.saturating_sub(line.depth * 2);

            let spans = Line::from(vec![
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
                Span::raw(" "),
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
                    Span::raw("")
                },
            ]);

            ListItem::new(spans)
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(cursor));

    let list = List::new(items).block(Block::default().borders(Borders::NONE));
    f.render_stateful_widget(list, area, &mut state);
}

/// Draw column headers for tree view.
pub fn draw_columns(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            format!("{:<26}", "  Name"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!("{:<8}", "Graph"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled("    Read ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("   Write ", Style::default().add_modifier(Modifier::DIM)),
        Span::styled("    Ops", Style::default().add_modifier(Modifier::DIM)),
        Span::styled(" Latency", Style::default().add_modifier(Modifier::DIM)),
    ]);
    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max > 1 {
        format!("{}~", &s[..max - 1])
    } else {
        "~".to_string()
    }
}
