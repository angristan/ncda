use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::model::NodeStats;

pub fn draw(f: &mut Frame, area: Rect, root_stats: &NodeStats, rate_bps: f64, total_events: u64) {
    let line = Line::from(vec![
        Span::styled(" R:", Style::default().fg(Color::Cyan)),
        Span::raw(format_bytes(root_stats.read_bytes)),
        Span::styled(" W:", Style::default().fg(Color::Red)),
        Span::raw(format_bytes(root_stats.write_bytes)),
        Span::raw(" | "),
        Span::styled("Ops:", Style::default().fg(Color::Yellow)),
        Span::raw(format_count(root_stats.total_ops())),
        Span::raw(" | "),
        Span::styled("Rate:", Style::default().fg(Color::Green)),
        Span::raw(format!("{}/s", format_bytes_raw(rate_bps as u64))),
        Span::raw(" | "),
        Span::raw(format!("Evts:{}", format_count(total_events))),
        Span::raw(" | "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(":help"),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

pub fn format_bytes(b: u64) -> String {
    format_bytes_raw(b)
}

pub fn format_bytes_raw(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1}G", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1}M", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1}K", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

pub fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}

pub fn format_latency(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{ns}ns")
    }
}
