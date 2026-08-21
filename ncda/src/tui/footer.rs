use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::model::NodeStats;

#[derive(Debug, Clone, Copy)]
pub struct Diagnostics {
    pub total_events: u64,
    pub dropped_events: u64,
    pub attribution_failures: u64,
    pub failed_io_events: u64,
    pub zero_byte_io_events: u64,
}

pub fn draw(
    f: &mut Frame,
    area: Rect,
    root_stats: &NodeStats,
    rate_bps: f64,
    diagnostics: Diagnostics,
) {
    let Diagnostics {
        total_events,
        dropped_events,
        attribution_failures,
        failed_io_events,
        zero_byte_io_events,
    } = diagnostics;
    let drop_style = Style::default().fg(if dropped_events == 0 {
        Color::DarkGray
    } else {
        Color::Red
    });
    let line = if area.width < 60 {
        Line::from(vec![
            Span::styled(" R:", Style::default().fg(Color::Cyan)),
            Span::raw(format_bytes(root_stats.read_bytes)),
            Span::styled(" W:", Style::default().fg(Color::Red)),
            Span::raw(format_bytes(root_stats.write_bytes)),
            Span::styled(" @", Style::default().fg(Color::Green)),
            Span::raw(format!("{}/s", format_bytes_raw(rate_bps as u64))),
            Span::styled(format!(" D:{}", format_count(dropped_events)), drop_style),
            Span::styled(
                format!(" A:{}", format_count(attribution_failures)),
                Style::default().fg(if attribution_failures == 0 {
                    Color::DarkGray
                } else {
                    Color::Yellow
                }),
            ),
            Span::styled(
                format!(" E:{}", format_count(failed_io_events)),
                Style::default().fg(if failed_io_events == 0 {
                    Color::DarkGray
                } else {
                    Color::Red
                }),
            ),
        ])
    } else {
        Line::from(vec![
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
            Span::styled(format!("Drop:{}", format_count(dropped_events)), drop_style),
            Span::raw(" | "),
            Span::styled(
                format!("Attr:{}", format_count(attribution_failures)),
                Style::default().fg(if attribution_failures == 0 {
                    Color::DarkGray
                } else {
                    Color::Yellow
                }),
            ),
            Span::raw(" | "),
            Span::styled(
                format!(
                    "Err:{} Zero:{}",
                    format_count(failed_io_events),
                    format_count(zero_byte_io_events)
                ),
                Style::default().fg(if failed_io_events == 0 {
                    Color::DarkGray
                } else {
                    Color::Red
                }),
            ),
            if area.width >= 90 {
                Span::raw(" | ")
            } else {
                Span::raw("")
            },
            if area.width >= 90 {
                Span::styled("q", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
            if area.width >= 90 {
                Span::raw(":quit ?:help")
            } else {
                Span::raw("")
            },
        ])
    };

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

pub fn format_bytes(b: u64) -> String {
    format_bytes_raw(b)
}

pub fn format_bytes_raw(bytes: u64) -> String {
    format_scaled(bytes, 1024, &["B", "K", "M", "G", "T", "P", "E"])
}

pub fn format_count(count: u64) -> String {
    format_scaled(count, 1000, &["", "K", "M", "B", "T", "Q", "Qi"])
}

fn format_scaled(value: u64, base: u64, units: &[&str]) -> String {
    let mut scaled = value as f64;
    let mut unit = 0;
    while scaled >= base as f64 && unit + 1 < units.len() {
        scaled /= base as f64;
        unit += 1;
    }

    if unit == 0 {
        return format!("{value}{}", units[unit]);
    }
    if scaled < 100.0 {
        format!("{scaled:.1}{}", units[unit])
    } else {
        format!("{scaled:.0}{}", units[unit])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_units_remain_bounded_through_exabytes() {
        assert_eq!(format_bytes(1 << 40), "1.0T");
        assert_eq!(format_bytes(1 << 50), "1.0P");
        assert_eq!(format_bytes(1 << 60), "1.0E");
        assert!(format_bytes(u64::MAX).len() <= 5);
    }

    #[test]
    fn count_units_remain_bounded_through_quintillions() {
        assert_eq!(format_count(1_000_000_000), "1.0B");
        assert_eq!(format_count(1_000_000_000_000), "1.0T");
        assert_eq!(format_count(1_000_000_000_000_000), "1.0Q");
        assert_eq!(format_count(1_000_000_000_000_000_000), "1.0Qi");
        assert!(format_count(u64::MAX).len() <= 6);
    }
}
