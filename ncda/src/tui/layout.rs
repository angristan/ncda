use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthProfile {
    Full,
    Compact,
    Minimal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableColumns {
    pub profile: WidthProfile,
    pub name: usize,
    pub graph: usize,
}

impl TableColumns {
    pub fn for_width(width: u16) -> Self {
        let width = usize::from(width);
        if width >= 96 {
            // Prefix + read/write/ops/rate/latency consume 53 cells.
            let flexible = width.saturating_sub(53);
            let graph = (flexible / 3).clamp(10, 30);
            Self {
                profile: WidthProfile::Full,
                name: flexible.saturating_sub(graph).max(1),
                graph,
            }
        } else if width >= 60 {
            // Prefix + total/rate consume 22 cells.
            let flexible = width.saturating_sub(22);
            let graph = (flexible / 3).clamp(8, 20);
            Self {
                profile: WidthProfile::Compact,
                name: flexible.saturating_sub(graph).max(1),
                graph,
            }
        } else {
            Self {
                profile: WidthProfile::Minimal,
                name: width.saturating_sub(12).max(1),
                graph: 0,
            }
        }
    }

    pub fn rendered_width(self) -> usize {
        match self.profile {
            WidthProfile::Full => 2 + self.name + self.graph + 51,
            WidthProfile::Compact => 2 + self.name + self.graph + 20,
            WidthProfile::Minimal => 2 + self.name + 10,
        }
    }
}

pub fn highlight_selected(spans: &mut [Span<'_>]) {
    let style = Style::default()
        .fg(Color::Black)
        .bg(Color::LightCyan)
        .add_modifier(Modifier::BOLD);
    for span in spans {
        span.style = style;
    }
}

pub fn activity_cell(total: u64, maximum: u64, width: usize) -> String {
    byte_bar(total, maximum, width)
}

fn byte_bar(total: u64, maximum: u64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let filled = if maximum == 0 {
        0
    } else {
        ((total as u128 * width as u128) / maximum as u128) as usize
    }
    .min(width);
    "█".repeat(filled) + &"░".repeat(width - filled)
}

pub fn fit_display(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(value) <= width {
        return format!(
            "{value}{}",
            " ".repeat(width - UnicodeWidthStr::width(value))
        );
    }

    if width == 1 {
        return "~".to_string();
    }
    let target = width - 1;
    let mut output = String::new();
    let mut used = 0;
    for character in value.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + character_width > target {
            break;
        }
        output.push(character);
        used += character_width;
    }
    output.push('~');
    output.push_str(&" ".repeat(width.saturating_sub(used + 1)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_fill_normal_terminal_widths() {
        for width in [40, 80, 140] {
            let columns = TableColumns::for_width(width);
            assert_eq!(columns.rendered_width(), width as usize);
        }
        assert_eq!(TableColumns::for_width(40).profile, WidthProfile::Minimal);
        assert_eq!(TableColumns::for_width(80).profile, WidthProfile::Compact);
        assert_eq!(TableColumns::for_width(140).profile, WidthProfile::Full);
    }

    #[test]
    fn display_fitting_handles_wide_unicode() {
        let fitted = fit_display("📦données", 7);
        assert_eq!(UnicodeWidthStr::width(fitted.as_str()), 7);
    }

    #[test]
    fn selection_overrides_low_contrast_cell_colors() {
        let mut spans = [
            Span::styled("name", Style::default().fg(Color::Blue)),
            Span::styled("metric", Style::default().fg(Color::Red)),
        ];
        highlight_selected(&mut spans);

        let expected = Style::default()
            .fg(Color::Black)
            .bg(Color::LightCyan)
            .add_modifier(Modifier::BOLD);
        assert!(spans.iter().all(|span| span.style == expected));
    }

    #[test]
    fn activity_bars_fill_the_available_width() {
        assert_eq!(activity_cell(0, 10, 4), "░░░░");
        assert_eq!(activity_cell(5, 10, 4), "██░░");
        assert_eq!(activity_cell(10, 10, 4), "████");
    }
}
