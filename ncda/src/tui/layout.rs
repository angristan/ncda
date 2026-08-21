use ratatui::style::{Color, Modifier};
use ratatui::text::Span;
use unicode_width::UnicodeWidthStr;

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
            // Prefix + read/write/ops/rate/latency consume 51 cells.
            let flexible = width.saturating_sub(51);
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
            WidthProfile::Full => 2 + self.name + self.graph + 49,
            WidthProfile::Compact => 2 + self.name + self.graph + 20,
            WidthProfile::Minimal => 2 + self.name + 10,
        }
    }
}

pub fn highlight_inactive_selected(spans: &mut [Span<'_>]) {
    for span in spans {
        span.style = span.style.bg(Color::Rgb(28, 34, 45));
    }
}

pub fn highlight_selected(spans: &mut [Span<'_>]) {
    for span in spans {
        let foreground = match span.style.fg {
            Some(Color::Black | Color::DarkGray | Color::Gray) | None => Color::White,
            Some(Color::Red) => Color::LightRed,
            Some(Color::Green) => Color::LightGreen,
            Some(Color::Yellow) => Color::LightYellow,
            Some(Color::Blue) => Color::LightBlue,
            Some(Color::Magenta) => Color::LightMagenta,
            Some(Color::Cyan) => Color::LightCyan,
            Some(color) => color,
        };
        span.style = span
            .style
            .fg(foreground)
            .bg(Color::Rgb(45, 55, 72))
            .add_modifier(Modifier::BOLD);
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
    let mut output = truncate_display(value, width);
    let used = UnicodeWidthStr::width(output.as_str());
    output.push_str(&" ".repeat(width.saturating_sub(used)));
    output
}

/// Truncate to terminal cells without splitting a combining or emoji cluster.
pub fn truncate_display(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(value) <= width {
        return value.to_string();
    }
    if width == 1 {
        return "~".to_string();
    }

    let target = width - 1;
    let mut output = String::new();
    let mut used = 0;
    let mut start = 0;
    while start < value.len() {
        let end = grapheme_end(value, start);
        let cluster = &value[start..end];
        let cluster_width = UnicodeWidthStr::width(cluster);
        if used + cluster_width > target {
            break;
        }
        output.push_str(cluster);
        used += cluster_width;
        start = end;
    }
    output.push('~');
    output
}

fn grapheme_end(value: &str, start: usize) -> usize {
    let mut characters = value[start..].char_indices();
    let Some((_, first)) = characters.next() else {
        return start;
    };
    let mut end = start + first.len_utf8();
    let mut after_joiner = false;
    let mut regional_indicators = usize::from(is_regional_indicator(first));

    for (offset, character) in characters {
        let absolute = start + offset;
        let include = if after_joiner {
            after_joiner = character == '\u{200d}';
            true
        } else if character == '\u{200d}' {
            after_joiner = true;
            true
        } else if is_grapheme_extend(character) {
            true
        } else if regional_indicators == 1 && is_regional_indicator(character) {
            regional_indicators += 1;
            true
        } else {
            false
        };
        if !include {
            break;
        }
        end = absolute + character.len_utf8();
    }
    end
}

fn is_regional_indicator(character: char) -> bool {
    ('\u{1f1e6}'..='\u{1f1ff}').contains(&character)
}

fn is_grapheme_extend(character: char) -> bool {
    matches!(
        character,
        '\u{0300}'..='\u{036f}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05bd}'
            | '\u{05bf}'
            | '\u{05c1}'..='\u{05c2}'
            | '\u{0610}'..='\u{061a}'
            | '\u{064b}'..='\u{065f}'
            | '\u{0670}'
            | '\u{06d6}'..='\u{06ed}'
            | '\u{0900}'..='\u{0903}'
            | '\u{093a}'..='\u{094f}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{fe20}'..='\u{fe2f}'
            | '\u{1f3fb}'..='\u{1f3ff}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

#[cfg(test)]
mod tests {
    use ratatui::style::Style;

    use super::*;

    #[test]
    fn profiles_fill_normal_terminal_widths() {
        for width in [40, 59, 60, 95, 96, 140] {
            let columns = TableColumns::for_width(width);
            assert_eq!(columns.rendered_width(), width as usize, "width {width}");
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
    fn display_fitting_does_not_split_grapheme_clusters() {
        let combining = truncate_display("e\u{301}xy", 2);
        assert_eq!(combining, "e\u{301}~");

        let family = "👩‍👩‍👧‍👦";
        let emoji = truncate_display(&format!("{family}xy"), 3);
        assert_eq!(emoji, format!("{family}~"));
        assert_eq!(UnicodeWidthStr::width(emoji.as_str()), 3);
    }

    #[test]
    fn selection_brightens_semantic_cell_colors() {
        let mut spans = [
            Span::styled("name", Style::default().fg(Color::Blue)),
            Span::styled("metric", Style::default().fg(Color::Red)),
            Span::raw("separator"),
        ];
        highlight_selected(&mut spans);

        assert_eq!(spans[0].style.fg, Some(Color::LightBlue));
        assert_eq!(spans[1].style.fg, Some(Color::LightRed));
        assert_eq!(spans[2].style.fg, Some(Color::White));
        assert!(spans.iter().all(|span| {
            span.style.bg == Some(Color::Rgb(45, 55, 72))
                && span.style.add_modifier.contains(Modifier::BOLD)
        }));
    }

    #[test]
    fn activity_bars_fill_the_available_width() {
        assert_eq!(activity_cell(0, 10, 4), "░░░░");
        assert_eq!(activity_cell(5, 10, 4), "██░░");
        assert_eq!(activity_cell(10, 10, 4), "████");
    }
}
