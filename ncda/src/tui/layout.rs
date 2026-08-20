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

pub fn activity_cell(total: u64, maximum: u64, samples: &[u64], width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let spark_width = if width >= 12 { 8.min(width - 4) } else { 0 };
    let bar_width = width.saturating_sub(spark_width + usize::from(spark_width > 0));
    let mut cell = byte_bar(total, maximum, bar_width);
    if spark_width > 0 {
        cell.push(' ');
        cell.push_str(&sparkline(samples, spark_width));
    }
    fit_display(&cell, width)
}

pub fn sparkline(samples: &[u64], width: usize) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if width == 0 {
        return String::new();
    }
    let start = samples.len().saturating_sub(width);
    let visible = &samples[start..];
    let maximum = visible.iter().copied().max().unwrap_or(0);
    let mut output = " ".repeat(width.saturating_sub(visible.len()));
    for value in visible {
        if *value == 0 || maximum == 0 {
            output.push(' ');
        } else {
            let level = ((*value as u128 * (LEVELS.len() - 1) as u128) / maximum as u128) as usize;
            output.push(LEVELS[level]);
        }
    }
    output
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
    fn sparklines_scale_and_pad() {
        assert_eq!(sparkline(&[0, 0], 4), "    ");
        assert_eq!(sparkline(&[0, 8, 0, 4], 4), " █ ▄");
        assert_eq!(sparkline(&[1, 2, 4, 8], 4), "▁▂▄█");
    }
}
