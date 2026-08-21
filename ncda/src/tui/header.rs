use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use super::app::{PaneFocus, ViewMode, ViewState};
use super::layout::truncate_display;

pub fn draw(f: &mut Frame, area: Rect, view: &ViewState) {
    let mut remaining = usize::from(area.width);
    let mut spans = Vec::new();

    // The editor owns the header while active. This keeps the insertion point
    // visible even on narrow terminals instead of clipping it behind status.
    if let Some(input) = &view.filter_input {
        push_segment(
            &mut spans,
            &mut remaining,
            format!(" /{input}█"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            true,
        );
        if let Some(error) = &view.filter_error {
            push_segment(
                &mut spans,
                &mut remaining,
                format!("  {error}"),
                Style::default().fg(Color::Red),
                true,
            );
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }

    push_segment(
        &mut spans,
        &mut remaining,
        " ncda ".to_string(),
        Style::default().fg(Color::Black).bg(Color::Cyan),
        true,
    );

    let mode_label = match view.mode {
        ViewMode::Flat => "FLAT",
        ViewMode::Tree => "TREE",
    };
    push_segment(
        &mut spans,
        &mut remaining,
        format!(" [{mode_label}]"),
        Style::default().fg(Color::Yellow),
        false,
    );

    // Flat mode is scoped to cwd; tree mode always presents the global tree.
    let scope = match view.mode {
        ViewMode::Flat => view.cwd_path(),
        ViewMode::Tree => "/".to_string(),
    };
    push_segment(
        &mut spans,
        &mut remaining,
        format!(" {scope}"),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        true,
    );

    if !view.filter.is_empty() {
        push_segment(
            &mut spans,
            &mut remaining,
            format!("  F:{}", view.filter.raw()),
            Style::default().fg(Color::Cyan),
            true,
        );
    }

    let sort_arrow = if view.sort_desc { "▼" } else { "▲" };
    push_segment(
        &mut spans,
        &mut remaining,
        format!("  {}{sort_arrow}", view.sort_by.label()),
        Style::default().fg(Color::Green),
        false,
    );

    if view.show_processes {
        let (label, modifier) = if view.focus == PaneFocus::Processes {
            ("  [PROCS]", Modifier::BOLD)
        } else {
            ("  [FILES]", Modifier::BOLD)
        };
        push_segment(
            &mut spans,
            &mut remaining,
            label.to_string(),
            Style::default().fg(Color::Magenta).add_modifier(modifier),
            false,
        );
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn push_segment<'a>(
    spans: &mut Vec<Span<'a>>,
    remaining: &mut usize,
    text: String,
    style: Style,
    truncate: bool,
) {
    if *remaining == 0 {
        return;
    }
    let width = UnicodeWidthStr::width(text.as_str());
    if width <= *remaining {
        *remaining -= width;
        spans.push(Span::styled(text, style));
    } else if truncate {
        let text = truncate_display(&text, *remaining);
        *remaining = remaining.saturating_sub(UnicodeWidthStr::width(text.as_str()));
        spans.push(Span::styled(text, style));
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    fn rendered_header(width: u16, view: &ViewState) -> String {
        let backend = TestBackend::new(width, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, frame.area(), view))
            .unwrap();
        (0..width)
            .map(|x| terminal.backend().buffer()[(x, 0)].symbol())
            .collect()
    }

    #[test]
    fn tree_header_does_not_show_flat_cwd() {
        let mut view = ViewState::new();
        view.cwd = vec!["var".into(), "log".into()];
        view.mode = ViewMode::Tree;
        let header = rendered_header(80, &view);
        assert!(header.contains("[TREE] /"));
        assert!(!header.contains("/var/log"));
    }

    #[test]
    fn narrow_header_keeps_filter_editor_visible() {
        let mut view = ViewState::new();
        view.filter_input = Some("path:very-long-directory".into());
        let header = rendered_header(12, &view);
        assert!(header.starts_with(" /path:"));
        assert!(header.contains('~'));
        assert_eq!(UnicodeWidthStr::width(header.as_str()), 12);
    }
}
