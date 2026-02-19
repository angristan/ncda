use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::app::{ViewMode, ViewState};

pub fn draw(f: &mut Frame, area: Rect, view: &ViewState) {
    let mode_label = match view.mode {
        ViewMode::Flat => "FLAT",
        ViewMode::Tree => "TREE",
    };

    let sort_arrow = if view.sort_desc { "▼" } else { "▲" };

    let line = Line::from(vec![
        Span::styled(" ncda ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(
            view.cwd_path(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("[{mode_label}]"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  Sort: "),
        Span::styled(
            format!("{}{sort_arrow}", view.sort_by.label()),
            Style::default().fg(Color::Green),
        ),
        if view.show_processes {
            Span::styled("  [P]rocs", Style::default().fg(Color::Magenta))
        } else {
            Span::raw("")
        },
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}
