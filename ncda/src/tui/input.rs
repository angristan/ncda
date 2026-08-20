use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{ViewMode, ViewState};
use crate::tui::filter::FilterQuery;
use crate::tui::tree_view::TreeLine;

/// Handle a key event, returning true if the app should quit.
pub fn handle_key(
    key: KeyEvent,
    view: &mut ViewState,
    flat_child_count: usize,
    tree_lines: &[TreeLine],
    should_reset: &mut bool,
) -> bool {
    // If help is showing, any key dismisses it
    if view.show_help {
        view.show_help = false;
        return false;
    }
    if view.filter_input.is_some() {
        handle_filter_input(key, view);
        return false;
    }

    match key.code {
        // Quit
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            if view.cursor > 0 {
                view.cursor -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = match view.mode {
                ViewMode::Flat => flat_child_count.saturating_sub(1),
                ViewMode::Tree => tree_lines.len().saturating_sub(1),
            };
            if view.cursor < max {
                view.cursor += 1;
            }
        }
        KeyCode::Home | KeyCode::Char('g') => {
            view.cursor = 0;
        }
        KeyCode::End | KeyCode::Char('G') => {
            view.cursor = match view.mode {
                ViewMode::Flat => flat_child_count.saturating_sub(1),
                ViewMode::Tree => tree_lines.len().saturating_sub(1),
            };
        }
        KeyCode::PageUp => {
            view.cursor = view.cursor.saturating_sub(20);
        }
        KeyCode::PageDown => {
            let max = match view.mode {
                ViewMode::Flat => flat_child_count.saturating_sub(1),
                ViewMode::Tree => tree_lines.len().saturating_sub(1),
            };
            view.cursor = (view.cursor + 20).min(max);
        }

        // Drill in (flat) / Expand (tree)
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => match view.mode {
            ViewMode::Flat => {
                // Get the selected child name and drill in if it's a directory
                // The caller will need to check if the child is a directory
                // We signal this by pushing to cwd (handled in mod.rs)
            }
            ViewMode::Tree => {
                if let Some(line) = tree_lines.get(view.cursor) {
                    if line.is_dir {
                        if line.is_expanded {
                            view.expanded.remove(&line.path);
                        } else {
                            view.expanded.insert(line.path.clone());
                        }
                    }
                }
            }
        },

        // Go up (flat) / Collapse (tree)
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => match view.mode {
            ViewMode::Flat => {
                if !view.cwd.is_empty() {
                    view.cwd.pop();
                    view.cursor = 0;
                }
            }
            ViewMode::Tree => {
                if let Some(line) = tree_lines.get(view.cursor) {
                    if line.is_dir && line.is_expanded {
                        view.expanded.remove(&line.path);
                    } else if line.depth > 0 {
                        // Navigate to parent
                        let parent_path: Vec<String> = line.path[..line.path.len() - 1].to_vec();
                        // Find the parent line index
                        if let Some(idx) = tree_lines.iter().position(|l| l.path == parent_path) {
                            view.cursor = idx;
                        }
                    }
                }
            }
        },

        // Toggle view mode
        KeyCode::Tab => {
            view.mode = match view.mode {
                ViewMode::Flat => ViewMode::Tree,
                ViewMode::Tree => ViewMode::Flat,
            };
            view.cursor = 0;
        }

        // Sort
        KeyCode::Char('s') => {
            view.sort_by = view.sort_by.next();
        }
        KeyCode::Char('S') => {
            view.sort_desc = !view.sort_desc;
        }

        // Activity filter editor and clear.
        KeyCode::Char('/') => {
            view.filter_input = Some(view.filter.raw().to_string());
            view.filter_error = None;
        }
        KeyCode::Esc => {
            view.filter = FilterQuery::default();
            view.filter_error = None;
            view.cursor = 0;
        }

        // Process panel toggle
        KeyCode::Char('p') => {
            view.show_processes = !view.show_processes;
        }

        // Reset counters
        KeyCode::Char('r') => {
            *should_reset = true;
        }

        // Help
        KeyCode::Char('?') => {
            view.show_help = true;
        }

        _ => {}
    }

    false
}

fn handle_filter_input(key: KeyEvent, view: &mut ViewState) {
    match key.code {
        KeyCode::Esc => {
            view.filter_input = None;
            view.filter_error = None;
        }
        KeyCode::Enter => {
            let input = view.filter_input.as_deref().unwrap_or_default();
            match FilterQuery::parse(input) {
                Ok(filter) => {
                    view.filter = filter;
                    view.filter_input = None;
                    view.filter_error = None;
                    view.cursor = 0;
                }
                Err(error) => view.filter_error = Some(error),
            }
        }
        KeyCode::Backspace => {
            if let Some(input) = &mut view.filter_input {
                input.pop();
            }
            view.filter_error = None;
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(input) = &mut view.filter_input {
                input.clear();
            }
            view.filter_error = None;
        }
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            if let Some(input) = &mut view.filter_input {
                input.push(character);
            }
            view.filter_error = None;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_editor_applies_and_clears_queries() {
        let mut view = ViewState::new();
        let lines = Vec::new();
        let mut reset = false;
        handle_key(
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
            &mut view,
            0,
            &lines,
            &mut reset,
        );
        for character in "pid:42".chars() {
            handle_key(
                KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                &mut view,
                0,
                &lines,
                &mut reset,
            );
        }
        handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut view,
            0,
            &lines,
            &mut reset,
        );
        assert_eq!(view.filter.raw(), "pid:42");
        assert!(view.filter_input.is_none());

        handle_key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &mut view,
            0,
            &lines,
            &mut reset,
        );
        assert!(view.filter.is_empty());
    }

    #[test]
    fn invalid_filter_stays_in_editor() {
        let mut view = ViewState::new();
        view.filter_input = Some("pid:nope".to_string());
        handle_filter_input(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &mut view);
        assert!(view.filter_input.is_some());
        assert!(view.filter_error.is_some());
    }
}
