use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{PaneFocus, ViewMode, ViewState};
use crate::tui::filter::FilterQuery;
use crate::tui::tree_view::TreeLine;

/// Handle a key event, returning true if the app should quit.
pub fn handle_key(
    key: KeyEvent,
    view: &mut ViewState,
    flat_child_count: usize,
    tree_lines: &[TreeLine],
    process_pids: &[u32],
    should_reset: &mut bool,
) -> bool {
    handle_key_with_page_height(
        key,
        view,
        flat_child_count,
        tree_lines,
        process_pids,
        20,
        should_reset,
    )
}

/// Handle a key event using the actual visible row count for page navigation.
pub fn handle_key_with_page_height(
    key: KeyEvent,
    view: &mut ViewState,
    flat_child_count: usize,
    tree_lines: &[TreeLine],
    process_pids: &[u32],
    page_height: usize,
    should_reset: &mut bool,
) -> bool {
    // Help is a true modal: its first key only dismisses it.
    if view.show_help {
        view.show_help = false;
        return false;
    }

    // These controls are global, including while the process pane or filter
    // editor has focus. Esc remains contextual so an editor can be cancelled
    // without also clearing the applied filter.
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Char('r') => {
            *should_reset = true;
            return false;
        }
        KeyCode::Tab => {
            view.mode = match view.mode {
                ViewMode::Flat => ViewMode::Tree,
                ViewMode::Tree => ViewMode::Flat,
            };
            view.cursor = 0;
            return false;
        }
        KeyCode::Esc => {
            if view.filter_input.is_some() {
                view.filter_input = None;
                view.filter_error = None;
            } else if view.focus == PaneFocus::Processes {
                view.focus = PaneFocus::Files;
            } else {
                view.filter = FilterQuery::default();
                view.filter_error = None;
                view.cursor = 0;
            }
            return false;
        }
        _ => {}
    }

    if view.filter_input.is_some() {
        handle_filter_input(key, view);
        return false;
    }
    if view.focus == PaneFocus::Processes {
        return handle_process_key(key, view, process_pids, page_height);
    }

    let page_height = page_height.max(1);
    match key.code {
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
            view.cursor = view.cursor.saturating_sub(page_height);
        }
        KeyCode::PageDown => {
            let max = match view.mode {
                ViewMode::Flat => flat_child_count.saturating_sub(1),
                ViewMode::Tree => tree_lines.len().saturating_sub(1),
            };
            view.cursor = view.cursor.saturating_add(page_height).min(max);
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

        // Process panel toggle
        KeyCode::Char('p') => {
            view.show_processes = !view.show_processes;
            if !view.show_processes {
                view.focus = PaneFocus::Files;
            }
        }
        KeyCode::Char('P') => {
            view.show_processes = true;
            view.focus = PaneFocus::Processes;
            view.reconcile_process_selection(process_pids);
        }

        // Help
        KeyCode::Char('?') => {
            view.show_help = true;
        }

        _ => {}
    }

    false
}

fn handle_process_key(
    key: KeyEvent,
    view: &mut ViewState,
    process_pids: &[u32],
    page_height: usize,
) -> bool {
    let page_height = page_height.max(1);
    match key.code {
        KeyCode::Char('P') => view.focus = PaneFocus::Files,
        KeyCode::Char('p') => {
            view.show_processes = false;
            view.focus = PaneFocus::Files;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            view.process_cursor = view.process_cursor.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            view.process_cursor =
                (view.process_cursor + 1).min(process_pids.len().saturating_sub(1));
        }
        KeyCode::Home | KeyCode::Char('g') => view.process_cursor = 0,
        KeyCode::End | KeyCode::Char('G') => {
            view.process_cursor = process_pids.len().saturating_sub(1);
        }
        KeyCode::PageUp => {
            view.process_cursor = view.process_cursor.saturating_sub(page_height);
        }
        KeyCode::PageDown => {
            view.process_cursor = view
                .process_cursor
                .saturating_add(page_height)
                .min(process_pids.len().saturating_sub(1));
        }
        KeyCode::Char('s') => view.process_sort = view.process_sort.next(),
        KeyCode::Char('S') => view.process_sort_desc = !view.process_sort_desc,
        KeyCode::Enter => {
            if let Some(pid) = process_pids.get(view.process_cursor) {
                view.filter = FilterQuery::parse(&format!("pid:{pid}")).unwrap();
                view.cursor = 0;
                view.focus = PaneFocus::Files;
            }
        }
        KeyCode::Char('/') => {
            view.filter_input = Some(view.filter.raw().to_string());
            view.filter_error = None;
        }
        KeyCode::Char('?') => view.show_help = true,
        _ => {}
    }
    view.selected_process = process_pids.get(view.process_cursor).copied();
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
            &[],
            &mut reset,
        );
        for character in "pid:42".chars() {
            handle_key(
                KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                &mut view,
                0,
                &lines,
                &[],
                &mut reset,
            );
        }
        handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut view,
            0,
            &lines,
            &[],
            &mut reset,
        );
        assert_eq!(view.filter.raw(), "pid:42");
        assert!(view.filter_input.is_none());

        handle_key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &mut view,
            0,
            &lines,
            &[],
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

    #[test]
    fn process_navigation_applies_selected_pid_filter() {
        let mut view = ViewState::new();
        view.show_processes = true;
        view.focus = PaneFocus::Processes;
        let pids = [10, 20, 30];
        handle_process_key(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut view,
            &pids,
            5,
        );
        assert_eq!(view.selected_process, Some(20));
        handle_process_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut view,
            &pids,
            5,
        );
        assert_eq!(view.filter.raw(), "pid:20");
        assert_eq!(view.focus, PaneFocus::Files);
    }

    #[test]
    fn help_consumes_drill_and_quit_keys() {
        let mut view = ViewState::new();
        view.show_help = true;
        let mut reset = false;
        let quit = handle_key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut view,
            3,
            &[],
            &[],
            &mut reset,
        );
        assert!(!quit);
        assert!(!view.show_help);
    }

    #[test]
    fn global_keys_work_from_editor_and_process_pane() {
        let mut view = ViewState::new();
        view.filter_input = Some("path:tmp".into());
        let mut reset = false;
        handle_key(
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            &mut view,
            0,
            &[],
            &[],
            &mut reset,
        );
        assert!(reset);
        assert!(view.filter_input.is_some());

        handle_key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &mut view,
            0,
            &[],
            &[],
            &mut reset,
        );
        assert!(view.filter_input.is_none());

        view.show_processes = true;
        view.focus = PaneFocus::Processes;
        handle_key(
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &mut view,
            0,
            &[],
            &[],
            &mut reset,
        );
        assert_eq!(view.mode, ViewMode::Tree);
        assert_eq!(view.focus, PaneFocus::Processes);

        assert!(handle_key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut view,
            0,
            &[],
            &[],
            &mut reset,
        ));
    }

    #[test]
    fn page_navigation_uses_visible_height() {
        let mut view = ViewState::new();
        let mut reset = false;
        handle_key_with_page_height(
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            &mut view,
            100,
            &[],
            &[],
            7,
            &mut reset,
        );
        assert_eq!(view.cursor, 7);
        handle_key_with_page_height(
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
            &mut view,
            100,
            &[],
            &[],
            7,
            &mut reset,
        );
        assert_eq!(view.cursor, 0);
    }
}
