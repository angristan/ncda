use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{ViewMode, ViewState};
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
