//! The GTK window: the class band, the act's text, the PIN field, and for an
//! act with a confirm word a second field the word must be typed into.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use gtk::prelude::*;
use gtk::{gdk, glib, pango};
use gtk4 as gtk;

use crate::Outcome;
use crate::options::{Band, Options};

const BAND_CSS_CLASS: &str = "piggy-band";

/// How long after opening the dialog takes no input but a cancel, so a
/// keystroke meant for another window cannot fill in or confirm the act.
const INPUT_BLOCK: Duration = Duration::from_secs(3);
const CONTENT_MARGIN: i32 = 18;
const TICK: Duration = Duration::from_millis(200);
const SHAKE_FRAME: Duration = Duration::from_millis(16);
const SHAKE_FRAMES: u32 = 12;
const SHAKE_AMPLITUDE: i32 = 10;

/// Shows the dialog and waits for it to end. Errs only when GTK cannot start,
/// which in practice means there is no display to open.
pub fn run(options: &Options, text: &str) -> Result<Outcome, String> {
    gtk::init().map_err(|error| format!("cannot open a display: {error}"))?;

    let main_loop = glib::MainLoop::new(None, false);
    let outcome: Rc<RefCell<Option<Outcome>>> = Rc::new(RefCell::new(None));
    // A header bar makes GTK draw the window's own decorations, as zenity's
    // libadwaita dialogs do. On twerk's GNOME X11 session (Mutter 46) a
    // window decorated by the window manager opened at the top-left, and the
    // same window with client-side decorations (GTK_CSD=1) opened centred.
    let window = gtk::Window::builder()
        .title(options.title.as_str())
        .resizable(false)
        .modal(true)
        .titlebar(&gtk::HeaderBar::new())
        .build();

    // The first ending wins; closing the window afterwards is not a cancel.
    let finish = {
        let main_loop = main_loop.clone();
        let outcome = outcome.clone();
        let window = window.downgrade();
        Rc::new(move |ending: Outcome| {
            if outcome.borrow().is_some() {
                return;
            }
            *outcome.borrow_mut() = Some(ending);
            if let Some(window) = window.upgrade() {
                window.destroy();
            }
            main_loop.quit();
        })
    };

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .build();

    if let Some(band) = &options.band {
        content.append(&band_label(band));
    }
    content.append(&text_label(text));

    let pin_entry = gtk::PasswordEntry::builder().hexpand(true).build();
    content.append(&field("PIV PIN", &pin_entry));

    let cancel = gtk::Button::with_label("Cancel");
    let confirm = gtk::Button::with_label(&options.ok_label);
    // Every field that takes input, so the input block can hold them all.
    let mut inputs: Vec<gtk::Widget> = vec![pin_entry.clone().upcast()];
    match &options.confirm_word {
        // The act grants authority: it takes the typed word, and the button
        // must be clicked, so no Return from either field can grant it.
        Some(word) => {
            confirm.add_css_class("destructive-action");
            let word_entry = gtk::Entry::builder().hexpand(true).build();
            content.append(&field(&format!("Type {word} to grant"), &word_entry));
            let word = word.clone();
            let confirm_button = confirm.clone();
            word_entry.connect_changed(move |entry| {
                confirm_button.set_sensitive(entry.text() == word.as_str());
            });
            inputs.push(word_entry.upcast());
        }
        None => {
            confirm.add_css_class("suggested-action");
            pin_entry.set_activates_default(true);
            window.set_default_widget(Some(&confirm));
        }
    }
    let confirm_sensitive_after_block = options.confirm_word.is_none();

    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .halign(gtk::Align::End)
        .build();
    buttons.append(&cancel);
    buttons.append(&confirm);
    content.append(&buttons);

    let status = gtk::Label::new(None);
    status.set_xalign(1.0);
    status.add_css_class("dim-label");
    content.append(&status);
    window.set_child(Some(&content));

    // The input block: nothing but a cancel is taken until it ends.
    let blocked = Rc::new(Cell::new(true));
    for input in &inputs {
        input.set_sensitive(false);
    }
    confirm.set_sensitive(false);
    let shaking = Rc::new(Cell::new(false));

    {
        let finish = finish.clone();
        cancel.connect_clicked(move |_| finish(Outcome::Cancelled));
    }
    {
        let finish = finish.clone();
        let pin_entry = pin_entry.clone();
        confirm.connect_clicked(move |button| {
            if button.is_sensitive() {
                finish(Outcome::Confirmed {
                    pin: pin_entry.text().to_string(),
                });
            }
        });
    }
    {
        // In the capture phase, so a key pressed during the block is caught
        // here before any field could see it.
        let finish = finish.clone();
        let blocked = blocked.clone();
        let shaking = shaking.clone();
        let content = content.clone();
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        keys.connect_key_pressed(move |_, key, _, _| {
            if key == gdk::Key::Escape {
                finish(Outcome::Cancelled);
                glib::Propagation::Stop
            } else if blocked.get() {
                shake(&content, &shaking);
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        window.add_controller(keys);
    }
    {
        let finish = finish.clone();
        window.connect_close_request(move |_| {
            finish(Outcome::Cancelled);
            glib::Propagation::Proceed
        });
    }
    {
        // One ticker drives both countdowns: it ends the input block, ends
        // the dialog at its timeout, and keeps the status line current.
        let opened = Instant::now();
        let timeout = options
            .timeout_secs
            .map(|secs| Duration::from_secs(secs.into()));
        let finish = finish.clone();
        let outcome = outcome.clone();
        let pin_entry = pin_entry.clone();
        let confirm = confirm.clone();
        let status = status.clone();
        let tick = move || {
            if outcome.borrow().is_some() {
                return glib::ControlFlow::Break;
            }
            let elapsed = opened.elapsed();
            if timeout.is_some_and(|timeout| elapsed >= timeout) {
                finish(Outcome::TimedOut);
                return glib::ControlFlow::Break;
            }
            if blocked.get() && elapsed >= INPUT_BLOCK {
                blocked.set(false);
                for input in &inputs {
                    input.set_sensitive(true);
                }
                confirm.set_sensitive(confirm_sensitive_after_block);
                pin_entry.grab_focus();
            }
            let block_left = secs_left(INPUT_BLOCK, elapsed);
            let timeout_left = timeout.map(|timeout| secs_left(timeout, elapsed));
            match status_text(block_left, timeout_left) {
                Some(text) => {
                    status.set_text(&text);
                    status.set_visible(true);
                }
                None => status.set_visible(false),
            }
            glib::ControlFlow::Continue
        };
        tick();
        glib::timeout_add_local(TICK, tick);
    }

    if let Some(band) = &options.band {
        install_band_style(&window, band);
    }
    // Present, not just show: a window that is only shown can open behind
    // the one the operator is typing into, and the PIN then goes there.
    window.present();
    pin_entry.grab_focus();
    main_loop.run();

    let ending = outcome.borrow_mut().take();
    Ok(ending.unwrap_or(Outcome::Cancelled))
}

/// Shakes the dialog's content side to side, the way a macOS password field
/// refuses a wrong password, to show a keystroke was not taken. The window
/// itself cannot be moved from a client, so the content moves inside it.
fn shake(content: &gtk::Box, shaking: &Rc<Cell<bool>>) {
    if shaking.replace(true) {
        return;
    }
    let content = content.clone();
    let shaking = shaking.clone();
    let mut frame = 0;
    glib::timeout_add_local(SHAKE_FRAME, move || {
        let offset = shake_offset(frame);
        content.set_margin_start(CONTENT_MARGIN + offset);
        content.set_margin_end(CONTENT_MARGIN - offset);
        if frame == SHAKE_FRAMES {
            shaking.set(false);
            return glib::ControlFlow::Break;
        }
        frame += 1;
        glib::ControlFlow::Continue
    });
}

/// The content's sideways offset at a frame of the shake: alternating sides,
/// dying away, and back at rest on the last frame.
fn shake_offset(frame: u32) -> i32 {
    let remaining = SHAKE_FRAMES.saturating_sub(frame) as i32;
    let amplitude = SHAKE_AMPLITUDE * remaining / SHAKE_FRAMES as i32;
    if frame % 2 == 0 {
        amplitude
    } else {
        -amplitude
    }
}

/// Whole seconds left of `total` after `elapsed`, rounded up, so the count
/// shows 3, 2, 1 and reaches 0 only when the time is up.
fn secs_left(total: Duration, elapsed: Duration) -> u64 {
    let left = total.saturating_sub(elapsed);
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

fn status_text(block_left: u64, timeout_left: Option<u64>) -> Option<String> {
    match (block_left, timeout_left) {
        (0, None) => None,
        (0, Some(timeout_left)) => Some(format!("Cancels in {timeout_left} s")),
        (block_left, None) => Some(format!("Input opens in {block_left} s")),
        (block_left, Some(timeout_left)) => Some(format!(
            "Input opens in {block_left} s · cancels in {timeout_left} s"
        )),
    }
}

fn band_label(band: &Band) -> gtk::Label {
    let label = gtk::Label::new(Some(&band.text));
    label.add_css_class(BAND_CSS_CLASS);
    label.set_hexpand(true);
    label.set_xalign(0.0);
    label
}

/// The act's text, set as plain text so nothing in it is read as markup, in
/// a monospace face so look-alike characters stay apart, and wrapped at the
/// width the script's height limit assumes.
fn text_label(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_use_markup(false);
    label.set_wrap(true);
    label.set_wrap_mode(pango::WrapMode::WordChar);
    label.set_max_width_chars(80);
    label.set_xalign(0.0);
    label.add_css_class("monospace");
    label
}

fn field(caption: &str, entry: &impl IsA<gtk::Widget>) -> gtk::Box {
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .build();
    let label = gtk::Label::new(Some(caption));
    label.set_xalign(0.0);
    label.set_mnemonic_widget(Some(entry));
    row.append(&label);
    row.append(entry);
    row
}

/// The colours come from `HexColour`, which accepts only `#rrggbb`, so the
/// stylesheet cannot be steered by them.
fn install_band_style(window: &gtk::Window, band: &Band) {
    let css = format!(
        "label.{BAND_CSS_CLASS} {{ background-color: {}; color: {}; font-size: x-large; \
         font-weight: bold; padding: 8px 12px; }}",
        band.background.as_str(),
        band.foreground.as_str(),
    );
    let provider = gtk::CssProvider::new();
    provider.load_from_string(&css);
    gtk::style_context_add_provider_for_display(
        &WidgetExt::display(window),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_left_round_up_and_reach_zero_only_at_the_end() {
        let three = Duration::from_secs(3);
        assert_eq!(secs_left(three, Duration::ZERO), 3);
        assert_eq!(secs_left(three, Duration::from_millis(200)), 3);
        assert_eq!(secs_left(three, Duration::from_millis(2_999)), 1);
        assert_eq!(secs_left(three, three), 0);
        assert_eq!(secs_left(three, Duration::from_secs(10)), 0);
    }

    #[test]
    fn the_status_line_shows_whichever_countdowns_are_running() {
        assert_eq!(
            status_text(3, Some(60)).as_deref(),
            Some("Input opens in 3 s · cancels in 60 s")
        );
        assert_eq!(status_text(2, None).as_deref(), Some("Input opens in 2 s"));
        assert_eq!(status_text(0, Some(42)).as_deref(), Some("Cancels in 42 s"));
        assert_eq!(status_text(0, None), None);
    }

    #[test]
    fn the_shake_alternates_dies_away_and_ends_at_rest() {
        assert_eq!(shake_offset(0), SHAKE_AMPLITUDE);
        assert!(shake_offset(1) < 0);
        assert!(shake_offset(2) > 0);
        assert!(shake_offset(2).abs() < shake_offset(0).abs());
        assert_eq!(shake_offset(SHAKE_FRAMES), 0);
    }
}
