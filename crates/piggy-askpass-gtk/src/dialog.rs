//! The GTK window: the class band, the act's text, the PIN field, and for an
//! act with a confirm word a second field the word must be typed into.

use std::cell::{Cell, RefCell};
use std::f64::consts::PI;
use std::rc::Rc;
use std::time::{Duration, Instant};

use gtk::prelude::*;
use gtk::{gdk, glib, pango};
use gtk4 as gtk;

use crate::Outcome;
use crate::options::{Band, Options};

const BAND_CSS_CLASS: &str = "piggy-band";
const DIGIT_CSS_CLASS: &str = "piggy-digit";

/// How long after opening the dialog takes no input but a cancel, so a
/// keystroke meant for another window cannot fill in or confirm the act.
const INPUT_BLOCK: Duration = Duration::from_secs(2);
/// The red section is a tenth of the time after the block, but never shorter
/// than this: the last stretch before the dialog gives up.
const RED_FLOOR: Duration = Duration::from_secs(3);
/// How long the clock stands still after each keystroke or pointer move, so
/// an operator who is typing is not timed out mid-PIN.
const INPUT_PAUSE: Duration = Duration::from_secs(2);
/// Input this recent still counts as going on: the clock shows a pause symbol
/// rather than the countdown to resuming.
const ACTIVITY_WINDOW: Duration = Duration::from_millis(400);
const CLOCK_SIZE: i32 = 48;
/// How long the pause symbol takes to fade in when input starts, and to fade
/// out once the clock is counting down to resuming.
const PAUSE_FADE_IN: Duration = Duration::from_millis(150);
const PAUSE_FADE_OUT: Duration = Duration::from_millis(350);
/// How far the pointer must move, in pixels, to count as input. GTK also
/// reports motion when the window lays out under a resting pointer.
const POINTER_SLOP: f64 = 3.0;
const CONTENT_MARGIN: i32 = 18;
const TICK: Duration = Duration::from_millis(50);
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

    // The clock: one pie, whole orange with the seconds of the input block
    // counted over it, then a green section and a short red one that turn
    // white as their time is used. It sits in the band, left of the class's
    // symbol.
    let timeout = options
        .timeout_secs
        .map(|secs| Duration::from_secs(secs.into()));
    let lengths = timeout.map(split_timeout);
    let green_share = lengths.map_or(1.0, |(green, red)| fraction(green, green + red));
    let has_timeout = lengths.is_some();
    // The phase, how much of the clock's time is used (0 to 1), and how
    // visible the pause symbol is (0 to 1) while input pauses the clock.
    let light_state = Rc::new(Cell::new((Phase::Hold, 0.0_f64, 0.0_f64)));
    let lights = gtk::DrawingArea::builder()
        .content_width(CLOCK_SIZE)
        .content_height(CLOCK_SIZE)
        .build();
    {
        let light_state = light_state.clone();
        lights.set_draw_func(move |_, cr, width, height| {
            let (phase, progress, pause_alpha) = light_state.get();
            let radius = f64::from(width.min(height)) / 2.0 - 3.0;
            let centre = (f64::from(width) / 2.0, f64::from(height) / 2.0);
            let green = light_rgb(Phase::Green);
            let red = light_rgb(Phase::Red);
            match phase {
                Phase::Hold => wedge(cr, centre, radius, light_rgb(Phase::Hold), 1.0, 0.0, 1.0),
                _ if !has_timeout => wedge(cr, centre, radius, green, 1.0, 0.0, 1.0),
                _ => {
                    // Time still to run stays green or red; time gone by is
                    // white, the colour of the rim.
                    let white = (1.0, 1.0, 1.0);
                    wedge(
                        cr,
                        centre,
                        radius,
                        green,
                        1.0,
                        progress.min(green_share),
                        green_share,
                    );
                    wedge(cr, centre, radius, red, 1.0, progress.max(green_share), 1.0);
                    wedge(cr, centre, radius, white, 1.0, 0.0, progress);
                }
            }
            if pause_alpha > 0.0 {
                // Input is going on: a pause symbol over a dimmed clock.
                cr.set_source_rgba(0.0, 0.0, 0.0, 0.45 * pause_alpha);
                cr.arc(centre.0, centre.1, radius, 0.0, 2.0 * PI);
                let _ = cr.fill();
                let (bar_width, bar_height, gap) = (radius * 0.24, radius * 0.95, radius * 0.24);
                cr.set_source_rgba(1.0, 1.0, 1.0, pause_alpha);
                cr.rectangle(
                    centre.0 - gap / 2.0 - bar_width,
                    centre.1 - bar_height / 2.0,
                    bar_width,
                    bar_height,
                );
                cr.rectangle(
                    centre.0 + gap / 2.0,
                    centre.1 - bar_height / 2.0,
                    bar_width,
                    bar_height,
                );
                let _ = cr.fill();
            }
            // The white rim.
            cr.set_source_rgba(1.0, 1.0, 1.0, 1.0);
            cr.set_line_width(2.5);
            cr.arc(centre.0, centre.1, radius, 0.0, 2.0 * PI);
            let _ = cr.stroke();
        });
    }
    // The block's seconds, 3, 2, 1, over the orange clock.
    let digit = gtk::Label::new(None);
    digit.add_css_class(DIGIT_CSS_CLASS);
    digit.set_halign(gtk::Align::Center);
    digit.set_valign(gtk::Align::Center);
    digit.set_can_target(false);
    let clock_face = gtk::Overlay::new();
    clock_face.set_child(Some(&lights));
    clock_face.add_overlay(&digit);

    content.append(&band_row(options.band.as_ref(), &clock_face));
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

    window.set_child(Some(&content));

    // The input block: nothing but a cancel is taken until it ends.
    let blocked = Rc::new(Cell::new(true));
    for input in &inputs {
        input.set_sensitive(false);
    }
    confirm.set_sensitive(false);
    let shaking = Rc::new(Cell::new(false));
    // The clock's phase, and how long it has run. Any input once the block
    // has ended pauses the clock for INPUT_PAUSE, so the dialog does not give
    // up on an operator who is in the middle of typing; it then carries on
    // from where it stopped.
    let clock = Rc::new(Cell::new((Phase::Hold, Duration::ZERO)));
    let last_input: Rc<Cell<Option<Instant>>> = Rc::new(Cell::new(None));
    // Set once the act is confirmed: the clock then changes no more.
    let frozen = Rc::new(Cell::new(false));
    let pause_clock = {
        let last_input = last_input.clone();
        let blocked = blocked.clone();
        let frozen = frozen.clone();
        Rc::new(move || {
            if !blocked.get() && !frozen.get() {
                last_input.set(Some(Instant::now()));
            }
        })
    };

    {
        let finish = finish.clone();
        cancel.connect_clicked(move |_| finish(Outcome::Cancelled));
    }
    {
        let finish = finish.clone();
        let pin_entry = pin_entry.clone();
        let frozen = frozen.clone();
        confirm.connect_clicked(move |button| {
            if button.is_sensitive() {
                frozen.set(true);
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
        let pause_clock = pause_clock.clone();
        // Where Return confirms, that keystroke is the end of the dialog, not
        // an operator at work: it must not touch the clock.
        let return_confirms = options.confirm_word.is_none();
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        keys.connect_key_pressed(move |_, key, _, _| {
            let is_return = matches!(key, gdk::Key::Return | gdk::Key::KP_Enter);
            if key == gdk::Key::Escape {
                finish(Outcome::Cancelled);
                glib::Propagation::Stop
            } else if blocked.get() {
                shake(&content, &shaking);
                glib::Propagation::Stop
            } else {
                if !(return_confirms && is_return) {
                    pause_clock();
                }
                glib::Propagation::Proceed
            }
        });
        window.add_controller(keys);
    }
    {
        // The pointer counts as input too: moving or clicking in the dialog
        // is an operator who is still there. Only a real move counts: GTK
        // also reports motion, at the same spot, when the window lays out
        // under a resting pointer, and that must not stop the clock.
        let motion = gtk::EventControllerMotion::new();
        motion.set_propagation_phase(gtk::PropagationPhase::Capture);
        let pause = pause_clock.clone();
        let anchor: Cell<Option<(f64, f64)>> = Cell::new(None);
        motion.connect_motion(move |_, x, y| match anchor.get() {
            Some((ax, ay)) if (x - ax).abs() + (y - ay).abs() < POINTER_SLOP => {}
            Some(_) => {
                anchor.set(Some((x, y)));
                pause();
            }
            None => anchor.set(Some((x, y))),
        });
        window.add_controller(motion);
        let click = gtk::GestureClick::new();
        click.set_propagation_phase(gtk::PropagationPhase::Capture);
        let pause = pause_clock.clone();
        click.connect_pressed(move |_, _, _, _| pause());
        window.add_controller(click);
    }
    {
        let finish = finish.clone();
        window.connect_close_request(move |_| {
            finish(Outcome::Cancelled);
            glib::Propagation::Proceed
        });
    }
    {
        // One ticker drives the clock: it ends the input block, moves green
        // to red and red to a timeout, and keeps the face current. With a
        // timeout of T the block takes the first INPUT_BLOCK; the rest splits
        // into a green section and a red one (split_timeout). Time in which
        // the clock is paused for input does not count.
        let opened = Instant::now();
        let last_tick = Cell::new(opened);
        let pause_alpha = Cell::new(0.0_f64);
        let frozen = frozen.clone();
        let finish = finish.clone();
        let outcome = outcome.clone();
        let pin_entry = pin_entry.clone();
        let confirm = confirm.clone();
        let digit = digit.clone();
        let lights = lights.clone();
        let clock = clock.clone();
        let last_input = last_input.clone();
        let light_state = light_state.clone();
        let blocked = blocked.clone();
        let tick = move || {
            if outcome.borrow().is_some() {
                return glib::ControlFlow::Break;
            }
            if frozen.get() {
                return glib::ControlFlow::Continue;
            }
            let now = Instant::now();
            let (mut phase, mut in_phase) = clock.get();
            // Only the part of this interval after any pause counts.
            let paused_until = last_input.get().map_or(opened, |at| at + INPUT_PAUSE);
            let counting_from = last_tick.replace(now).max(paused_until);
            in_phase += now.saturating_duration_since(counting_from);
            match phase {
                Phase::Hold => {
                    if timeout
                        .is_some_and(|timeout| now.saturating_duration_since(opened) >= timeout)
                    {
                        finish(Outcome::TimedOut);
                        return glib::ControlFlow::Break;
                    }
                    if in_phase >= INPUT_BLOCK {
                        blocked.set(false);
                        for input in &inputs {
                            input.set_sensitive(true);
                        }
                        confirm.set_sensitive(confirm_sensitive_after_block);
                        pin_entry.grab_focus();
                        (phase, in_phase) = (Phase::Green, Duration::ZERO);
                    }
                }
                Phase::Green => {
                    if lengths.is_some_and(|(green, _)| in_phase >= green) {
                        (phase, in_phase) = (Phase::Red, Duration::ZERO);
                    }
                }
                Phase::Red => {
                    if lengths.is_some_and(|(_, red)| in_phase >= red) {
                        finish(Outcome::TimedOut);
                        return glib::ControlFlow::Break;
                    }
                }
            }
            clock.set((phase, in_phase));
            // How much of the clock's time is used.
            let used = match (phase, lengths) {
                (Phase::Hold, _) => 0.0,
                (Phase::Green, Some((green, red))) => fraction(in_phase, green + red),
                (Phase::Red, Some((green, red))) => fraction(green + in_phase, green + red),
                (_, None) => 1.0,
            };
            // While input is going on the clock shows a pause symbol; once it
            // stops, the seconds until the clock resumes are counted over it,
            // as the input block's are over the orange one.
            let pausing = match last_input.get() {
                Some(at) if phase != Phase::Hold => {
                    let since = now.saturating_duration_since(at);
                    if since < ACTIVITY_WINDOW {
                        Pausing::Active
                    } else if since < INPUT_PAUSE {
                        Pausing::Counting(secs_left(INPUT_PAUSE, since))
                    } else {
                        Pausing::No
                    }
                }
                _ => Pausing::No,
            };
            // The pause symbol fades in while input goes on and out after.
            let step = |fade: Duration| TICK.as_secs_f64() / fade.as_secs_f64();
            let alpha = if pausing == Pausing::Active {
                (pause_alpha.get() + step(PAUSE_FADE_IN)).min(1.0)
            } else {
                (pause_alpha.get() - step(PAUSE_FADE_OUT)).max(0.0)
            };
            pause_alpha.set(alpha);
            light_state.set((phase, used, alpha));
            let counted = match (phase, pausing) {
                (Phase::Hold, _) => Some(secs_left(INPUT_BLOCK, in_phase)),
                (_, Pausing::Counting(left)) => Some(left),
                _ => None,
            };
            match counted {
                Some(seconds) => {
                    digit.set_markup(&format!(
                        "<span size=\"large\" weight=\"heavy\" foreground=\"#ffffff\">{seconds}</span>"
                    ));
                    digit.set_visible(true);
                }
                None => digit.set_visible(false),
            }
            lights.queue_draw();
            glib::ControlFlow::Continue
        };
        tick();
        glib::timeout_add_local(TICK, tick);
    }

    install_style(&window, options.band.as_ref());
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

/// The clock's phase: orange while input is held, green while it is taken,
/// red while the dialog counts down to giving up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Hold,
    Green,
    Red,
}

/// Whether input has paused the clock: going on now, counting down to the
/// clock's resuming (whole seconds left), or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pausing {
    No,
    Active,
    Counting(u64),
}

fn light_rgb(light: Phase) -> (f64, f64, f64) {
    match light {
        Phase::Hold => (0.96, 0.62, 0.07),
        Phase::Green => (0.15, 0.64, 0.41),
        Phase::Red => (0.88, 0.11, 0.14),
    }
}

/// How a timeout of `total`, counted from opening, divides once the input
/// block has taken its share: the green section and the red one. The red one
/// is a tenth of what is left, but at least `RED_FLOOR` and never more than
/// half of it.
fn split_timeout(total: Duration) -> (Duration, Duration) {
    let after_block = total.saturating_sub(INPUT_BLOCK);
    let red = (after_block / 10).max(RED_FLOOR).min(after_block / 2);
    (after_block - red, red)
}

/// Fills the part of the clock from `from` to `to` (each a fraction of a turn
/// from the top, clockwise) in `rgb` at `alpha`.
fn wedge(
    cr: &gdk::cairo::Context,
    centre: (f64, f64),
    radius: f64,
    rgb: (f64, f64, f64),
    alpha: f64,
    from: f64,
    to: f64,
) {
    if to <= from {
        return;
    }
    let top = -PI / 2.0;
    cr.set_source_rgba(rgb.0, rgb.1, rgb.2, alpha);
    cr.move_to(centre.0, centre.1);
    cr.arc(
        centre.0,
        centre.1,
        radius,
        top + 2.0 * PI * from,
        top + 2.0 * PI * to,
    );
    cr.close_path();
    let _ = cr.fill();
}

/// How far `elapsed` has got through `total`, from 0 to 1.
fn fraction(elapsed: Duration, total: Duration) -> f64 {
    if total.is_zero() {
        1.0
    } else {
        (elapsed.as_secs_f64() / total.as_secs_f64()).min(1.0)
    }
}

/// The strip across the top of the dialog: the clock, and the class's name
/// and symbol beside it in the class's colour. Without a band, the clock
/// stands alone.
fn band_row(band: Option<&Band>, clock: &impl IsA<gtk::Widget>) -> gtk::Box {
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .build();
    row.append(clock);
    if let Some(band) = band {
        row.add_css_class(BAND_CSS_CLASS);
        let label = gtk::Label::new(Some(&band.text));
        label.set_hexpand(true);
        label.set_xalign(0.0);
        row.append(&label);
    }
    row
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
fn install_style(window: &gtk::Window, band: Option<&Band>) {
    // The clock's digits sit over green, red or orange: a dark halo keeps
    // them legible on each.
    let mut css = format!(
        "label.{DIGIT_CSS_CLASS} {{ text-shadow: 0 0 4px rgba(0, 0, 0, 0.9), 0 0 2px #000000; }} "
    );
    if let Some(band) = band {
        css.push_str(&format!(
            "box.{BAND_CSS_CLASS} {{ background-color: {}; padding: 8px 12px; }} \
             box.{BAND_CSS_CLASS} label {{ color: {}; font-size: x-large; font-weight: bold; }}",
            band.background.as_str(),
            band.foreground.as_str(),
        ));
    }
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
    fn a_timeout_splits_into_the_block_a_green_section_and_a_short_red_one() {
        let secs = Duration::from_secs;
        let millis = Duration::from_millis;
        // Red is a tenth of what the block leaves: 58 s gives 5.8 s.
        assert_eq!(split_timeout(secs(60)), (millis(52_200), millis(5_800)));
        // A tenth would be under the floor, so the floor applies.
        assert_eq!(split_timeout(secs(12)), (secs(7), secs(3)));
        // Not even the floor fits: red is half of what is left.
        assert_eq!(split_timeout(secs(5)), (millis(1_500), millis(1_500)));
        // No time left after the block: nothing to split.
        assert_eq!(split_timeout(secs(2)), (Duration::ZERO, Duration::ZERO));
        assert_eq!(split_timeout(secs(1)), (Duration::ZERO, Duration::ZERO));
    }

    #[test]
    fn a_fraction_runs_from_zero_to_one_and_stops_there() {
        let ten = Duration::from_secs(10);
        assert_eq!(fraction(Duration::ZERO, ten), 0.0);
        assert_eq!(fraction(Duration::from_secs(5), ten), 0.5);
        assert_eq!(fraction(Duration::from_secs(20), ten), 1.0);
        assert_eq!(fraction(Duration::from_secs(1), Duration::ZERO), 1.0);
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
