//! The GTK window: the class band, the act's text, the PIN field, and for an
//! act with a confirm word a second field the word must be typed into.

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;
use gtk::{gdk, glib, pango};
use gtk4 as gtk;

use crate::Outcome;
use crate::options::{Band, Options};

const BAND_CSS_CLASS: &str = "piggy-band";

/// Shows the dialog and waits for it to end. Errs only when GTK cannot start,
/// which in practice means there is no display to open.
pub fn run(options: &Options, text: &str) -> Result<Outcome, String> {
    gtk::init().map_err(|error| format!("cannot open a display: {error}"))?;

    let main_loop = glib::MainLoop::new(None, false);
    let outcome: Rc<RefCell<Option<Outcome>>> = Rc::new(RefCell::new(None));
    let window = gtk::Window::builder()
        .title(options.title.as_str())
        .resizable(false)
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
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();

    if let Some(band) = &options.band {
        content.append(&band_label(band));
    }
    content.append(&text_label(text));

    let pin_entry = gtk::PasswordEntry::builder().hexpand(true).build();
    content.append(&field("PIV PIN", &pin_entry));

    let cancel = gtk::Button::with_label("Cancel");
    let confirm = gtk::Button::with_label(&options.ok_label);
    match &options.confirm_word {
        // The act grants authority: it takes the typed word, and the button
        // must be clicked, so no Return from either field can grant it.
        Some(word) => {
            confirm.add_css_class("destructive-action");
            confirm.set_sensitive(false);
            let word_entry = gtk::Entry::builder().hexpand(true).build();
            content.append(&field(&format!("Type {word} to grant"), &word_entry));
            let word = word.clone();
            let confirm_button = confirm.clone();
            word_entry.connect_changed(move |entry| {
                confirm_button.set_sensitive(entry.text() == word.as_str());
            });
        }
        None => {
            confirm.add_css_class("suggested-action");
            pin_entry.set_activates_default(true);
            window.set_default_widget(Some(&confirm));
        }
    }

    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .halign(gtk::Align::End)
        .build();
    buttons.append(&cancel);
    buttons.append(&confirm);
    content.append(&buttons);
    window.set_child(Some(&content));

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
        let finish = finish.clone();
        let keys = gtk::EventControllerKey::new();
        keys.connect_key_pressed(move |_, key, _, _| {
            if key == gdk::Key::Escape {
                finish(Outcome::Cancelled);
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
    if let Some(secs) = options.timeout_secs {
        let finish = finish.clone();
        glib::timeout_add_seconds_local_once(secs, move || finish(Outcome::TimedOut));
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
