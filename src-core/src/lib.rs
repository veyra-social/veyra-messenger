#[cfg(target_os = "android")]
mod android_round;
mod api;
mod app_state;
mod crypto;
mod errors;
mod logging;
mod media_server;
mod models;
mod p2p;
mod storage;
mod update_check;
mod update_manifest;
mod version;

use api::commands::*;
use app_state::AppState;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
#[cfg(all(desktop, target_os = "macos"))]
use std::sync::Mutex;
#[cfg(desktop)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(all(desktop, target_os = "macos"))]
use std::time::{Duration, Instant};
#[cfg(all(desktop, target_os = "macos"))]
use tauri::tray::MouseButtonState;
use tauri::Manager;
#[cfg(desktop)]
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    WindowEvent,
};

const VEYRA_AUTOSTART_ARG: &str = "--veyra-autostart";
const VEYRA_DATA_DIR_ARG: &str = "--veyra-data-dir";
#[cfg(all(desktop, target_os = "macos"))]
const MACOS_TRAY_DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(500);

/// The user's "keep the screen on" preference, mirrored out of the database so
/// the foreground lifecycle hooks can apply it without touching storage. Starts
/// at the iOS default (`true`) and is corrected by the startup warm-up and by
/// every `set_ui_prefs` call.
#[cfg(target_os = "ios")]
static IOS_KEEP_SCREEN_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// `UIApplication` is main-thread-only: `-[UIApplication
/// _setIdleTimerDisabled:forReason:]` trips `assertBarrierOnQueue` and iOS
/// kills the process (EXC_BREAKPOINT) when it is touched from anywhere else.
/// Every caller here runs off the main thread — Tauri commands execute on
/// worker threads and the startup warm-up is its own `std::thread` — so the
/// call always hops through the app handle. Field crash 2026-07-27: the 1.26.28
/// warm-up seeding called it directly from that thread and the app died on
/// launch.
#[cfg(target_os = "ios")]
fn set_ios_idle_timer_disabled_on_main(app: &tauri::AppHandle, disabled: bool) {
    if let Err(err) = app.run_on_main_thread(move || set_ios_idle_timer_disabled(disabled)) {
        tracing::warn!(
            ?err,
            "could not reach the main thread for the iOS idle timer"
        );
    }
}

/// Records the preference and applies it right away. Called when the user flips
/// the toggle and once at startup with the stored value.
#[cfg(target_os = "ios")]
pub(crate) fn set_ios_keep_screen_on(app: &tauri::AppHandle, enabled: bool) {
    use std::sync::atomic::Ordering;
    IOS_KEEP_SCREEN_ON.store(enabled, Ordering::Relaxed);
    set_ios_idle_timer_disabled_on_main(app, enabled);
}

/// Applies the preference on every path that means "we are in the foreground
/// again". Backgrounding always releases the idle timer regardless.
#[cfg(target_os = "ios")]
pub(crate) fn apply_ios_keep_screen_on_foreground(app: &tauri::AppHandle) {
    use std::sync::atomic::Ordering;
    set_ios_idle_timer_disabled_on_main(app, IOS_KEEP_SCREEN_ON.load(Ordering::Relaxed));
}

/// Private on purpose: `set_ios_idle_timer_disabled_on_main` is the only door
/// to this call, so no future caller can reach UIKit off the main thread.
#[cfg(target_os = "ios")]
fn set_ios_idle_timer_disabled(disabled: bool) {
    use objc2::{
        class, msg_send,
        runtime::{AnyObject, Bool},
    };

    unsafe {
        let application: *mut AnyObject = msg_send![class!(UIApplication), sharedApplication];
        if !application.is_null() {
            let _: () = msg_send![application, setIdleTimerDisabled: Bool::from(disabled)];
            let applied: Bool = msg_send![application, isIdleTimerDisabled];
            tracing::info!(
                requested = disabled,
                applied = applied.as_bool(),
                "iOS idle timer state updated"
            );
        }
    }
}

// Replace the implementation of `-[WKContentView inputAccessoryView]` so the
// iOS QuickType / form-navigation accessory bar above the on-screen keyboard
// is suppressed. WKContentView is the private first responder inside every
// WKWebView, and overriding this single getter is the canonical way to hide
// the accessory bar for web inputs without subclassing the web view. We run
// this once during application setup; subsequent input focuses inherit the
// new implementation.
#[cfg(target_os = "ios")]
pub(crate) fn disable_ios_input_accessory_bar() {
    use objc2::ffi::{class_getInstanceMethod, method_setImplementation, objc_getClass};
    use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
    use objc2::sel;
    use std::ffi::CString;

    unsafe extern "C-unwind" fn return_nil(_this: &AnyObject, _cmd: Sel) -> *mut AnyObject {
        std::ptr::null_mut()
    }

    unsafe {
        let class_name = CString::new("WKContentView").unwrap();
        let cls = objc_getClass(class_name.as_ptr()) as *const AnyClass;
        if cls.is_null() {
            tracing::warn!(
                "WKContentView class not found; skipping iOS input accessory bar swizzle"
            );
            return;
        }
        let sel = sel!(inputAccessoryView);
        let method = class_getInstanceMethod(cls, sel);
        if method.is_null() {
            tracing::warn!("WKContentView has no inputAccessoryView method; skipping swizzle");
            return;
        }
        let imp_fn: unsafe extern "C-unwind" fn(&AnyObject, Sel) -> *mut AnyObject = return_nil;
        let imp: Imp = std::mem::transmute(imp_fn);
        let _previous = method_setImplementation(method, imp);
        tracing::info!("WKContentView.inputAccessoryView overridden to return nil");
    }
}

// iOS background-operation Stage 1 (next-steps/ios-background-operation.md).
// When the app moves to the background iOS suspends the process within seconds.
// `beginBackgroundTask` buys a short (~30s) grace window so in-flight outbox
// sends / ACKs / receipts can finish before suspension instead of being cut off
// mid-flight. We end the task on resume and from the expiration handler
// (whichever fires first). This is the serverless part of Stage 1 — it does NOT
// give real-time background delivery (that needs push, Stage 2), only a graceful
// wind-down so backgrounding does not strand half-sent messages.
#[cfg(target_os = "ios")]
mod ios_background {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use block2::RcBlock;
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};

    // UIBackgroundTaskInvalid == NSUIntegerMax.
    const UI_BACKGROUND_TASK_INVALID: usize = usize::MAX;
    static BG_TASK: AtomicUsize = AtomicUsize::new(UI_BACKGROUND_TASK_INVALID);

    pub(crate) fn begin_background_task() {
        // Never stack tasks: release any prior identifier first.
        end_background_task();
        unsafe {
            let app: *mut AnyObject = msg_send![class!(UIApplication), sharedApplication];
            if app.is_null() {
                return;
            }
            // Expiration handler: iOS is about to reclaim the grace window, so
            // release the task or the watchdog flags us for holding it too long.
            let handler = RcBlock::new(|| {
                end_background_task();
            });
            let id: usize = msg_send![app, beginBackgroundTaskWithExpirationHandler: &*handler];
            BG_TASK.store(id, Ordering::SeqCst);
            tracing::info!(id, "iOS began background task (grace window)");
        }
    }

    pub(crate) fn end_background_task() {
        let id = BG_TASK.swap(UI_BACKGROUND_TASK_INVALID, Ordering::SeqCst);
        if id == UI_BACKGROUND_TASK_INVALID {
            return;
        }
        unsafe {
            let app: *mut AnyObject = msg_send![class!(UIApplication), sharedApplication];
            if app.is_null() {
                return;
            }
            let _: () = msg_send![app, endBackgroundTask: id];
            tracing::info!(id, "iOS ended background task");
        }
    }
}

// Voice-call audio session for iOS (2026-07-16 field report: a call played
// through the loud speaker with no way to switch to the earpiece). WebRTC
// audio inside WKWebView stays on the default media route unless the app
// configures AVAudioSession itself — there is no JS-side control. This is
// the iOS mirror of Android's MODE_IN_COMMUNICATION bridge
// (VeyraNativeBridge.startCallAudio / setSpeakerphone / stopCallAudio):
// PlayAndRecord + VoiceChat routes to the earpiece by default, and
// overrideOutputAudioPort flips the loudspeaker on demand. Driven from Rust
// via objc2 message sends like `ios_background` above — the generated
// gen/apple project stays untouched.
#[cfg(target_os = "ios")]
pub(crate) mod ios_call_audio {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};

    /// AVAudioSessionCategoryOptionAllowBluetooth.
    const OPTION_ALLOW_BLUETOOTH: usize = 0x4;
    /// AVAudioSessionPortOverrideNone / ...Speaker ('spkr').
    const PORT_OVERRIDE_NONE: usize = 0;
    const PORT_OVERRIDE_SPEAKER: usize = 0x7370_6b72;
    /// AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation.
    const NOTIFY_OTHERS_ON_DEACTIVATION: usize = 1;

    unsafe fn ns_string(value: &str) -> *mut AnyObject {
        let Ok(value) = std::ffi::CString::new(value) else {
            return std::ptr::null_mut();
        };
        msg_send![class!(NSString), stringWithUTF8String: value.as_ptr()]
    }

    unsafe fn shared_session() -> *mut AnyObject {
        msg_send![class!(AVAudioSession), sharedInstance]
    }

    /// Enters the communication session: PlayAndRecord + VoiceChat (earpiece
    /// by default, Bluetooth headsets allowed), active, then applies the
    /// requested output route.
    pub(crate) fn start(speaker: bool) -> bool {
        unsafe {
            let session = shared_session();
            if session.is_null() {
                return false;
            }
            let category = ns_string("AVAudioSessionCategoryPlayAndRecord");
            let mode = ns_string("AVAudioSessionModeVoiceChat");
            if category.is_null() || mode.is_null() {
                return false;
            }
            let mut error: *mut AnyObject = std::ptr::null_mut();
            let category_ok: bool = msg_send![
                session,
                setCategory: category,
                mode: mode,
                options: OPTION_ALLOW_BLUETOOTH,
                error: &mut error
            ];
            let mut error: *mut AnyObject = std::ptr::null_mut();
            let active_ok: bool = msg_send![session, setActive: true, error: &mut error];
            let route_ok = set_speaker(speaker);
            tracing::info!(
                category_ok,
                active_ok,
                route_ok,
                speaker,
                "iOS call audio session started"
            );
            category_ok && active_ok
        }
    }

    /// Switches the in-call route between earpiece (`false`) and the
    /// loudspeaker (`true`).
    pub(crate) fn set_speaker(on: bool) -> bool {
        unsafe {
            let session = shared_session();
            if session.is_null() {
                return false;
            }
            let value = if on {
                PORT_OVERRIDE_SPEAKER
            } else {
                PORT_OVERRIDE_NONE
            };
            let mut error: *mut AnyObject = std::ptr::null_mut();
            let ok: bool = msg_send![session, overrideOutputAudioPort: value, error: &mut error];
            tracing::info!(ok, speaker = on, "iOS call audio route switched");
            ok
        }
    }

    /// Leaves the communication session; other apps' audio resumes.
    pub(crate) fn stop() -> bool {
        unsafe {
            let session = shared_session();
            if session.is_null() {
                return false;
            }
            let _ = set_speaker(false);
            let mut error: *mut AnyObject = std::ptr::null_mut();
            let ok: bool = msg_send![
                session,
                setActive: false,
                withOptions: NOTIFY_OTHERS_ON_DEACTIVATION,
                error: &mut error
            ];
            tracing::info!(ok, "iOS call audio session stopped");
            ok
        }
    }
}

// iOS app-switcher privacy shield (Android pair is planned:
// next-steps/android-recents-privacy-shield.md). When the app loses active
// status — the switcher is opened, Control Center / the notification shade is
// pulled, a system permission alert appears — iOS snapshots the window and
// that snapshot becomes the app-switcher card. Chat content must not leak
// into it, so an opaque cover styled like the boot splash — the entry-screen
// background plus the "V" mark + wordmark row in the resolved theme's
// palette — covers the key window
// synchronously inside the willResignActive handler (the system snapshots
// only after the handler returns) and is removed on didBecomeActive. The
// cover must be a native view: a webview/CSS overlay repaints asynchronously
// and loses the race with the snapshot. `WindowEvent::Suspended`/`Resumed`
// are not usable here — they map to entering/leaving the background, while
// the switcher opens with the app still foreground (resign-active only).
// Driven from Rust via objc2 like `ios_background` above — the generated
// gen/apple project stays untouched. The observer blocks run on the main
// queue and UIKit posts these notifications from the main thread, so the
// blocks execute synchronously in-place and never touch UIKit off the main
// thread.
#[cfg(target_os = "ios")]
pub(crate) mod ios_privacy_shield {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use block2::RcBlock;
    use objc2::encode::{Encode, Encoding};
    use objc2::runtime::{AnyObject, Bool};
    use objc2::{class, msg_send};

    // Minimal CoreGraphics geometry, hand-rolled so this stays a plain objc2
    // module without pulling in a UIKit/Foundation crate. CGFloat is f64 on
    // every target we ship (arm64).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CGPoint {
        x: f64,
        y: f64,
    }
    unsafe impl Encode for CGPoint {
        const ENCODING: Encoding =
            Encoding::Struct("CGPoint", &[Encoding::Double, Encoding::Double]);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CGSize {
        width: f64,
        height: f64,
    }
    unsafe impl Encode for CGSize {
        const ENCODING: Encoding =
            Encoding::Struct("CGSize", &[Encoding::Double, Encoding::Double]);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CGRect {
        origin: CGPoint,
        size: CGSize,
    }
    unsafe impl Encode for CGRect {
        const ENCODING: Encoding =
            Encoding::Struct("CGRect", &[CGPoint::ENCODING, CGSize::ENCODING]);
    }

    /// UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight —
    /// the cover tracks the window through rotation.
    const AUTORESIZING_WIDTH_AND_HEIGHT: usize = (1 << 1) | (1 << 4);
    /// All four flexible margins — keeps the logo row centered on rotation.
    const AUTORESIZING_FLEXIBLE_MARGINS: usize = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 5);

    /// Boot-splash geometry from index.html (`.boot-splash__logo` /
    /// `.boot-splash__mark`): 44pt rounded-12 mark, 10pt gap, 22pt bold type.
    const MARK_SIDE: f64 = 44.0;
    const MARK_CORNER_RADIUS: f64 = 12.0;
    const LOGO_GAP: f64 = 10.0;
    const LOGO_FONT_SIZE: f64 = 22.0;

    /// Whether the resolved UI theme is light. Drives the shield palette; the
    /// frontend updates it through the `set_privacy_shield_light` command on
    /// every theme change (the iOS mirror of Android's
    /// `applyRecentsCardColor`). Defaults to light — the Veyra default.
    static SHIELD_LIGHT: AtomicBool = AtomicBool::new(true);

    pub(crate) fn set_light(light: bool) {
        SHIELD_LIGHT.store(light, Ordering::SeqCst);
    }

    /// Boot-splash palette from index.html (`.boot-splash` light and dark).
    /// Keep in sync with the frontend splash — same rule as the Android
    /// `ENTRY_BACKGROUND_*` constants in MainActivity.kt.
    unsafe fn color(r: u8, g: u8, b: u8) -> *mut AnyObject {
        msg_send![
            class!(UIColor),
            colorWithRed: r as f64 / 255.0,
            green: g as f64 / 255.0,
            blue: b as f64 / 255.0,
            alpha: 1.0f64
        ]
    }

    /// The installed cover view (+1 from alloc/init, released in `hide`).
    /// Main-thread only; atomic solely because statics must be Sync. Doubles
    /// as the idempotence guard: a second resign-active is a no-op.
    static SHIELD_VIEW: AtomicUsize = AtomicUsize::new(0);

    unsafe fn ns_string(value: &str) -> *mut AnyObject {
        let Ok(value) = std::ffi::CString::new(value) else {
            return std::ptr::null_mut();
        };
        msg_send![class!(NSString), stringWithUTF8String: value.as_ptr()]
    }

    /// Registers the two lifecycle observers. Called once from setup; the
    /// observer tokens are deliberately kept forever — the shield lives as
    /// long as the process.
    pub(crate) fn install() {
        unsafe {
            let center: *mut AnyObject = msg_send![class!(NSNotificationCenter), defaultCenter];
            let queue: *mut AnyObject = msg_send![class!(NSOperationQueue), mainQueue];
            let resign = ns_string("UIApplicationWillResignActiveNotification");
            let active = ns_string("UIApplicationDidBecomeActiveNotification");
            if center.is_null() || queue.is_null() || resign.is_null() || active.is_null() {
                tracing::warn!("iOS privacy shield not installed: notification center unavailable");
                return;
            }
            let show = RcBlock::new(|_note: *mut AnyObject| show_shield());
            let _: *mut AnyObject = msg_send![
                center,
                addObserverForName: resign,
                object: std::ptr::null_mut::<AnyObject>(),
                queue: queue,
                usingBlock: &*show
            ];
            let hide = RcBlock::new(|_note: *mut AnyObject| hide_shield());
            let _: *mut AnyObject = msg_send![
                center,
                addObserverForName: active,
                object: std::ptr::null_mut::<AnyObject>(),
                queue: queue,
                usingBlock: &*hide
            ];
            tracing::info!("iOS privacy shield installed (app-switcher snapshot cover)");
        }
    }

    /// Covers the key window. Runs synchronously inside willResignActive on
    /// the main thread, so the cover is in place before iOS snapshots.
    fn show_shield() {
        if SHIELD_VIEW.load(Ordering::SeqCst) != 0 {
            return;
        }
        unsafe {
            let app: *mut AnyObject = msg_send![class!(UIApplication), sharedApplication];
            if app.is_null() {
                return;
            }
            let mut window: *mut AnyObject = msg_send![app, keyWindow];
            if window.is_null() {
                // keyWindow can be nil mid-transition; any app window works —
                // the cover only has to win the snapshot.
                let windows: *mut AnyObject = msg_send![app, windows];
                if !windows.is_null() {
                    window = msg_send![windows, firstObject];
                }
            }
            if window.is_null() {
                tracing::warn!("iOS privacy shield: no window to cover");
                return;
            }
            let bounds: CGRect = msg_send![window, bounds];
            let view: *mut AnyObject = msg_send![class!(UIView), alloc];
            let view: *mut AnyObject = msg_send![view, initWithFrame: bounds];
            if view.is_null() {
                return;
            }
            let _: () = msg_send![view, setAutoresizingMask: AUTORESIZING_WIDTH_AND_HEIGHT];
            let light = SHIELD_LIGHT.load(Ordering::SeqCst);
            let background = if light {
                color(0xfb, 0xfd, 0xfb)
            } else {
                color(0x07, 0x14, 0x0e)
            };
            if !background.is_null() {
                let _: () = msg_send![view, setBackgroundColor: background];
            }
            add_boot_splash_logo(view, bounds, light);
            let _: () = msg_send![window, addSubview: view];
            SHIELD_VIEW.store(view as usize, Ordering::SeqCst);
        }
    }

    /// Recreates the boot-splash logo row (`.boot-splash__logo`) natively:
    /// the rounded "V" mark next to the "veyra" wordmark, centered in the
    /// cover. The wordmark deliberately says "veyra", not the splash's
    /// "veyra.social" — field ratification 2026-07-31. Purely cosmetic —
    /// bails out on any allocation failure and leaves the plain
    /// entry-background cover, which is all the privacy guarantee needs.
    unsafe fn add_boot_splash_logo(shield: *mut AnyObject, bounds: CGRect, light: bool) {
        let (mark_bg, mark_fg, word_fg) = if light {
            (
                color(0x05, 0x68, 0x4b),
                color(0xc7, 0xf1, 0x1f),
                color(0x05, 0x68, 0x4b),
            )
        } else {
            (
                color(0x14, 0xc7, 0x78),
                color(0x07, 0x14, 0x0e),
                color(0x2b, 0xd9, 0x88),
            )
        };
        let font: *mut AnyObject = msg_send![class!(UIFont), boldSystemFontOfSize: LOGO_FONT_SIZE];

        let mark: *mut AnyObject = msg_send![class!(UILabel), alloc];
        let mark: *mut AnyObject = msg_send![mark, initWithFrame: CGRect {
            origin: CGPoint { x: 0.0, y: 0.0 },
            size: CGSize { width: MARK_SIDE, height: MARK_SIDE },
        }];
        if mark.is_null() {
            return;
        }
        let _: () = msg_send![mark, setText: ns_string("V")];
        if !font.is_null() {
            let _: () = msg_send![mark, setFont: font];
        }
        if !mark_fg.is_null() {
            let _: () = msg_send![mark, setTextColor: mark_fg];
        }
        if !mark_bg.is_null() {
            let _: () = msg_send![mark, setBackgroundColor: mark_bg];
        }
        // NSTextAlignmentCenter == 1.
        let _: () = msg_send![mark, setTextAlignment: 1usize];
        let layer: *mut AnyObject = msg_send![mark, layer];
        if !layer.is_null() {
            let _: () = msg_send![layer, setCornerRadius: MARK_CORNER_RADIUS];
            let _: () = msg_send![layer, setMasksToBounds: Bool::from(true)];
        }

        let word: *mut AnyObject = msg_send![class!(UILabel), alloc];
        let word: *mut AnyObject = msg_send![word, init];
        if word.is_null() {
            let _: () = msg_send![mark, release];
            return;
        }
        let _: () = msg_send![word, setText: ns_string("veyra")];
        if !font.is_null() {
            let _: () = msg_send![word, setFont: font];
        }
        if !word_fg.is_null() {
            let _: () = msg_send![word, setTextColor: word_fg];
        }
        let _: () = msg_send![word, sizeToFit];
        let word_frame: CGRect = msg_send![word, frame];

        let row_width = MARK_SIDE + LOGO_GAP + word_frame.size.width;
        let row: *mut AnyObject = msg_send![class!(UIView), alloc];
        let row: *mut AnyObject = msg_send![row, initWithFrame: CGRect {
            origin: CGPoint {
                x: (bounds.size.width - row_width) / 2.0,
                y: (bounds.size.height - MARK_SIDE) / 2.0,
            },
            size: CGSize { width: row_width, height: MARK_SIDE },
        }];
        if row.is_null() {
            let _: () = msg_send![mark, release];
            let _: () = msg_send![word, release];
            return;
        }
        let _: () = msg_send![row, setAutoresizingMask: AUTORESIZING_FLEXIBLE_MARGINS];
        let _: () = msg_send![word, setFrame: CGRect {
            origin: CGPoint {
                x: MARK_SIDE + LOGO_GAP,
                y: (MARK_SIDE - word_frame.size.height) / 2.0,
            },
            size: word_frame.size,
        }];
        let _: () = msg_send![row, addSubview: mark];
        let _: () = msg_send![row, addSubview: word];
        let _: () = msg_send![shield, addSubview: row];
        // The superviews hold the retains now; balance our alloc/init +1s.
        let _: () = msg_send![mark, release];
        let _: () = msg_send![word, release];
        let _: () = msg_send![row, release];
    }

    /// Removes the cover on didBecomeActive. No-op when nothing is installed
    /// (e.g. the first activation at launch).
    fn hide_shield() {
        let view = SHIELD_VIEW.swap(0, Ordering::SeqCst);
        if view == 0 {
            return;
        }
        let view = view as *mut AnyObject;
        unsafe {
            let _: () = msg_send![view, removeFromSuperview];
            // Balance the alloc/init retain; the superview dropped its own
            // hold in removeFromSuperview.
            let _: () = msg_send![view, release];
        }
    }
}

fn is_autostart_launch() -> bool {
    std::env::args_os().any(|arg| arg == VEYRA_AUTOSTART_ARG)
}

fn data_dir_arg() -> Option<PathBuf> {
    let mut args = std::env::args_os();
    while let Some(arg) = args.next() {
        if arg == OsStr::new(VEYRA_DATA_DIR_ARG) {
            return args.next().map(PathBuf::from);
        }
        if let Some(arg) = arg.to_str() {
            if let Some(value) = arg.strip_prefix("--veyra-data-dir=") {
                return Some(PathBuf::from(value.trim_matches('"')));
            }
        }
    }
    None
}

#[cfg(desktop)]
fn autostart_args_for_data_dir(data_dir: &Path) -> Vec<String> {
    let mut args = vec![VEYRA_AUTOSTART_ARG.to_string()];
    #[cfg(windows)]
    args.push(format!(
        "{}=\"{}\"",
        VEYRA_DATA_DIR_ARG,
        data_dir.to_string_lossy()
    ));
    #[cfg(not(windows))]
    {
        let _ = data_dir;
    }
    args
}

fn resolve_data_dir(app: &tauri::App) -> PathBuf {
    if let Ok(data_dir) = std::env::var("VEYRA_DATA_DIR") {
        return PathBuf::from(data_dir);
    }

    if let Some(data_dir) = data_dir_arg() {
        return data_dir;
    }

    #[cfg(mobile)]
    if let Ok(data_dir) = app.path().app_data_dir() {
        return data_dir;
    }

    // macOS desktop: when the .app is launched by Finder/launchd,
    // `std::env::current_dir()` resolves to "/" (the root system volume,
    // read-only since Catalina). Writing the SQLite vault under
    // "/.veyra-data" fails with EROFS errno 30. Skip the current-dir
    // probe here and go straight to the platform's standard
    // app_data_dir (typically ~/Library/Application Support/app.veyra.messenger).
    // Windows and Linux keep the existing portable-by-current_dir
    // convention so installed profiles there are not relocated.
    #[cfg(all(target_os = "macos", not(mobile)))]
    if let Ok(data_dir) = app.path().app_data_dir() {
        return data_dir;
    }

    #[cfg(all(target_os = "windows", not(mobile)))]
    if is_autostart_launch() {
        if let Ok(current_dir) = std::env::current_dir() {
            let portable_data_dir = current_dir.join(".veyra-data");
            if portable_data_dir.is_dir() {
                return portable_data_dir;
            }
        }
        if let Ok(data_dir) = app.path().app_data_dir() {
            return data_dir;
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        return current_dir.join(".veyra-data");
    }

    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from(".").join(".veyra-data"))
}

/// Parses one HTTP byte range. Malformed and multi-range inputs stay explicit
/// so they can become HTTP 416 instead of accidentally decrypting a full file.
fn parse_media_range(header: Option<&str>) -> crate::storage::db::AttachmentStreamRange {
    use crate::storage::db::AttachmentStreamRange;

    let Some(header) = header else {
        return AttachmentStreamRange::Full;
    };
    let header = header.trim();
    let Some((unit, spec)) = header.split_once('=') else {
        return AttachmentStreamRange::Invalid;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
        return AttachmentStreamRange::Invalid;
    }
    let Some((start, end)) = spec.trim().split_once('-') else {
        return AttachmentStreamRange::Invalid;
    };
    let start = start.trim();
    let end = end.trim();
    match (start.is_empty(), end.is_empty()) {
        (true, true) => AttachmentStreamRange::Invalid,
        (true, false) => end
            .parse::<u64>()
            .map(|length| AttachmentStreamRange::Suffix { length })
            .unwrap_or(AttachmentStreamRange::Invalid),
        (false, true) => start
            .parse::<u64>()
            .map(|start| AttachmentStreamRange::OpenEnded { start })
            .unwrap_or(AttachmentStreamRange::Invalid),
        (false, false) => match (start.parse::<u64>(), end.parse::<u64>()) {
            (Ok(start), Ok(end_inclusive)) if start <= end_inclusive => {
                AttachmentStreamRange::Bounded {
                    start,
                    end_inclusive,
                }
            }
            _ => AttachmentStreamRange::Invalid,
        },
    }
}

#[derive(Clone, Copy, Default)]
struct MediaRequestAggregate {
    requests: u64,
    returned_bytes: u64,
    decrypt_millis: u64,
}

fn media_attachment_tag(attachment_id: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(attachment_id.as_bytes());
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn record_media_request(
    attachment_tag: &str,
    returned_bytes: u64,
    decrypt_millis: u64,
) -> MediaRequestAggregate {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static AGGREGATES: OnceLock<Mutex<HashMap<String, MediaRequestAggregate>>> = OnceLock::new();
    let mut aggregates = AGGREGATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if aggregates.len() >= 256 && !aggregates.contains_key(attachment_tag) {
        aggregates.clear();
    }
    let aggregate = aggregates.entry(attachment_tag.to_string()).or_default();
    aggregate.requests = aggregate.requests.saturating_add(1);
    aggregate.returned_bytes = aggregate.returned_bytes.saturating_add(returned_bytes);
    aggregate.decrypt_millis = aggregate.decrypt_millis.saturating_add(decrypt_millis);
    *aggregate
}

fn media_request_purpose(uri: &tauri::http::Uri) -> &'static str {
    if uri.query().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair.eq_ignore_ascii_case("purpose=poster"))
    }) {
        "poster"
    } else {
        "playback"
    }
}

fn media_origin_label(origin: Option<&str>) -> &'static str {
    match origin.map(str::trim) {
        None | Some("") => "absent",
        Some("http://tauri.localhost") | Some("https://tauri.localhost") => "tauri-app",
        Some(origin)
            if origin.starts_with("http://localhost:")
                || origin.starts_with("http://127.0.0.1:") =>
        {
            "vite-dev"
        }
        Some(_) => "other",
    }
}

/// Extracts the attachment id from a `veyra-media` request URI.
///
/// Path forms differ per platform: macOS/Linux deliver
/// `veyra-media://attachment/<id>` ("attachment" becomes the host),
/// Windows/Android deliver `http(s)://veyra-media.localhost/attachment/<id>`
/// (the host is the scheme's synthetic domain). On top of that,
/// `convertFileSrc` percent-encodes its path argument, so the separator can
/// arrive as `%2F` (`/attachment%2F<id>`); decode before splitting. Only our
/// own frontend talks to this scheme and ids are UUIDs, so a decoded `/`
/// can't smuggle extra segments.
fn media_attachment_id(uri: &tauri::http::Uri) -> Option<String> {
    let path = percent_encoding::percent_decode_str(uri.path())
        .decode_utf8()
        .ok()?;
    let mut segments: Vec<&str> = uri
        .host()
        .into_iter()
        .chain(path.split('/'))
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments
        .first()
        .is_some_and(|host| *host == "localhost" || host.ends_with(".localhost"))
    {
        segments.remove(0);
    }
    match segments.as_slice() {
        ["attachment", attachment_id] => Some((*attachment_id).to_string()),
        _ => None,
    }
}

/// `veyra-media://attachment/<id>` — one ranged, decrypted slice of an
/// attachment out of the encrypted store. Runs on a dedicated thread per
/// request (decryption is CPU-bound and must never block the main thread).
fn serve_veyra_media(
    app_handle: &tauri::AppHandle,
    uri: &tauri::http::Uri,
    range_header: Option<String>,
    origin_header: Option<String>,
) -> tauri::http::Response<Vec<u8>> {
    use tauri::http::{header, Response, StatusCode};
    use tauri::Manager as _;

    fn status_response(status: StatusCode) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::CONTENT_LENGTH, "0")
            .body(Vec::new())
            .unwrap_or_else(|_| Response::new(Vec::new()))
    }

    let Some(attachment_id) = media_attachment_id(uri) else {
        tracing::debug!("veyra-media: unrecognized path");
        return status_response(StatusCode::NOT_FOUND);
    };
    let attachment_id = attachment_id.as_str();
    let attachment_tag = media_attachment_tag(attachment_id);
    let purpose = media_request_purpose(uri);
    let origin = media_origin_label(origin_header.as_deref());
    let range = parse_media_range(range_header.as_deref());
    if matches!(range, crate::storage::db::AttachmentStreamRange::Invalid) {
        tracing::warn!(
            attachment = %attachment_tag,
            purpose,
            origin,
            "veyra-media: malformed or multi-range request"
        );
    }

    let state = app_handle.state::<AppState>();
    let Some(profile) = state.profile() else {
        return status_response(StatusCode::FORBIDDEN);
    };
    let data_dir = state.data_dir();
    let conn = match crate::storage::db::open_db(&data_dir) {
        Ok(conn) => conn,
        Err(_) => return status_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let decrypt_started = std::time::Instant::now();
    let read = match crate::storage::db::read_attachment_stream_slice(
        &conn,
        &data_dir,
        &profile.storage_key,
        attachment_id,
        range,
    ) {
        Ok(slice) => slice,
        Err(crate::errors::AppError::MessageNotFound) => {
            return status_response(StatusCode::NOT_FOUND)
        }
        Err(_) => return status_response(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let decrypt_millis = decrypt_started.elapsed().as_millis() as u64;
    let slice = match read {
        crate::storage::db::AttachmentStreamRead::Slice(slice) => slice,
        crate::storage::db::AttachmentStreamRead::Unsatisfiable { total_len } => {
            tracing::debug!(
                attachment = %attachment_tag,
                purpose,
                origin,
                range = ?range,
                status = 416,
                total_len,
                decrypt_millis,
                outcome = "response_ready",
                "veyra-media request"
            );
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_RANGE, format!("bytes */{total_len}"))
                .header(header::CONTENT_LENGTH, "0")
                .header(header::CACHE_CONTROL, "no-store")
                .body(Vec::new())
                .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let end = slice.range_start + slice.bytes.len() as u64;
    let returned_bytes = slice.bytes.len() as u64;
    let aggregate = record_media_request(&attachment_tag, returned_bytes, decrypt_millis);
    let status = if range.is_partial() { 206 } else { 200 };
    tracing::debug!(
        attachment = %attachment_tag,
        purpose,
        origin,
        range = ?range,
        status,
        span_start = slice.range_start,
        span_end_exclusive = end,
        total_len = slice.total_len,
        returned_bytes,
        decrypt_millis,
        aggregate_requests = aggregate.requests,
        aggregate_bytes = aggregate.returned_bytes,
        aggregate_decrypt_millis = aggregate.decrypt_millis,
        outcome = "response_ready",
        "veyra-media request"
    );
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, slice.mime_type.as_str())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, slice.bytes.len().to_string())
        .header(header::CACHE_CONTROL, "no-store");
    builder = if range.is_partial() {
        builder.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                slice.range_start,
                end.saturating_sub(1),
                slice.total_len
            ),
        )
    } else {
        builder.status(StatusCode::OK)
    };
    builder
        .body(slice.bytes)
        .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_filter = if cfg!(target_os = "android") {
        // On Android we have no way to set RUST_LOG, so default to a verbose-enough
        // filter to see DNS resolution and dial outcomes in `adb logcat` while
        // keeping noisy crates (rustls, mio, hickory_proto) at warn.
        "info,libp2p_swarm=debug,libp2p_dns=debug,libp2p_tcp=debug,libp2p_quic=debug,\
         libp2p_relay=trace,multistream_select=debug,veyra_messenger=debug,connection_manager=debug,\
         rustls=warn,mio=warn,hickory_proto=warn"
    } else {
        "info"
    };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        // Console/logcat layer plus the optional file layer (field
        // diagnostics for devices whose logcat buffer churns away the
        // night). The file writer is a no-op until the user's toggle is
        // loaded in setup; both layers share the same filter, so the file
        // shows exactly the stream logcat would have shown.
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(logging::FileLogMakeWriter),
            )
            .init();
    }

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        // External links: v2 webviews block `target="_blank"` navigation, so
        // every outbound URL goes through the opener plugin (all platforms).
        .plugin(tauri_plugin_opener::init());
    // Desktop window memory: restore the last window size/position (and
    // maximized state) on every launch. Registered on the Builder, not in
    // `.setup` — the main window is created before setup runs, so a
    // setup-time registration would miss the restore hook. First launch has
    // no saved state and keeps the config's `center: true` placement.
    // Visibility is deliberately excluded: hide/show stays owned by the
    // autostart/tray logic.
    #[cfg(desktop)]
    let builder = builder.plugin(
        tauri_plugin_window_state::Builder::default()
            .with_state_flags(
                tauri_plugin_window_state::StateFlags::SIZE
                    | tauri_plugin_window_state::StateFlags::POSITION
                    | tauri_plugin_window_state::StateFlags::MAXIMIZED,
            )
            .build(),
    );
    builder
        // veyra-media: streams attachment previews straight out of the
        // encrypted store (chunked v2 containers) with HTTP Range support —
        // <img>/<video> point at it, so attachment bytes never cross the IPC
        // bridge as base64 and video seeking works. 403 while the profile is
        // locked; no plaintext ever lands on disk.
        .register_asynchronous_uri_scheme_protocol("veyra-media", |ctx, request, responder| {
            let app_handle = ctx.app_handle().clone();
            let uri = request.uri().clone();
            let range_header = request
                .headers()
                .get("range")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let origin_header = request
                .headers()
                .get("origin")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            std::thread::spawn(move || {
                responder.respond(serve_veyra_media(
                    &app_handle,
                    &uri,
                    range_header,
                    origin_header,
                ));
                tracing::trace!(outcome = "handed_to_webview", "veyra-media response");
            });
        })
        .setup(|app| {
            let base_dir = resolve_data_dir(app);
            // Multi-profile layout: the resolved dir is the app BASE; the
            // active profile lives in profiles/<id>/ (legacy single-profile
            // contents migrate there on first start — synchronously, before
            // the schema warm-up and AppState, so the file moves race
            // nothing). On failure fall back to the legacy flat layout:
            // running like yesterday beats not starting.
            let data_dir = match storage::profile_registry::ensure_profile_layout(&base_dir) {
                Ok(active_dir) => active_dir,
                Err(err) => {
                    tracing::error!(?err, "profile layout failed; using base data dir");
                    base_dir.clone()
                }
            };

            #[cfg(desktop)]
            {
                // Autostart always points at the BASE dir: the profile
                // registry decides the active profile at each launch.
                #[cfg(target_os = "macos")]
                let autostart_builder = tauri_plugin_autostart::Builder::new()
                    .args(autostart_args_for_data_dir(&base_dir))
                    .macos_launcher(tauri_plugin_autostart::MacosLauncher::LaunchAgent);
                #[cfg(not(target_os = "macos"))]
                let autostart_builder = tauri_plugin_autostart::Builder::new()
                    .args(autostart_args_for_data_dir(&base_dir));
                app.handle().plugin(autostart_builder.build())?;

                #[cfg(all(target_os = "windows", not(mobile)))]
                if !is_autostart_launch() {
                    use tauri_plugin_autostart::ManagerExt as _;
                    match app.handle().autolaunch().is_enabled() {
                        Ok(true) => {
                            if let Err(err) = app.handle().autolaunch().enable() {
                                tracing::warn!(?err, "failed to refresh Windows autostart entry");
                            }
                        }
                        Ok(false) => {}
                        Err(err) => tracing::debug!(?err, "failed to read Windows autostart state"),
                    }
                }
            }

            // Android: <video> cannot stream large files over the intercepted
            // veyra-media scheme (capped 206 windows stall the WebView media
            // pipeline) — serve video through a token-guarded loopback HTTP
            // server instead. Desktop/iOS keep the custom protocol.
            #[cfg(target_os = "android")]
            media_server::start(app.handle().clone());

            let app_handle = app.handle().clone();
            // Warm the schema migration once, off the main thread, before the
            // webview's first IPC call lands. `open_db` migrates exactly once
            // per data dir (guarded), so this just pays that one-time cost here
            // instead of inside the first `get_app_status`, keeping the
            // pre-unlock splash from blocking on it.
            {
                let warm_dir = data_dir.clone();
                #[cfg(target_os = "ios")]
                let warm_app = app_handle.clone();
                std::thread::spawn(move || {
                    match storage::db::open_db(&warm_dir) {
                        Ok(conn) => {
                            // The file-log toggle lives in app_meta; apply it
                            // as soon as the schema is warm so an enabled log
                            // captures the whole session from here on.
                            let enabled = storage::db::file_logging_enabled(&conn).unwrap_or(false);
                            logging::configure(logging::log_directory(&warm_dir), enabled);
                            #[cfg(target_os = "ios")]
                            set_ios_keep_screen_on(
                                &warm_app,
                                storage::db::read_keep_screen_on(&conn)
                                    .unwrap_or_else(|_| storage::db::default_keep_screen_on()),
                            );
                        }
                        Err(err) => {
                            tracing::warn!(?err, "startup schema warm-up failed");
                            logging::configure(logging::log_directory(&warm_dir), false);
                        }
                    }
                });
            }
            app.manage(AppState::new(base_dir, data_dir, app_handle));
            #[cfg(target_os = "ios")]
            {
                let lifecycle_app = app.handle().clone();
                apply_ios_keep_screen_on_foreground(&lifecycle_app);
                disable_ios_input_accessory_bar();
                ios_privacy_shield::install();
                if let Some(window) = app.get_webview_window("main") {
                    window.on_window_event(move |event| match event {
                        tauri::WindowEvent::Resumed => {
                            apply_ios_keep_screen_on_foreground(&lifecycle_app);
                            ios_background::end_background_task();
                        }
                        tauri::WindowEvent::Suspended => {
                            set_ios_idle_timer_disabled_on_main(&lifecycle_app, false);
                            ios_background::begin_background_task();
                        }
                        _ => {}
                    });
                }
            }
            #[cfg(desktop)]
            {
                setup_desktop_tray(app)?;
                setup_close_to_tray(app);
            }
            // Show the main window from the native side unless this is a
            // background autostart launch. main.tsx has the same safety net.
            // catch on a dynamic import — the window stayed invisible while
            #[cfg(not(mobile))]
            if let Some(window) = app.get_webview_window("main") {
                let hide_autostart =
                    is_autostart_launch() && db_read_close_to_tray(app).unwrap_or(true);
                if hide_autostart {
                    let _ = window.hide();
                } else {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_local_profiles,
            unlock_local_profile,
            create_local_profile,
            prepare_local_profile_for_import,
            mark_active_local_profile,
            get_background_restriction_status,
            get_update_check_status,
            get_media_server_info,
            quit_app,
            set_update_auto_check,
            check_app_update,
            auto_check_app_update,
            delete_local_profile,
            export_local_profile_backup,
            export_local_profile_backup_temp_file,
            serialize_local_profile_backup,
            init_profile,
            unlock_profile,
            change_master_password,
            set_duress_password,
            clear_duress_password,
            transform_to_decoy_profile,
            lock_profile,
            get_my_profile,
            rename_profile,
            set_my_avatar_jpeg,
            clear_my_avatar,
            set_my_profile_extensions,
            sync_peer_avatar_for_contact,
            sync_peer_profile_card_for_contact,
            generate_invite_string,
            generate_invite_with_routing,
            get_listen_addresses,
            begin_device_pairing,
            cancel_device_pairing,
            complete_device_pairing,
            list_own_devices,
            set_own_device_enabled,
            rename_own_device,
            sync_own_device,
            restore_chat_history,
            restore_chat_history_from_contact,
            respond_chat_restore_consent,
            get_attachment_receive_settings,
            set_attachment_receive_settings,
            get_contact_attachment_denied_kinds,
            set_contact_attachment_denied_kinds,
            accept_attachment,
            decline_attachment,
            pause_attachment_transfer,
            resume_attachment_transfer,
            cancel_attachment_transfer,
            request_attachment_transfer,
            resend_attachment_as_new,
            get_device_sync_mode,
            set_device_sync_mode,
            get_file_logging_status,
            set_file_logging_enabled,
            add_contact,
            parse_invite_string,
            list_contacts,
            refresh_contact_presence,
            verify_contact,
            accept_contact_request,
            reject_contact_request,
            block_contact,
            unblock_contact,
            rename_contact,
            delete_contact,
            delete_chat,
            set_chat_pinned,
            get_chat_statistics,
            clear_chat_history,
            create_direct_chat,
            list_chats,
            mark_chat_opened,
            list_call_log,
            get_current_call,
            get_call_ice_servers,
            report_call_media_ice_outcome,
            request_system_microphone_access,
            trigger_haptic,
            set_privacy_shield_light,
            log_call_media_diagnostic,
            call_audio_session_start,
            call_audio_session_set_speaker,
            call_audio_session_stop,
            begin_call,
            send_call_offer,
            start_call,
            answer_call,
            send_call_ice_candidate,
            fail_call,
            hangup_call,
            reject_call,
            no_microphone_call,
            timeout_call,
            get_ui_locale,
            set_ui_locale,
            get_ui_prefs,
            set_ui_prefs,
            get_notification_prefs,
            set_notification_prefs,
            get_offline_delivery_enabled,
            set_offline_delivery_enabled,
            set_desktop_badge_state,
            get_desktop_integration_prefs,
            set_close_to_tray_enabled,
            set_autostart_enabled,
            should_show_main_window_on_startup,
            get_chat_messages,
            get_chat_messages_page,
            get_chat_message_states,
            get_chat_messages_delta,
            get_chat_transport,
            send_message,
            send_attachment_message,
            begin_attachment_upload,
            append_attachment_upload,
            abort_attachment_upload,
            finalize_attachment_upload,
            export_attachment_to_temp,
            delete_attachment_temp_file,
            get_attachment_bytes,
            get_attachment_poster,
            set_attachment_poster,
            save_attachment,
            share_attachment,
            forward_attachment_message,
            delete_attachment_local,
            resend_attachment,
            edit_message,
            delete_message,
            retry_message,
            clear_outbox,
            connect_peer,
            list_connected_peers,
            add_bootstrap_node,
            probe_bootstrap_node,
            add_probed_bootstrap_node,
            list_bootstrap_nodes,
            remove_bootstrap_node,
            test_bootstrap_node,
            fetch_node_passport,
            connect_bootstrap_nodes,
            block_bootstrap_node,
            export_bootstrap_catalog,
            import_bootstrap_catalog,
            import_access_bundle,
            preview_access_bundle,
            import_access_bundle_text,
            export_access_bundle,
            list_access_bundle_imports,
            remove_access_bundle_import,
            get_bootstrap_network_summary,
            get_network_routes_status,
            request_bootstrap_catalog_from_peer,
            request_bootstrap_catalog_from_connected_peers,
            get_reachability_status,
            get_connect_policy,
            set_connect_policy,
            list_proxies,
            add_proxy,
            update_proxy,
            remove_proxy,
            parse_proxy_line,
            get_proxy_status,
            test_proxy,
            enable_proxy,
            disable_proxy,
            list_relay_reservations,
            force_relay_refresh,
            export_backup,
            inspect_backup,
            import_backup,
            serialize_backup,
            export_backup_temp_file,
            create_backup_import_temp_file,
            delete_backup_temp_file,
            inspect_backup_bytes,
            import_backup_bytes,
            restart_app,
            get_app_status,
            list_pending_outbox_per_peer,
            notify_app_resumed,
            notify_app_backgrounded,
            get_version_info
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Veyra Messenger");
}

/// True once an explicit quit was chosen (tray "Выйти" or the hamburger
/// "Закрыть" command) — the close-to-tray handler then lets the window
/// actually close instead of hiding it. A static, not setup-local state:
/// the `quit_app` command needs to flip it too (Ubuntu's stock GNOME shows
/// no tray icon, so the in-app menu is the only reachable exit there).
#[cfg(desktop)]
static QUITTING: AtomicBool = AtomicBool::new(false);

#[cfg(desktop)]
pub(crate) fn note_quitting() {
    QUITTING.store(true, Ordering::SeqCst);
}

#[cfg(desktop)]
fn setup_desktop_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show_i = MenuItem::with_id(app, "show", "Открыть Veyra", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

    #[cfg(target_os = "macos")]
    let last_left_click = Arc::new(Mutex::new(None::<Instant>));
    let initial_icon = get_tray_icon(TrayState::Offline)
        .unwrap_or_else(|| app.default_window_icon().unwrap().clone());
    let builder = TrayIconBuilder::with_id(VEYRA_TRAY_ID)
        .icon(initial_icon)
        .tooltip("Veyra")
        .menu(&menu)
        .show_menu_on_left_click(false);

    #[cfg(target_os = "macos")]
    let builder = builder.icon_as_template(true);

    builder
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => {
                note_quitting();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event({
            #[cfg(target_os = "macos")]
            let last_left_click = last_left_click.clone();
            move |tray, event| match event {
                TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => show_main_window(tray.app_handle()),
                #[cfg(target_os = "macos")]
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Down,
                    ..
                } => {
                    let now = Instant::now();
                    let mut last_click = match last_left_click.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    if last_click
                        .map(|previous| {
                            now.duration_since(previous) <= MACOS_TRAY_DOUBLE_CLICK_WINDOW
                        })
                        .unwrap_or(false)
                    {
                        *last_click = None;
                        show_main_window(tray.app_handle());
                    } else {
                        *last_click = Some(now);
                    }
                }
                _ => {}
            }
        })
        .build(app)?;

    Ok(())
}

#[cfg(desktop)]
fn setup_close_to_tray(app: &mut tauri::App) {
    let data_dir = resolve_data_dir(app);
    if let Some(window) = app.get_webview_window("main") {
        let close_window = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if QUITTING.load(Ordering::SeqCst) {
                    return;
                }
                let close_to_tray = crate::storage::db::open_db(&data_dir)
                    .and_then(|conn| crate::storage::db::read_close_to_tray_enabled(&conn))
                    .unwrap_or(true);
                if close_to_tray {
                    api.prevent_close();
                    let _ = close_window.hide();
                }
            }
        });
    }
}

#[cfg(desktop)]
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn db_read_close_to_tray(app: &tauri::App) -> crate::errors::AppResult<bool> {
    let data_dir = resolve_data_dir(app);
    let conn = crate::storage::db::open_db(&data_dir)?;
    crate::storage::db::read_close_to_tray_enabled(&conn)
}

#[cfg(test)]
mod media_uri_tests {
    use super::{media_attachment_id, parse_media_range};
    use crate::storage::db::AttachmentStreamRange;

    fn id_of(uri: &str) -> Option<String> {
        media_attachment_id(&uri.parse::<tauri::http::Uri>().expect("valid uri"))
    }

    #[test]
    fn android_windows_synthetic_host_plain_path() {
        assert_eq!(
            id_of("http://veyra-media.localhost/attachment/abc-123").as_deref(),
            Some("abc-123")
        );
        assert_eq!(
            id_of("https://veyra-media.localhost/attachment/abc-123").as_deref(),
            Some("abc-123")
        );
    }

    #[test]
    fn percent_encoded_separator_from_convert_file_src() {
        // convertFileSrc runs the path through encodeURIComponent, so the
        // whole `attachment/<id>` argument arrives as one encoded segment.
        assert_eq!(
            id_of("http://veyra-media.localhost/attachment%2Fabc-123").as_deref(),
            Some("abc-123")
        );
        assert_eq!(
            id_of("veyra-media://localhost/attachment%2Fabc-123").as_deref(),
            Some("abc-123")
        );
    }

    #[test]
    fn macos_linux_attachment_as_host() {
        assert_eq!(
            id_of("veyra-media://attachment/abc-123").as_deref(),
            Some("abc-123")
        );
        assert_eq!(
            id_of("veyra-media://localhost/attachment/abc-123").as_deref(),
            Some("abc-123")
        );
    }

    #[test]
    fn rejects_unknown_shapes() {
        assert_eq!(id_of("http://veyra-media.localhost/attachment"), None);
        assert_eq!(id_of("http://veyra-media.localhost/other/abc"), None);
        assert_eq!(id_of("http://veyra-media.localhost/attachment/a/b"), None);
        assert_eq!(id_of("http://veyra-media.localhost/"), None);
    }

    #[test]
    fn parses_single_http_byte_ranges() {
        assert_eq!(parse_media_range(None), AttachmentStreamRange::Full);
        assert_eq!(
            parse_media_range(Some("bytes=4-9")),
            AttachmentStreamRange::Bounded {
                start: 4,
                end_inclusive: 9,
            }
        );
        assert_eq!(
            parse_media_range(Some("bytes=4-")),
            AttachmentStreamRange::OpenEnded { start: 4 }
        );
        assert_eq!(
            parse_media_range(Some("bytes=-512")),
            AttachmentStreamRange::Suffix { length: 512 }
        );
    }

    #[test]
    fn rejects_malformed_reversed_and_multi_ranges() {
        for header in [
            "items=0-1",
            "bytes=",
            "bytes=-",
            "bytes=9-4",
            "bytes=abc-4",
            "bytes=1-abc",
            "bytes=0-1,4-5",
        ] {
            assert_eq!(
                parse_media_range(Some(header)),
                AttachmentStreamRange::Invalid,
                "header={header}"
            );
        }
    }
}
