//! User notifications through `UNUserNotificationCenter` (the Swift `AppModel`'s notification code): the
//! authorization request, posting with `userInfo`, removing a delivered notification, showing notifications in
//! the foreground (`willPresent` → banner and sound) and the click callback (`didReceive`, with the `userInfo`
//! strings).
//!
//! Only call these from a real app bundle: `UNUserNotificationCenter.currentNotificationCenter` raises an
//! Objective-C exception (and aborts) in a process without a bundle identifier, exactly as the Swift app checked
//! `Bundle.main.bundleIdentifier != nil` first.
//!
//! Audit notes: everything goes through the safe `objc2-user-notifications` bindings, except `setUserInfo`
//! (unsafe because the dictionary must hold property-list objects only: ours holds `NSString`s) and the cast of
//! the typed string dictionary to the untyped `NSDictionary` it is (`Retained::cast_unchecked`). The delegate
//! object lives for the rest of the process (the center keeps only a weak reference), and its methods only read
//! the response's `userInfo` and call the completion handler.
#![allow(unsafe_code)]

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread, define_class, msg_send};
use objc2_foundation::{NSArray, NSDictionary, NSError, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotification, UNNotificationPresentationOptions,
    UNNotificationRequest, UNNotificationResponse, UNUserNotificationCenter, UNUserNotificationCenterDelegate,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// A click on a notification: its `userInfo` (string values only).
pub type ClickHandler = Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>;

static ON_CLICK: OnceLock<ClickHandler> = OnceLock::new();

define_class!(
    // SAFETY: NSObject has no subclassing requirements; the class has no ivars and does not implement `Drop`.
    #[unsafe(super(NSObject))]
    #[name = "MacVPNNotificationDelegate"]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl UNUserNotificationCenterDelegate for Delegate {
        /// In the foreground too (the Swift `willPresent`): banner and sound.
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            completion_handler: &block2::DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            completion_handler
                .call((UNNotificationPresentationOptions::Banner | UNNotificationPresentationOptions::Sound,));
        }

        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            completion_handler: &block2::DynBlock<dyn Fn()>,
        ) {
            let info = string_values(&response.notification().request().content().userInfo());
            if let Some(handler) = ON_CLICK.get() {
                // A panic must not unwind into the notification center.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(info)));
            }
            completion_handler.call(());
        }
    }
);

impl Delegate {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        // SAFETY: `NSObject`'s designated initializer.
        unsafe { msg_send![super(this), init] }
    }
}

/// The string values of a `userInfo` dictionary (other entries are skipped).
fn string_values(info: &NSDictionary) -> BTreeMap<String, String> {
    let (keys, values) = info.to_vecs();
    keys.into_iter()
        .zip(values)
        .filter_map(|(k, v)| {
            let k = k.downcast::<NSString>().ok()?;
            let v = v.downcast::<NSString>().ok()?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Installs the delegate (foreground presentation, clicks to `on_click`) and asks for permission to show alerts
/// with sound (the Swift `requestAuthorization(options: [.alert, .sound])`). Once per process; later calls do
/// nothing. Bundle only (see the module docs).
pub fn start(on_click: impl Fn(BTreeMap<String, String>) + Send + Sync + 'static) {
    if ON_CLICK.set(Box::new(on_click)).is_err() {
        return;
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let delegate = Delegate::new();
    center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    // The center keeps a weak reference: the delegate lives for the rest of the process.
    std::mem::forget(delegate);
    let done = RcBlock::new(|_granted: Bool, _error: *mut NSError| {});
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &done,
    );
}

/// Posts a notification now. `user_info`: one string entry (the Swift `connectionID` / `authPrompt`).
pub fn post(identifier: &str, title: &str, body: &str, user_info: (&str, &str)) {
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    let key = NSString::from_str(user_info.0);
    let value = NSString::from_str(user_info.1);
    let typed: Retained<NSDictionary<NSString, NSString>> = NSDictionary::from_slices(&[&*key], &[&*value]);
    // SAFETY: an `NSDictionary<NSString, NSString>` is an `NSDictionary` (the generics are compile-time only).
    let info: Retained<NSDictionary> = unsafe { Retained::cast_unchecked(typed) };
    // SAFETY: the dictionary holds property-list objects only (strings).
    unsafe { content.setUserInfo(&info) };
    let request =
        UNNotificationRequest::requestWithIdentifier_content_trigger(&NSString::from_str(identifier), &content, None);
    UNUserNotificationCenter::currentNotificationCenter().addNotificationRequest_withCompletionHandler(&request, None);
}

/// Removes a delivered notification (the prompt it announced closed).
pub fn remove_delivered(identifier: &str) {
    let ids = NSArray::from_retained_slice(&[NSString::from_str(identifier)]);
    UNUserNotificationCenter::currentNotificationCenter().removeDeliveredNotificationsWithIdentifiers(&ids);
}
