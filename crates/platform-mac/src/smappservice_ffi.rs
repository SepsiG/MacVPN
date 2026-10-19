//! `SMAppService.mainApp` (ServiceManagement, macOS 13+) through `objc2-service-management`.
//!
//! Audit notes: every call is a plain Objective-C message send on the shared `mainAppService` object, with no
//! arguments besides the receiver; errors come back as owned `NSError` objects and only their localized
//! description is kept. Never called from tests (they use mock services).
#![allow(unsafe_code)]

use crate::login_item::LoginItemStatus;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

pub fn status() -> LoginItemStatus {
    // SAFETY: class method without arguments returning the shared service; `status` is a plain getter.
    let s = unsafe { SMAppService::mainAppService().status() };
    if s == SMAppServiceStatus::Enabled {
        LoginItemStatus::Enabled
    } else if s == SMAppServiceStatus::NotRegistered {
        LoginItemStatus::NotRegistered
    } else if s == SMAppServiceStatus::RequiresApproval {
        LoginItemStatus::RequiresApproval
    } else {
        // `.notFound` and any future value (Swift `@unknown default`).
        LoginItemStatus::NotFound
    }
}

pub fn register() -> Result<(), String> {
    // SAFETY: as in `status`; the error out-parameter is handled by the binding.
    unsafe { SMAppService::mainAppService().registerAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
}

pub fn unregister() -> Result<(), String> {
    // SAFETY: as in `register`.
    unsafe { SMAppService::mainAppService().unregisterAndReturnError() }
        .map_err(|e| e.localizedDescription().to_string())
}

pub fn open_system_settings_login_items() {
    // SAFETY: class method without arguments.
    unsafe { SMAppService::openSystemSettingsLoginItems() }
}
