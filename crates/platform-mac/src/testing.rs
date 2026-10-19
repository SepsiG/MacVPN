//! Test doubles for the platform services (ports of the Swift tests' `MockCommandRunner`, `MockNativeDriver`,
//! `MockLoginItemService` and `MockHTTPClient`). Nothing here touches the system: no process, VPN, login item or
//! network.

use crate::command::{CommandError, CommandResult, CommandRunner};
use crate::http::{HttpClient, HttpError, HttpResponse};
use crate::login_item::{LoginItemService, LoginItemStatus};
use crate::native_vpn::{BoxError, NativeConnectionDriver};
use macvpn_core::native::NativeStartOptions;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub executable: String,
    pub arguments: Vec<String>,
    pub stdin: Option<String>,
}

impl Call {
    /// The full command line joined with spaces, e.g. `/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status`.
    pub fn command_line(&self) -> String {
        std::iter::once(self.executable.as_str())
            .chain(self.arguments.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Answers by command line; unknown commands succeed with empty output.
#[derive(Debug, Default)]
pub struct MockCommandRunner {
    calls: Mutex<Vec<Call>>,
    responses: Mutex<HashMap<String, CommandResult>>,
    delays: Mutex<HashMap<String, Duration>>,
}

impl MockCommandRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn respond(&self, command_line: &str, result: CommandResult) {
        self.responses.lock().expect("lock").insert(command_line.to_string(), result);
    }

    /// The given command line waits this long (the answer is decided when the call arrives).
    pub fn delay(&self, command_line: &str, delay: Duration) {
        self.delays.lock().expect("lock").insert(command_line.to_string(), delay);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("lock").clone()
    }
}

impl CommandRunner for MockCommandRunner {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        let call = Call {
            executable: executable.to_string(),
            arguments: arguments.to_vec(),
            stdin: stdin.map(str::to_string),
        };
        let line = call.command_line();
        self.calls.lock().expect("lock").push(call);
        let response = self.responses.lock().expect("lock").get(&line).cloned();
        let delay = self.delays.lock().expect("lock").get(&line).copied();
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        Ok(response.unwrap_or_default())
    }
}

/// Gives the same answer to every call.
#[derive(Debug, Clone)]
pub struct FixedRunner(pub CommandResult);

impl CommandRunner for FixedRunner {
    fn run(&self, _: &str, _: &[String], _: Option<&str>) -> Result<CommandResult, CommandError> {
        Ok(self.0.clone())
    }
}

/// A recorded native start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeStart {
    pub service_id: String,
    pub options: Option<NativeStartOptions>,
    pub linger: bool,
}

/// Records the native start/stop calls instead of calling SystemConfiguration (no real VPN is touched).
#[derive(Default)]
pub struct MockNativeDriver {
    starts: Mutex<Vec<NativeStart>>,
    stops: Mutex<Vec<String>>,
    /// Returned by `start` when set (its message).
    pub start_error: Mutex<Option<String>>,
    pub stop_error: Mutex<Option<String>>,
}

impl MockNativeDriver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn starts(&self) -> Vec<NativeStart> {
        self.starts.lock().expect("lock").clone()
    }

    pub fn stops(&self) -> Vec<String> {
        self.stops.lock().expect("lock").clone()
    }
}

impl NativeConnectionDriver for MockNativeDriver {
    fn start(&self, service_id: &str, options: Option<&NativeStartOptions>, linger: bool) -> Result<(), BoxError> {
        self.starts.lock().expect("lock").push(NativeStart {
            service_id: service_id.to_string(),
            options: options.cloned(),
            linger,
        });
        match self.start_error.lock().expect("lock").clone() {
            Some(m) => Err(Box::new(crate::mvpn_client::MvpnError::Failed(m))),
            None => Ok(()),
        }
    }

    fn stop(&self, service_id: &str) -> Result<(), BoxError> {
        self.stops.lock().expect("lock").push(service_id.to_string());
        match self.stop_error.lock().expect("lock").clone() {
            Some(m) => Err(Box::new(crate::mvpn_client::MvpnError::Failed(m))),
            None => Ok(()),
        }
    }
}

/// The error the mock login item service returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginItemTestError;

impl std::fmt::Display for LoginItemTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Operation not permitted")
    }
}

impl std::error::Error for LoginItemTestError {}

/// The mock's state, shared between the test and the service it hands out.
#[derive(Debug)]
pub struct MockLoginItemState {
    pub status: LoginItemStatus,
    pub calls: Vec<String>,
    pub register_error: bool,
    pub unregister_error: bool,
    /// The status after a successful register (e.g. `RequiresApproval`).
    pub status_after_register: LoginItemStatus,
}

/// A login item service over shared state (`Rc<RefCell<…>>`, single-threaded like the Swift `@MainActor` mock).
#[derive(Debug, Clone)]
pub struct MockLoginItemService(pub Rc<RefCell<MockLoginItemState>>);

impl MockLoginItemService {
    pub fn new(status: LoginItemStatus) -> Self {
        MockLoginItemService(Rc::new(RefCell::new(MockLoginItemState {
            status,
            calls: Vec::new(),
            register_error: false,
            unregister_error: false,
            status_after_register: LoginItemStatus::Enabled,
        })))
    }

    pub fn calls(&self) -> Vec<String> {
        self.0.borrow().calls.clone()
    }

    pub fn set_status(&self, status: LoginItemStatus) {
        self.0.borrow_mut().status = status;
    }
}

impl LoginItemService for MockLoginItemService {
    fn status(&self) -> LoginItemStatus {
        self.0.borrow().status
    }

    fn register(&self) -> Result<(), BoxError> {
        let mut s = self.0.borrow_mut();
        s.calls.push("register".into());
        if s.register_error {
            return Err(Box::new(LoginItemTestError));
        }
        s.status = s.status_after_register;
        Ok(())
    }

    fn unregister(&self) -> Result<(), BoxError> {
        let mut s = self.0.borrow_mut();
        s.calls.push("unregister".into());
        if s.unregister_error {
            return Err(Box::new(LoginItemTestError));
        }
        s.status = LoginItemStatus::NotRegistered;
        Ok(())
    }

    fn open_system_settings_login_items(&self) {
        self.0.borrow_mut().calls.push("openSettings".into());
    }
}

/// A network-free HTTP client: URL → response; unknown URLs are 404.
#[derive(Debug, Default)]
pub struct MockHttpClient {
    responses: Mutex<HashMap<String, HttpResponse>>,
    requested: Mutex<Vec<String>>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn respond(&self, url: &str, response: HttpResponse) {
        self.responses.lock().expect("lock").insert(url.to_string(), response);
    }

    pub fn requested(&self) -> Vec<String> {
        self.requested.lock().expect("lock").clone()
    }

    fn response(&self, url: &str) -> HttpResponse {
        self.requested.lock().expect("lock").push(url.to_string());
        self.responses.lock().expect("lock").get(url).cloned().unwrap_or(HttpResponse { status: 404, data: Vec::new() })
    }
}

impl HttpClient for MockHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        Ok(self.response(url))
    }

    fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError> {
        let r = self.response(url);
        let file = std::env::temp_dir().join(format!("mock-dl-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, &r.data).map_err(HttpError::Io)?;
        Ok((file, r.status))
    }
}
