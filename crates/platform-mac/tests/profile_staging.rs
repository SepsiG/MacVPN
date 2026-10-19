//! Port of `NativeProfileStagingTests.swift` (the legacy profile removal test lives with the core store tests).

mod common;

use common::{Scratch, mode};
use macvpn_core::date::Date;
use macvpn_platform_mac::profile_staging::{self, PREFIX, REGENERATED_GRACE, StagedProfiles};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[test]
fn stage_writes_private_file_in_fresh_private_directory() {
    let parent = Scratch::new("staging");
    let a = profile_staging::stage(b"x", "Office.mobileconfig", parent.path()).unwrap();
    let b = profile_staging::stage(b"y", "Office.mobileconfig", parent.path()).unwrap();
    assert_ne!(a.parent(), b.parent());
    assert_eq!(a.file_name().unwrap(), "Office.mobileconfig");
    assert!(a.parent().unwrap().file_name().unwrap().to_string_lossy().starts_with(PREFIX));
    assert_eq!(std::fs::read(&a).unwrap(), b"x");
    assert_eq!(mode(&a), 0o600);
    assert_eq!(mode(a.parent().unwrap()), 0o700);
}

#[test]
fn stage_rejects_path_in_file_name() {
    let parent = Scratch::new("staging");
    for bad in ["../x.mobileconfig", "a/b", "", ".", ".."] {
        assert!(profile_staging::stage(b"", bad, parent.path()).is_err(), "{bad}");
    }
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn remove_deletes_only_staged_directories() {
    let parent = Scratch::new("staging");
    let staged = profile_staging::stage(b"x", "A.mobileconfig", parent.path()).unwrap();
    profile_staging::remove(&staged);
    assert!(!staged.parent().unwrap().exists());
    // A file outside a staging directory is not deleted.
    let other = parent.join("keep/A.mobileconfig");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::write(&other, b"").unwrap();
    profile_staging::remove(&other);
    assert!(other.exists());
}

#[test]
fn sweep_removes_leftovers_but_not_other_files_or_symlinks() {
    let parent = Scratch::new("staging");
    profile_staging::stage(b"x", "A.mobileconfig", parent.path()).unwrap();
    profile_staging::stage(b"y", "B.mobileconfig", parent.path()).unwrap();
    std::fs::create_dir_all(parent.join("other")).unwrap();
    let target = parent.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep"), b"").unwrap();
    std::os::unix::fs::symlink(&target, parent.join(&format!("{PREFIX}link"))).unwrap();
    assert_eq!(profile_staging::sweep(parent.path()), 2);
    let mut left: Vec<String> =
        std::fs::read_dir(parent.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into()).collect();
    left.sort();
    assert_eq!(left, vec![format!("{PREFIX}link"), "other".into(), "target".into()]);
    assert!(target.join("keep").exists());
    assert_eq!(profile_staging::sweep(&parent.join("missing")), 0);
}

fn manual_clock(start: f64) -> (Arc<Mutex<Date>>, Box<dyn Fn() -> Date + Send + Sync>) {
    let now = Arc::new(Mutex::new(Date::from_time_interval_since_1970(start)));
    let read = now.clone();
    (now, Box::new(move || *read.lock().unwrap()))
}

#[test]
fn tracker_removes_when_service_appears() {
    let parent = Scratch::new("staging");
    let (now, clock) = manual_clock(1000.0);
    let mut tracker = StagedProfiles::new(clock);
    let (id, other) = (Uuid::new_v4(), Uuid::new_v4());
    let profile = profile_staging::stage(b"x", "A.mobileconfig", parent.path()).unwrap();
    tracker.track(id, profile.clone(), false);
    assert_eq!(tracker.pending_ids(), HashSet::from([id]));
    tracker.services_seen(&HashSet::from([other]));
    assert!(profile.exists(), "not installed yet");
    let later = now.lock().unwrap().adding(1.0);
    *now.lock().unwrap() = later;
    tracker.services_seen(&HashSet::from([id]));
    assert!(!profile.parent().unwrap().exists());
    assert!(tracker.pending_ids().is_empty());
}

#[test]
fn tracker_waits_before_removing_a_regenerated_profile() {
    let parent = Scratch::new("staging");
    let (now, clock) = manual_clock(1000.0);
    let mut tracker = StagedProfiles::new(clock);
    let id = Uuid::new_v4();
    let profile = profile_staging::stage(b"x", "A.mobileconfig", parent.path()).unwrap();
    // The service existed already: it being listed says nothing about whether the new profile was installed.
    tracker.track(id, profile.clone(), true);
    let t = now.lock().unwrap().adding(60.0);
    *now.lock().unwrap() = t;
    tracker.services_seen(&HashSet::from([id]));
    assert!(profile.exists());
    let t = now.lock().unwrap().adding(REGENERATED_GRACE);
    *now.lock().unwrap() = t;
    tracker.services_seen(&HashSet::from([id]));
    assert!(!profile.exists());
}

#[test]
fn tracking_again_replaces_the_previous_profile() {
    let parent = Scratch::new("staging");
    let mut tracker = StagedProfiles::default();
    let id = Uuid::new_v4();
    let first = profile_staging::stage(b"x", "A.mobileconfig", parent.path()).unwrap();
    let second = profile_staging::stage(b"y", "A.mobileconfig", parent.path()).unwrap();
    tracker.track(id, first.clone(), false);
    tracker.track(id, second.clone(), false);
    assert!(!first.exists());
    assert!(second.exists());
    tracker.remove_all();
    assert!(!second.exists());
}
