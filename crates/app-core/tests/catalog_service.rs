//! The team catalog service (plan Task 11): subscribe, refresh, verify, apply, unsubscribe, pending removals,
//! notifications and the logs, over the in-memory vault, the mock root and a fake fetcher.

mod catalog_support;
mod common;

use catalog_support::*;
use common::down_line;
use macvpn_app_core::catalog::{CatalogServiceError, RefreshResult, SubscribeInput, SubscriptionChange};
use macvpn_app_core::catalog_schedule::RefreshTrigger;
use macvpn_app_core::manager::ConnectionItem;
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::keys::{AdminKey, TeamKey};
use macvpn_core::catalog::planner::ApplySummary;
use macvpn_core::catalog::source::CatalogSource;
use macvpn_core::catalog::subscription::{SubscriptionString, format_subscription};
use macvpn_core::models::{SecretField, VPNKind};
use macvpn_core::vault::{FixedEntropy, SubscriptionRecord, SubscriptionStatus};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MANUAL: RefreshTrigger = RefreshTrigger::Manual;

fn source() -> CatalogSource {
    CatalogSource::File(PathBuf::from("/Volumes/Share/team/acme.macvpncatalog"))
}

fn input(p: &Publisher) -> SubscribeInput {
    SubscribeInput {
        source: source(),
        team_key: TeamKey::from_bytes(p.team.as_bytes()).unwrap(),
        fingerprint: p.admin.public().fingerprint(),
        bearer: None,
        catalog_id: None,
        min_version: None,
    }
}

fn subscribe(f: &CatalogFixture, p: &Publisher, bytes: Vec<u8>) -> ApplySummary {
    f.fetcher.serve(bytes);
    let (_, pending) = f.service.preview(input(p)).unwrap();
    f.service.confirm(pending).unwrap()
}

fn record(f: &CatalogFixture) -> SubscriptionRecord {
    f.vault.with_read(|v| v.subscription(catalog_id())).unwrap().unwrap()
}

fn connected(keys: &[String]) -> String {
    let rows: Vec<String> = keys
        .iter()
        .map(|k| format!(r#"{{"id":"{k}","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}}"#))
        .collect();
    format!("[{}]", rows.join(","))
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn v1() -> macvpn_core::catalog::payload::CatalogPayload {
    payload(&[(1, "One"), (2, "Two")])
}

// MARK: - subscribe

#[test]
fn subscribing_with_the_right_fingerprint_applies_the_catalog() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &v1()));
    let (preview, pending) = f.service.preview(input(&p)).unwrap();
    assert_eq!(preview.catalog_id, catalog_id());
    assert_eq!(preview.name, "Acme VPN");
    assert_eq!(preview.version, 1);
    assert_eq!(preview.fingerprint, p.admin.public().fingerprint());
    assert_eq!((preview.connections, preview.folders, preview.risky, preview.team_secrets), (2, 0, 0, 0));
    assert_eq!(preview.slots, ["Office AD"]);
    assert!(f.service.view().is_empty(), "nothing is stored before the confirmation");
    assert!(!format!("{pending:?}").contains(OPENVPN));

    let summary = f.service.confirm(pending).unwrap();
    assert_eq!(summary.added, 2);
    assert_eq!(f.connection_names(), ["One", "Two"]);
    let view = f.service.view();
    assert_eq!(view.len(), 1);
    assert_eq!(view[0].name, "Acme VPN");
    assert_eq!(view[0].version, Some(1));
    assert_eq!(view[0].status, "ok");
    assert_eq!(view[0].source, "acme.macvpncatalog");
    assert_eq!(view[0].fingerprint, p.admin.public().fingerprint().to_text());
    assert_eq!(view[0].slots.len(), 1);
    assert_eq!(view[0].slots[0].name, "Office AD");
    assert!(!view[0].slots[0].filled);
    let r = record(&f);
    assert_eq!(r.publisher_key, Some(p.admin.public()), "the full key is pinned");
    // The control API's `list` (the manager's ordered items) carries the namespaced local ids.
    let ids: Vec<String> = f.manager.ordered_items().iter().map(ConnectionItem::id).collect();
    assert!(ids.contains(&key(1)) && ids.contains(&key(2)));
    let badges = f.service.badges();
    assert_eq!(badges[&key(1)].name, "Acme VPN");
    assert!(!badges[&key(1)].pending_removal);
    assert!(f.service.read_only_reason(&key(1)).unwrap().contains("Acme VPN"));
    assert_eq!(f.service.read_only_reason("00000000-0000-4000-8000-000000000001"), None);
}

#[test]
fn a_wrong_fingerprint_is_refused_and_nothing_is_stored() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &v1()));
    let mut wrong = input(&p);
    wrong.fingerprint = AdminKey::generate(&FixedEntropy::new(77)).unwrap().public().fingerprint();
    let err = f.service.preview(wrong).unwrap_err();
    assert_eq!(err, CatalogServiceError::FingerprintMismatch);
    assert!(err.to_string().contains("fingerprint you entered"));
    assert!(f.service.view().is_empty());
    assert!(f.connection_names().is_empty());
}

#[test]
fn subscribing_twice_is_refused() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    assert_eq!(f.service.preview(input(&p)).unwrap_err(), CatalogServiceError::AlreadySubscribed);
    let mut bound = input(&p);
    bound.catalog_id = Some(catalog_id());
    assert_eq!(f.service.preview(bound).unwrap_err(), CatalogServiceError::AlreadySubscribed);
}

#[test]
fn the_subscription_strings_catalog_id_and_min_version_bind_the_first_download() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(2, &v1()));
    let s = SubscriptionString {
        source: source(),
        team_key: TeamKey::from_bytes(p.team.as_bytes()).unwrap(),
        fingerprint: p.admin.public().fingerprint(),
        catalog_id: Some(uid(0xF00)),
        min_version: Some(3),
    };
    let mut other = SubscribeInput::from_subscription(s, None);
    assert_eq!(f.service.preview(other).unwrap_err(), CatalogServiceError::Catalog(CatalogError::WrongCatalog));
    other = input(&p);
    other.catalog_id = Some(catalog_id());
    other.min_version = Some(3);
    assert_eq!(
        f.service.preview(other).unwrap_err(),
        CatalogServiceError::Catalog(CatalogError::Rollback { applied: 3, offered: 2 })
    );
    let mut exact = input(&p);
    exact.catalog_id = Some(catalog_id());
    exact.min_version = Some(2);
    let (preview, _) = f.service.preview(exact).unwrap();
    assert_eq!(preview.version, 2);
}

#[test]
fn an_expired_preview_cannot_be_confirmed() {
    // `PendingSubscription::is_expired` is the rule `confirm` applies.
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &v1()));
    let (_, pending) = f.service.preview(input(&p)).unwrap();
    assert!(!pending.is_expired(Instant::now()));
    assert!(pending.is_expired(Instant::now() + Duration::from_secs(10 * 60)));
}

// MARK: - refresh

#[test]
fn refresh_applies_new_versions_and_notifies_only_non_zero_parts() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::NotModified);
    assert_eq!(record(&f).status, SubscriptionStatus::NotModified);
    assert!(f.notices().is_empty());

    // v2: One renamed, Two removed, Three added.
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One B"), (3, "Three")])));
    let result = f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(result, RefreshResult::Applied(ApplySummary { added: 1, changed: 1, removed: 1, deferred: 0 }));
    assert_eq!(f.connection_names(), ["One B", "Three"]);
    assert_eq!(f.notices(), ["Team catalog “Acme VPN” updated: 1 added, 1 changed, 1 removed"]);
    assert_eq!(*f.forgotten.lock().unwrap(), [key(2)], "the removed id leaves every allowlist");

    // v3: only an addition.
    f.fetcher.serve(p.seal(3, &payload(&[(1, "One B"), (3, "Three"), (4, "Four")])));
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(f.notices().last().unwrap(), "Team catalog “Acme VPN” updated: 1 added");

    // The same version re-uploaded (other bytes): nothing applied, no notification.
    f.fetcher.serve(p.seal(3, &payload(&[(9, "Nine")])));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Unchanged);
    assert_eq!(f.notices().len(), 2);
    assert_eq!(record(&f).status, SubscriptionStatus::Ok);
    assert_eq!(f.connection_names(), ["Four", "One B", "Three"]);

    // An older version: refused, one notification per offered version, items unchanged.
    f.fetcher.serve(p.seal(1, &v1()));
    assert_eq!(
        f.service.refresh(catalog_id(), MANUAL),
        RefreshResult::Refused(CatalogError::Rollback { applied: 3, offered: 1 })
    );
    assert_eq!(record(&f).status, SubscriptionStatus::RollbackRefused { offered: 1 });
    assert_eq!(
        f.notices().last().unwrap(),
        "Team catalog “Acme VPN” offered an older version (v1 after v3) and was not applied."
    );
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(f.notices().len(), 3, "the same refusal notifies once");
    assert_eq!(f.connection_names(), ["Four", "One B", "Three"]);
    assert_eq!(f.service.view()[0].status, "rollbackRefused");
    assert!(f.service.view()[0].error.as_deref().unwrap().contains("version 1"));
}

#[test]
fn a_rotated_team_key_is_reported_once_and_the_new_key_applies() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    let rotated = TeamKey::generate(&FixedEntropy::new(2)).unwrap();
    f.fetcher.serve(p.seal_with(2, &payload(&[(1, "One")]), &p.admin, &rotated, None));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Refused(CatalogError::WrongTeamKey));
    assert_eq!(record(&f).status, SubscriptionStatus::TeamKeyChanged);
    assert_eq!(record(&f).failures, 0, "not a transport failure");
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(f.notices(), ["The team key of “Acme VPN” has changed. Ask your administrator for the new key."]);
    f.service
        .update_subscription(
            catalog_id(),
            SubscriptionChange::TeamKey(TeamKey::from_bytes(rotated.as_bytes()).unwrap()),
        )
        .unwrap();
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
    assert_eq!(f.connection_names(), ["One"]);
    assert_eq!(record(&f).status, SubscriptionStatus::Ok);
}

#[test]
fn the_successor_key_is_stored_only_when_applied_and_a_catalog_it_signs_re_pins() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    let successor = AdminKey::generate(&FixedEntropy::new(10)).unwrap();
    subscribe(&f, &p, p.seal(1, &v1()));
    // A refused catalog's announcement is never stored.
    let wrong = TeamKey::generate(&FixedEntropy::new(2)).unwrap();
    f.fetcher.serve(p.seal_with(2, &v1(), &p.admin, &wrong, Some(successor.public())));
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Refused(_)));
    assert_eq!(record(&f).successor_key, None);
    // v3 announces S.
    f.fetcher.serve(p.seal_with(3, &v1(), &p.admin, &p.team, Some(successor.public())));
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
    assert_eq!(record(&f).successor_key, Some(successor.public()));
    assert_eq!(record(&f).pinned, p.admin.public().fingerprint());
    // v4 signed by S: applied and re-pinned.
    f.fetcher.serve(p.seal_with(4, &payload(&[(1, "One")]), &successor, &p.team, None));
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
    let r = record(&f);
    assert_eq!(r.pinned, successor.public().fingerprint());
    assert_eq!(r.publisher_key, Some(successor.public()));
    assert_eq!(r.successor_key, None);
    assert_eq!(f.service.view()[0].fingerprint, successor.public().fingerprint().to_text());
    assert!(f.log.lock().unwrap().iter().any(|l| l.contains("publisher key rotated")));
    // v5 signed by the old key: no longer accepted.
    f.fetcher.serve(p.seal(5, &v1()));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Refused(CatalogError::UnknownPublisher));
    assert_eq!(
        record(&f).status,
        SubscriptionStatus::Failed(macvpn_core::catalog::format::CatalogErrorKind::UnknownPublisher)
    );
    assert_eq!(f.connection_names(), ["One"]);
}

#[test]
fn unavailable_never_notifies_and_a_failure_notifies_once_per_status_change() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    f.fetcher.fail(CatalogError::Unavailable("acme.macvpncatalog".into()));
    f.service.refresh(catalog_id(), MANUAL);
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(record(&f).status, SubscriptionStatus::Unavailable);
    assert_eq!(record(&f).failures, 2);
    assert!(f.notices().is_empty());
    assert_eq!(f.service.view()[0].status, "unavailable");
    f.fetcher.fail(CatalogError::Io("not a regular file".into()));
    f.service.refresh(catalog_id(), MANUAL);
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(record(&f).failures, 4);
    assert_eq!(f.notices(), ["Team catalog “Acme VPN” could not be updated: The team catalog could not be read."]);
    // Healthy again: the count resets.
    f.fetcher.serve(p.seal(1, &v1()));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::NotModified);
    assert_eq!(record(&f).failures, 0);
}

#[test]
fn a_locked_vault_fetches_nothing() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    let calls = f.fetcher.calls();
    f.vault.lock();
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Locked);
    assert!(f.service.refresh_all(MANUAL).is_empty());
    assert_eq!(f.fetcher.calls(), calls);
    assert!(f.service.view().is_empty());
}

#[test]
fn a_restored_subscription_applies_the_same_version_once_and_still_refuses_a_lower_one() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    f.fetcher.serve(p.seal(2, &v1()));
    f.service.refresh(catalog_id(), MANUAL);
    // Simulates what `restore_catalog` leaves (reapply, the version kept as the floor, the validators cleared); the
    // real backup and restore path is `a_real_backup_and_restore_brings_the_items_back`.
    let restore = |f: &CatalogFixture| {
        f.vault
            .with(|v| {
                v.update_subscription_state(catalog_id(), |r| {
                    r.reapply = true;
                    r.validators = Default::default();
                })
            })
            .unwrap()
    };
    restore(&f);
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
    assert!(!record(&f).reapply);
    assert_eq!(record(&f).applied_version, Some(2));
    // Once only: the same version again is just unchanged.
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Unchanged);
    // A lower one after a restore: still a rollback against the restored version.
    restore(&f);
    f.fetcher.serve(p.seal(1, &v1()));
    assert_eq!(
        f.service.refresh(catalog_id(), MANUAL),
        RefreshResult::Refused(CatalogError::Rollback { applied: 2, offered: 1 })
    );
    assert!(record(&f).reapply, "still waiting for the restored version");
}

// MARK: - removals and unsubscribe

#[test]
fn a_connection_removed_while_up_stays_until_it_disconnects() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    f.root.respond("status", Ok(&connected(&[key(2)])));
    f.manager.refresh();
    assert!(f.manager.state(&key(2)).is_active());
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    let result = f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(result, RefreshResult::Applied(ApplySummary { added: 0, changed: 0, removed: 1, deferred: 1 }));
    assert_eq!(f.connection_names(), ["One", "Two"]);
    assert!(f.service.badges()[&key(2)].pending_removal);
    assert!(f.forgotten.lock().unwrap().is_empty());
    // The root reports it down: removed, and its id leaves the allowlists.
    f.root.respond("status", Ok("[]"));
    f.manager.refresh();
    wait_until("the pending removal", || f.connection_names() == ["One"]);
    wait_until("the allowlist pruning", || *f.forgotten.lock().unwrap() == [key(2)]);
    assert!(!f.service.badges().contains_key(&key(2)));
}

#[test]
fn unsubscribe_disconnects_first_keeps_a_filled_slot_and_prunes_the_allowlists() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    f.vault.with(|v| v.save_prompted_secret(&key(1), SecretField::Username, "alice")).unwrap();
    assert!(f.service.view()[0].slots[0].filled);
    f.root.respond("status", Ok(&connected(&[key(1)])));
    f.manager.refresh();
    assert!(f.manager.state(&key(1)).is_active());
    // Still up after the wait: refused, nothing removed.
    f.service.set_disconnect_wait(Duration::from_millis(200));
    assert_eq!(f.service.unsubscribe(catalog_id()).unwrap_err(), CatalogServiceError::StillActive);
    assert_eq!(f.connection_names(), ["One", "Two"]);
    // It goes down when asked.
    f.root.respond("status", Ok("[]"));
    let report = f.service.unsubscribe(catalog_id()).unwrap();
    assert!(f.root.lines().contains(&down_line(VPNKind::Openvpn, &local(1))));
    assert_eq!(report.kept_credentials, ["Office AD"]);
    let mut removed = report.removed_connections.clone();
    removed.sort();
    let mut expected = vec![local(1), local(2)];
    expected.sort();
    assert_eq!(removed, expected);
    assert!(f.connection_names().is_empty());
    assert!(f.service.view().is_empty());
    let mut forgotten = f.forgotten.lock().unwrap().clone();
    forgotten.sort();
    let mut keys = vec![key(1), key(2)];
    keys.sort();
    assert_eq!(forgotten, keys);
    let credentials = f.vault.with_read(|v| v.credentials()).unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].username, "alice");
}

#[test]
fn duplicate_makes_a_personal_copy() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    let copy = f.service.duplicate(local(1), "One (mine)").unwrap();
    assert_eq!(f.connection_names(), ["One", "One (mine)", "Two"]);
    assert_eq!(f.service.read_only_reason(&macvpn_core::models::uuid_string(&copy)), None);
}

// MARK: - secrets in the logs

#[test]
fn no_log_line_or_notice_carries_a_key_a_token_a_config_or_a_subscription_string() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    let token = "s3cr3t.TOKEN~xyz";
    f.fetcher.serve(p.seal(1, &v1()));
    let mut with_token = input(&p);
    with_token.bearer = Some(Zeroizing::new(token.to_string()));
    let (_, pending) = f.service.preview(with_token).unwrap();
    f.service.confirm(pending).unwrap();
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(f.fetcher.bearers().last().unwrap().as_deref(), Some(token), "the token reaches the fetcher");
    f.fetcher.serve(p.seal(1, &v1()));
    f.service.refresh(catalog_id(), MANUAL);
    f.service
        .update_subscription(catalog_id(), SubscriptionChange::Bearer(Some(Zeroizing::new("n3w.t0ken".into()))))
        .unwrap();
    f.service.unsubscribe(catalog_id()).unwrap();
    let subscription = format_subscription(&SubscriptionString {
        source: source(),
        team_key: TeamKey::from_bytes(p.team.as_bytes()).unwrap(),
        fingerprint: p.admin.public().fingerprint(),
        catalog_id: None,
        min_version: None,
    });
    let team_text = p.team.to_text();
    let mut lines = f.log.lock().unwrap().clone();
    lines.extend(f.notices());
    assert!(!lines.is_empty());
    for line in lines {
        for secret in [team_text.as_str(), token, "n3w.t0ken", subscription.as_str(), "auth-user-pass", "remote vpn"] {
            assert!(!line.contains(secret), "{line:?} contains a secret");
        }
        assert!(!line.contains("/Volumes/Share"), "a file source is logged by its file name at most: {line:?}");
    }
}

// MARK: - review fixes

#[test]
fn a_real_backup_and_restore_brings_the_items_back() {
    use macvpn_core::vault::backup::{self, BackupPreferences, ConflictMode};
    let a = CatalogFixture::new();
    let p = Publisher::new();
    let file = p.seal(1, &v1());
    subscribe(&a, &p, file.clone());
    assert!(record(&a).validators.content_hash.is_some());
    let prefs = BackupPreferences {
        auto_check: true,
        delay_24h: false,
        launch_at_login: false,
        control_api_enabled: false,
        auto_unlock: false,
    };
    let payload = a
        .vault
        .with_read(|v| backup::collect(v, prefs, macvpn_app_core::deps::Clock::now(&*a.clock), "1.3.0"))
        .unwrap();

    let b = CatalogFixture::new();
    b.vault.with(|v| backup::merge(v, &payload, ConflictMode::Overwrite)).unwrap();
    b.manager.reload();
    assert!(b.connection_names().is_empty(), "the catalog items are not in the backup");
    // The source still serves the very same file: it must be applied, not taken as "not modified".
    b.fetcher.serve(file);
    assert!(matches!(b.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
    assert_eq!(b.connection_names(), ["One", "Two"]);
    assert!(!record(&b).reapply);
}

#[test]
fn while_reapply_is_set_the_stored_validators_are_not_sent() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    // A restore from before the fix: reapply with the backed-up validators still there.
    f.vault.with(|v| v.update_subscription_state(catalog_id(), |r| r.reapply = true)).unwrap();
    assert!(record(&f).validators.content_hash.is_some());
    assert!(matches!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Applied(_)));
}

#[test]
fn a_new_origin_drops_the_bearer_token_and_the_same_origin_keeps_it() {
    use macvpn_core::catalog::source::HttpsUrl;
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &v1()));
    let mut with_token = input(&p);
    with_token.source = CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/a.macvpncatalog").unwrap());
    with_token.bearer = Some(Zeroizing::new("tok.en".into()));
    let (_, pending) = f.service.preview(with_token).unwrap();
    f.service.confirm(pending).unwrap();
    let https = |u: &str| CatalogSource::Https(HttpsUrl::parse(u).unwrap());
    f.service
        .update_subscription(catalog_id(), SubscriptionChange::Source(https("https://vpn.example.com/b.macvpncatalog")))
        .unwrap();
    assert!(record(&f).has_bearer, "same host and port: the token stays");
    f.service
        .update_subscription(
            catalog_id(),
            SubscriptionChange::Source(https("https://vpn.example.com:8443/b.macvpncatalog")),
        )
        .unwrap();
    assert!(!record(&f).has_bearer, "another origin never gets the old token");
    assert_eq!(f.vault.with_read(|v| v.subscription_secrets(catalog_id())).unwrap().1, None);
}

#[test]
fn a_connection_that_comes_up_while_an_apply_is_planned_is_never_deleted() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    let root = f.root.clone();
    let manager = f.manager.clone();
    let once = std::sync::Once::new();
    f.service.set_before_apply(move || {
        once.call_once(|| {
            root.respond("status", Ok(&connected(&[key(2)])));
            manager.refresh();
        })
    });
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    let result = f.service.refresh(catalog_id(), MANUAL);
    assert_eq!(result, RefreshResult::Applied(ApplySummary { added: 0, changed: 0, removed: 1, deferred: 1 }));
    assert_eq!(f.connection_names(), ["One", "Two"], "kept until it disconnects");
}

#[test]
fn a_failed_allowlist_prune_is_logged() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    f.service.set_forget_keys(|_| Err("disk full".to_string()));
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    f.service.refresh(catalog_id(), MANUAL);
    assert!(f.log.lock().unwrap().iter().any(|l| l.contains("allowlist") && l.contains("failed")));
}

#[test]
fn a_refusal_while_the_vault_locks_is_not_notified() {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    subscribe(&f, &p, p.seal(1, &v1()));
    let vault = f.vault.clone();
    f.fetcher.set_on_fetch(move || vault.lock());
    f.fetcher.fail(CatalogError::Io("not a regular file".into()));
    assert_eq!(f.service.refresh(catalog_id(), MANUAL), RefreshResult::Locked);
    assert!(f.notices().is_empty());
}
