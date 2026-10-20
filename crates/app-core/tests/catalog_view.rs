//! The view model's team catalog parts (plan Task 15): the subscriptions, the "Team" and "Published in" badges and
//! the publishing side are there while the vault is open, carry no team key, token, subscription string, source
//! query or config, and are all gone while it is locked.

mod catalog_support;
mod common;

use catalog_support::{CatalogFixture, MASTER, OPENVPN, Publisher, key, payload};
use macvpn_app_core::catalog::SubscribeInput;
use macvpn_app_core::catalog_publish::{PublishInput, Publisher as CatalogPublisher, PublisherDeps};
use macvpn_app_core::view_model::{PublishingView, VaultView};
use macvpn_app_core::{RowView, ViewModel};
use macvpn_core::catalog::keys::TeamKey;
use macvpn_core::catalog::selection::PublishSelection;
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::vault::{AdminKeyRole, FixedEntropy, KdfParams};
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN: &str = "per-user.Token-123";

fn https(url: &str) -> CatalogSource {
    CatalogSource::Https(HttpsUrl::parse(url).unwrap())
}

fn row<'a>(vm: &'a ViewModel, id: &str) -> &'a RowView {
    vm.rows.iter().find(|r| r.id == id).unwrap_or_else(|| panic!("no row {id}"))
}

#[test]
fn the_view_model_shows_catalogs_and_publishing_but_never_a_secret_and_nothing_while_locked() {
    let f = CatalogFixture::new();
    // The subscriber side: a catalog over HTTPS with a query in the URL and an access token.
    let team = Publisher::new();
    f.fetcher.serve(team.seal(1, &payload(&[(1, "Office")])));
    let (_, pending) = f
        .service
        .preview(SubscribeInput {
            source: https("https://vpn.example.com/acme.macvpncatalog?sig=query-secret"),
            team_key: TeamKey::from_bytes(team.team.as_bytes()).unwrap(),
            fingerprint: team.admin.public().fingerprint(),
            bearer: Some(Zeroizing::new(TOKEN.into())),
            catalog_id: None,
            min_version: None,
        })
        .unwrap();
    f.service.confirm(pending).unwrap();

    // The publisher side, on the same vault: a personal connection published as "Lab Team".
    let lab = Uuid::from_u128(0x7000_0000_0000_4000_8000_0000_0000_0001);
    f.vault
        .with(|v| v.save_connection(&Connection::with_id(lab, "Lab", VPNKind::Openvpn, Date::now()), Some(OPENVPN)))
        .unwrap();
    f.manager.reload();
    let publisher = CatalogPublisher::new(PublisherDeps {
        vault: f.vault.clone(),
        entropy: Arc::new(FixedEntropy::new(77)),
        kdf: KdfParams::insecure_for_tests(),
        clock: f.clock.clone(),
    });
    publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let published = publisher
        .publish(PublishInput {
            catalog_id: None,
            name: "Lab Team".into(),
            selection: PublishSelection { connections: BTreeSet::from([lab]), ..Default::default() },
            path: f.tmp.path().join("lab.macvpncatalog"),
        })
        .unwrap();
    let new_team_key = published.new_team_key.clone().unwrap();
    let subscription = publisher
        .subscription_string(
            published.catalog_id,
            Zeroizing::new(MASTER.into()),
            https("https://vpn.example.com/lab.macvpncatalog"),
        )
        .unwrap();

    // What the app's view model gets while the vault is open.
    let fill = |vm: &mut ViewModel| {
        vm.catalogs = f.service.view();
        vm.set_catalog_badges(&f.service.badges());
        vm.publishing = PublishingView::build(&publisher);
        vm.set_published_badges(&publisher.published_badges().unwrap_or_default());
    };
    let mut vm = ViewModel::build(&f.manager.snapshot(), "en", |_| true, Vec::new(), true);
    fill(&mut vm);
    vm.apply_vault(VaultView::build(&f.vault.state(), false, false, 0));
    assert_eq!(vm.catalogs.len(), 1);
    let catalog = &vm.catalogs[0];
    assert_eq!((catalog.name.as_str(), catalog.version, catalog.has_token), ("Acme VPN", Some(1), true));
    assert_eq!(catalog.slots.len(), 1);
    assert_eq!(row(&vm, &key(1)).catalog.as_ref().map(|b| b.name.as_str()), Some("Acme VPN"));
    assert!(row(&vm, &key(1)).published.is_empty());
    let lab_row = row(&vm, &uuid_string(&lab));
    assert!(lab_row.catalog.is_none());
    assert_eq!(lab_row.published.iter().map(|b| (b.name.as_str(), b.version)).collect::<Vec<_>>(), [("Lab Team", 1)]);
    assert_eq!(vm.publishing.admin_keys.len(), 1);
    assert_eq!(vm.publishing.admin_keys[0].role, "primary");
    assert_eq!(vm.publishing.admin_keys[0].fingerprint, published.fingerprint.to_text());
    assert_eq!(vm.publishing.publications.len(), 1);
    assert_eq!(vm.publishing.publications[0].file_name.as_deref(), Some("lab.macvpncatalog"));

    let json = serde_json::to_string(&vm).unwrap();
    let acme_key = team.team.to_text();
    for secret in [
        acme_key.as_str(),
        &acme_key[5..19],
        new_team_key.as_str(),
        &new_team_key[5..19],
        TOKEN,
        subscription.as_str(),
        "macvpn-sub:",
        "query-secret",
        "remote vpn.example.com 1194",
        f.tmp.path().to_str().unwrap(),
    ] {
        assert!(!json.contains(secret), "{secret} in the view model");
    }

    // Locked: the service and the publisher list nothing, and a stale view is cleared by `apply_vault`.
    f.vault.lock();
    f.manager.enter_locked();
    assert!(f.service.view().is_empty() && f.service.badges().is_empty());
    assert_eq!(PublishingView::build(&publisher), PublishingView::default());
    let mut stale = ViewModel::build(&f.manager.snapshot(), "en", |_| true, Vec::new(), true);
    stale.catalogs = vm.catalogs.clone();
    stale.team_folders.insert(uuid_string(&lab), uuid_string(&published.catalog_id));
    stale.publishing = vm.publishing.clone();
    stale.apply_vault(VaultView::build(&f.vault.state(), false, false, 0));
    assert!(stale.catalogs.is_empty() && stale.team_folders.is_empty() && stale.rows.is_empty());
    assert_eq!(stale.publishing, PublishingView::default());
    let json = serde_json::to_string(&stale).unwrap();
    for name in ["Acme VPN", "Lab Team", "vpn.example.com", &published.fingerprint.to_text()] {
        assert!(!json.contains(name), "{name} while locked");
    }
}
