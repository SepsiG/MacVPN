//! The secret agent's pure rules (`pure::nm::agent`): the CRV1 hints, the prompt's message, the deadline.

use macvpn_platform_linux::pure::nm::agent::{CRV1_DEADLINE_SECS, dynamic_challenge, message};

#[test]
fn the_dynamic_challenge_hint_and_its_echo_flag() {
    let hints =
        vec!["x-vpn-message:Enter your code".to_string(), "x-dynamic-challenge-echo:challenge-response".to_string()];
    assert_eq!(dynamic_challenge(&hints), Some((true, "Enter your code".to_string())));
    let hints = vec!["x-dynamic-challenge:challenge-response".to_string()];
    assert_eq!(dynamic_challenge(&hints), Some((false, String::new())));
    assert_eq!(dynamic_challenge(&["password".to_string()]), None);
}

#[test]
fn the_message_is_cleaned_for_the_prompt() {
    assert_eq!(message(&["x-vpn-message:a\u{7}b".to_string()]), Some("ab".to_string()));
    assert!(message(&[format!("x-vpn-message:{}", "x".repeat(5000))]).unwrap().chars().count() <= 512);
}

#[test]
fn the_deadline_stays_inside_nms_agent_timeout() {
    assert!((20..=120).contains(&CRV1_DEADLINE_SECS));
}
