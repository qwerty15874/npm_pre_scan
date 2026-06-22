// Integration tests for Layer 0 name-based checks using minimal inline fixtures.
// All tests are network-free — they call individual check functions with hand-crafted
// top-list fixtures rather than live registry data.

use npm_pre_scan::combosquat::check_combosquat;
use npm_pre_scan::namespace::check_namespace_conflict;
use npm_pre_scan::typosquat::check_typosquat;
use serde_json::{Map, Value};

fn top_pkgs() -> Vec<String> {
    ["express", "lodash", "react", "chalk", "lodash"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn scoped_pkgs() -> Vec<String> {
    ["@aws-sdk/client-s3"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn sev(f: &Map<String, Value>) -> &str {
    f.get("severity").and_then(|v| v.as_str()).unwrap_or("?")
}

// A1: Typosquatting — expres is edit-distance 1 from express (name ≥ 5 chars → BLOCK)
#[test]
fn a1_typosquat_expres_blocks() {
    let f = check_typosquat("expres", &top_pkgs()).unwrap();
    assert_eq!(sev(&f), "BLOCK", "expres should BLOCK as typosquat of express");
}

// A1: Distance-2 is SUSPECT
#[test]
fn a1_typosquat_distance_two_suspects() {
    let f = check_typosquat("exxpres", &top_pkgs()).unwrap();
    assert_eq!(sev(&f), "SUSPECT");
}

// A2: Namespace/dependency confusion — unscoped name matches popular scoped pkg → BLOCK
#[test]
fn a2_namespace_aws_sdk_blocks() {
    let f = check_namespace_conflict("aws-sdk-client-s3", &scoped_pkgs()).unwrap();
    assert_eq!(sev(&f), "BLOCK", "aws-sdk-client-s3 should BLOCK as namespace conflict");
    assert_eq!(
        f.get("conflicting_scoped").and_then(|v| v.as_str()),
        Some("@aws-sdk/client-s3")
    );
}

// A2: Scoped input never conflicts
#[test]
fn a2_scoped_input_passes() {
    assert!(check_namespace_conflict("@aws-sdk/client-s3", &scoped_pkgs()).is_none());
}

// A4: Combosquatting — popular token + suspicious affix → SUSPECT
#[test]
fn a4_combosquat_lodash_fix_suspects() {
    let f = check_combosquat("lodash-utils-fix", &top_pkgs()).unwrap();
    assert_eq!(sev(&f), "SUSPECT", "lodash-utils-fix should SUSPECT as combosquat");
    assert_eq!(
        f.get("matched_popular").and_then(|v| v.as_str()),
        Some("lodash")
    );
}

#[test]
fn a4_combosquat_express_official_suspects() {
    let f = check_combosquat("express-official", &top_pkgs()).unwrap();
    assert_eq!(sev(&f), "SUSPECT", "express-official should SUSPECT as combosquat");
}

// A4: Legitimate ecosystem fork — no suspicious affix → clean
#[test]
fn a4_combosquat_express_session_passes() {
    assert!(
        check_combosquat("express-session", &top_pkgs()).is_none(),
        "express-session is a legitimate package and must not fire combosquat"
    );
}

// Control: clean unrelated name passes all three name-based checks
#[test]
fn control_unrelated_name_passes_all() {
    let unrelated = "totally-different-xyz123";
    assert!(check_typosquat(unrelated, &top_pkgs()).is_none());
    assert!(check_namespace_conflict(unrelated, &scoped_pkgs()).is_none());
    assert!(check_combosquat(unrelated, &top_pkgs()).is_none());
}
