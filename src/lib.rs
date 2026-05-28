pub mod age_check;
pub mod checker;
pub mod maintainer;
pub mod models;
pub mod namespace;
pub mod registry;
pub mod typosquat;

pub use checker::run_layer0;
pub use models::{CheckResult, Finding, Verdict};
