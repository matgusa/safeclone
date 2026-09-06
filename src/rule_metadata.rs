//! Shared static detector metadata used by scanners and compatibility hashing.

pub(crate) const SCOPE_CONTENT: u8 = 1;
pub(crate) const SCOPE_PATH: u8 = 2;
pub(crate) const SCOPE_FILENAME: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Parameter {
    pub id: &'static str,
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DetectorRuleSpec {
    pub rule_id: &'static str,
    pub scope_flags: u8,
    pub patterns: Vec<Vec<u8>>,
    pub validator_id: &'static str,
    pub category: &'static str,
    pub token_category: &'static str,
    pub parameters: Vec<Parameter>,
}
