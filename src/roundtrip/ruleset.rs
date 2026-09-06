//! Canonical public detector-suite compatibility descriptor.

use std::fmt::Write as _;

use crate::rule_metadata::DetectorRuleSpec;

use super::canonical::CanonicalWriter;
use super::crypto::public_static_sha256;
use super::token::TokenCategory;
use super::{Error, Result};

pub const OVERLAP_NORMALIZATION_VERSION: &str = "safeclone-overlap-normalization-v1";
pub const EMBEDDED_RULESET_ID: &str =
    "ruleset-sha256-db05d116f06728ef64c5cdf7cc087df2f2f799459d2845a15e32479a1e8d1825";
const DESCRIPTOR_LIMIT: usize = 256 * 1024;

pub fn ruleset_id() -> &'static str {
    EMBEDDED_RULESET_ID
}

pub fn canonical_descriptor() -> Result<Vec<u8>> {
    let mut specs = Vec::new();
    specs.extend(crate::secrets::descriptor_rule_specs());
    specs.extend(crate::sensitive::descriptor_rule_specs());
    specs.extend(crate::filename::descriptor_rule_specs());
    specs.sort_by(|left, right| left.rule_id.cmp(right.rule_id));
    if specs
        .windows(2)
        .any(|pair| pair[0].rule_id >= pair[1].rule_id)
    {
        return Err(Error::InvalidCanonicalInput);
    }

    let mut writer = CanonicalWriter::new("safeclone/rt1/ruleset-descriptor", DESCRIPTOR_LIMIT)?;
    writer.u16(1)?;
    writer.u32(u32::try_from(specs.len()).map_err(|_| Error::BoundExceeded)?)?;
    for spec in &specs {
        encode_rule(&mut writer, spec)?;
    }
    writer.ascii(OVERLAP_NORMALIZATION_VERSION)?;
    let mapping = [
        ("secret", TokenCategory::Secret),
        ("email_address", TokenCategory::Email),
        ("international_phone", TokenCategory::Phone),
        (
            "japanese_domestic_phone_candidate",
            TokenCategory::JapanesePhone,
        ),
        ("ip_address", TokenCategory::Ip),
        (
            "japanese_postal_code_candidate",
            TokenCategory::JapanesePostal,
        ),
        ("my_number_candidate", TokenCategory::MyNumber),
        (
            "japanese_corporate_number_candidate",
            TokenCategory::CorporateNumber,
        ),
        ("multiple_distinct_categories", TokenCategory::Multiple),
    ];
    writer.u32(u32::try_from(mapping.len()).map_err(|_| Error::BoundExceeded)?)?;
    for (evidence, category) in mapping {
        writer.ascii(evidence)?;
        writer.u8(category as u8)?;
        writer.ascii(category.as_str())?;
    }
    Ok(writer.finish())
}

pub fn computed_ruleset_id() -> Result<String> {
    let digest = public_static_sha256(&canonical_descriptor()?);
    let mut id = String::with_capacity("ruleset-sha256-".len() + 64);
    id.push_str("ruleset-sha256-");
    for byte in digest {
        write!(&mut id, "{byte:02x}").map_err(|_| Error::InvalidCanonicalInput)?;
    }
    Ok(id)
}

fn encode_rule(writer: &mut CanonicalWriter, spec: &DetectorRuleSpec) -> Result<()> {
    writer.ascii(spec.rule_id)?;
    writer.u8(spec.scope_flags)?;
    writer.u32(u32::try_from(spec.patterns.len()).map_err(|_| Error::BoundExceeded)?)?;
    for pattern in &spec.patterns {
        writer.bytes(pattern)?;
    }
    writer.ascii(spec.validator_id)?;
    writer.ascii(spec.category)?;
    writer.ascii(spec.token_category)?;
    let mut parameters = spec.parameters.clone();
    parameters.sort_by(|left, right| left.id.cmp(right.id));
    if parameters.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(Error::InvalidCanonicalInput);
    }
    writer.u32(u32::try_from(parameters.len()).map_err(|_| Error::BoundExceeded)?)?;
    for parameter in parameters {
        writer.ascii(parameter.id)?;
        writer.u64(parameter.value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ruleset_id_matches_canonical_descriptor() {
        let computed = computed_ruleset_id().expect("compute public ruleset ID");
        assert_eq!(computed, EMBEDDED_RULESET_ID, "computed={computed}");
    }
}
