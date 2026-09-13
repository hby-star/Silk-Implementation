//! Selection from already verified certificate material.
use crate::beacon::DistributedError;
use ::silk_beacon::{CertifiedTranscript, protocol::VerifiedDealerCertificate};
use std::collections::{BTreeMap, BTreeSet};
pub(super) type CertifiedMaterialCache = BTreeMap<CertifiedTranscript, VerifiedDealerCertificate>;

pub(super) fn first_distinct_materials(
    cache: &CertifiedMaterialCache,
    count: usize,
) -> Result<Vec<VerifiedDealerCertificate>, DistributedError> {
    let mut dealers = BTreeSet::new();
    let materials = cache
        .iter()
        .filter(|(reference, _)| dealers.insert(reference.dealer))
        .map(|(_, material)| material.clone())
        .take(count)
        .collect::<Vec<_>>();
    if materials.len() != count {
        return Err(DistributedError::Protocol(format!(
            "Silk certified-material cache contains only {} distinct dealers, expected {count}",
            materials.len()
        )));
    }
    Ok(materials)
}
