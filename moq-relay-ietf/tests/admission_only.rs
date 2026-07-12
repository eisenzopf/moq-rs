// SPDX-FileCopyrightText: 2026 Bridgefu contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use moq_relay_ietf::{AdmissionLease, AdmissionSessionId, DenyAllAdmission, SessionAdmission};

fn requires_session_admission<T: SessionAdmission>() {}

fn accepts_admission_lease(_: Option<&dyn AdmissionLease>) {}

#[test]
fn admission_contract_is_public_without_the_runtime_feature() {
    requires_session_admission::<DenyAllAdmission>();
    accepts_admission_lease(None);

    let session_id = AdmissionSessionId::new("admission-only-contract").unwrap();
    assert_eq!(session_id.as_str(), "admission-only-contract");
}
