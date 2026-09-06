pub fn assert_product_output(output: &str) {
    for private in [
        "implementation_phase=",
        "security_release_gate=",
        "roundtrip_security_gate=",
        "distribution_release_gate=",
        "public_publication_gate=",
        "release_artifact_available=",
        "release_hardening_required=",
        "release_gate=",
        "implemented phase",
        "RT-",
        "PUB-",
        "HUMAN DECISION",
        "EVIDENCE-MISSING",
    ] {
        assert!(
            !output.contains(private),
            "private CLI bookkeeping: {private}"
        );
    }
}
