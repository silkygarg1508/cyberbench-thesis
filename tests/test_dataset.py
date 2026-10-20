from cyberbench_verifier.dataset import audit_evidence


def test_evidence_audit_counts_valid_case(sample_case) -> None:
    audit = audit_evidence([sample_case])
    assert audit["cases"] == 1
    assert audit["cases_with_evidence"] == 1
    assert audit["evidence_items"] == 1
    assert audit["missing_required_field_cases"] == 0
    assert audit["missing_evidence_ids"] == 0
    assert audit["duplicate_evidence_ids"] == 0
