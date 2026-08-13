from bob15_sast.redaction import REDACTED, redact, redact_text


def test_redacts_tokens_flags_and_sensitive_keys() -> None:
    value = {
        "token": "super-secret-value",
        "nested": ["Authorization: Bearer abcdefghijklmnop", "FLAG{demo-only}"],
    }
    result = redact(value)
    assert result["token"] == REDACTED
    assert "abcdefghijklmnop" not in result["nested"][0]
    assert "demo-only" not in result["nested"][1]


def test_redact_text_preserves_non_secret_context() -> None:
    assert redact_text("status=healthy") == "status=healthy"


def test_redact_common_token_and_private_key_formats() -> None:
    value = (
        "ghp_abcdefghijklmnopqrstuvwxyz123456 "
        "eyJabcdefghijk.abcdefghijk.abcdefghijk "
        "postgresql://demo:p4ssword@example.invalid/db "
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
    )
    cleaned = redact_text(value)
    assert "ghp_" not in cleaned
    assert "eyJ" not in cleaned
    assert "p4ssword" not in cleaned
    assert "not-a-real-key" not in cleaned
