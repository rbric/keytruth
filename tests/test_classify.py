import keytruth
from keytruth import (
    classify_key,
    classify_assignment,
    hash_key,
    mask_key,
    apply_reuse_risk,
    compute_risk,
    risk_label,
)


def test_classify_key_categories():
    assert classify_key("") == "Empty"
    assert classify_key("****") == "Empty"
    assert classify_key("replace-with-your-key") == "Placeholder"
    assert classify_key("your_api_key_here") == "Placeholder"
    assert classify_key("sk-...redacted") == "Placeholder"
    assert classify_key("<TOKEN>") == "Placeholder"
    assert classify_key("short") == "Malformed"
    assert classify_key("has space in value xx") == "Malformed"
    assert classify_key("sk-" + "x" * 40) == "Candidate"
    assert classify_key("r8_" + "y" * 10) == "Candidate"


def test_classify_assignment_by_name_and_shape():
    openai = "sk-proj-" + ("A" * 48)
    assert classify_assignment("OPENAI_API_KEY", openai) == ("OPENAI", False)
    assert classify_assignment("ANTHROPIC_API_KEY", "sk-ant-" + ("B" * 40)) == ("ANTHROPIC", False)
    assert classify_assignment("STRIPE_SECRET_KEY", "sk_live_" + ("C" * 24)) == ("STRIPE", False)
    assert classify_assignment("OPENAI_API_KEY", "replace-me") == ("OPENAI", True)
    assert classify_assignment("RANDOM_VAR", openai)[0] in {"OPENAI", "DEEPSEEK"}
    assert classify_assignment("MY_CUSTOM_SECRET", "a" * 32) == ("UNKNOWN", False)
    assert classify_assignment("MY_CUSTOM_SECRET", "replace-me") == ("IGNORE", True)
    assert classify_assignment("PATH", "/usr/bin") == ("IGNORE", True)


def test_mask_and_hash_stable():
    key = "sk-proj-" + ("Z" * 48)
    assert mask_key(key).startswith("sk-proj-")
    assert "..." in mask_key(key)
    assert len(hash_key(key)) == 12
    assert hash_key(key) == hash_key(key)
    assert hash_key(key) != hash_key(key + "x")


def test_apply_reuse_risk_dumb_rule():
    rows = [
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env", "b.env"],
            "status": {
                "metric_value": "No balance authority",
                "auth": "Valid",
                "access": "Working",
                "risk": "Low",
            },
        },
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env", "b.env.example"],
            "status": {
                "metric_value": "No balance authority",
                "auth": "Valid",
                "access": "Working",
                "risk": "Low",
            },
        },
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env", "b.env"],
            "status": {"metric_value": "Unprobed", "auth": "Unknown", "risk": "Low"},
        },
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env"],
            "status": {"metric_value": "Unprobed", "auth": "Unknown", "risk": "Low"},
        },
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env", "b.env"],
            "status": {"metric_value": "Placeholder", "auth": "Not tested", "risk": "Low"},
        },
        {
            "provider": "OPENAI",
            "masked_key": "sk-proj-xxxx",
            "files": ["a.env", "a.env.backup", "a.env.bak"],
            "status": {
                "metric_value": "No balance authority",
                "auth": "Valid",
                "access": "Working",
                "risk": "Low",
            },
        },
        {
            "provider": "STRIPE",
            "masked_key": "sk_test_xxxx",
            "files": ["a.env", "b.env"],
            "status": {"metric_value": "Test key", "auth": "Detected", "risk": "Low"},
        },
        {
            "provider": "HUGGINGFACE",
            "masked_key": "hf_xxxx",
            "files": ["a.env", "b.env"],
            "status": {"metric_value": "Invalid Key", "auth": "Invalid", "risk": "Low"},
        },
    ]
    apply_reuse_risk(rows)
    assert rows[0]["status"]["risk"].startswith("Critical")  # live reuse
    assert rows[1]["status"]["risk"].startswith("Critical")  # real key in .env.example after probe
    assert rows[2]["status"]["risk"].startswith("Review")  # unprobed → soft
    assert "probe to confirm" in rows[2]["status"]["risk"]
    assert rows[3]["status"]["risk"] == "Low"
    assert rows[4]["status"]["risk"] == "Low"
    assert rows[5]["status"]["risk"] == "Low"  # backup-only extras
    assert rows[6]["status"]["risk"].startswith("Review")  # test key
    assert rows[7]["status"]["risk"].startswith("Review")  # dead key


def test_unprobed_never_critical():
    data = {
        "provider": "OPENAI",
        "masked_key": "sk-x",
        "files": ["a.env", "b.env.example", "c.env"],
        "status": {"metric_value": "Unprobed", "auth": "Unknown"},
    }
    assert risk_label(compute_risk(data)) == "REVIEW"
