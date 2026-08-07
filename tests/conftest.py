import json
import pytest
import keytruth


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    path = tmp_path / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", path)
    return path


@pytest.fixture
def fixture_tree(tmp_path):
    """Synthetic .env tree covering reuse, placeholders, and several providers."""
    openai = "sk-proj-" + ("A" * 48)
    stripe_live = "sk_live_" + ("B" * 24)
    stripe_test = "sk_test_" + ("C" * 24)
    anthropic = "sk-ant-" + ("D" * 40)
    openrouter = "sk-or-v1-" + ("E" * 32)
    replicate = "r8_" + ("F" * 37)
    resend = "re_" + ("G" * 24)

    (tmp_path / "proj-a").mkdir()
    (tmp_path / "proj-b").mkdir()
    (tmp_path / "proj-a" / "node_modules").mkdir()
    (tmp_path / "proj-a" / "node_modules" / ".env").write_text(
        f"OPENAI_API_KEY={openai}\n"
    )

    (tmp_path / "proj-a" / ".env").write_text(
        f"""
OPENAI_API_KEY={openai}
ANTHROPIC_API_KEY={anthropic}
STRIPE_SECRET_KEY={stripe_live}
OPENROUTER_API_KEY={openrouter}
REPLICATE_API_TOKEN={replicate}
RESEND_API_KEY={resend}
EMPTY_KEY=
PLACEHOLDER_KEY=your-api-key-here
MALFORMED_TOKEN=short
CUSTOM_SECRET=not-a-known-provider-but-long-enough-secret
""".strip()
        + "\n"
    )
    (tmp_path / "proj-b" / ".env.local").write_text(
        f"""
OPENAI_API_KEY={openai}
STRIPE_SECRET_KEY={stripe_live}
STRIPE_TEST_KEY={stripe_test}
ANTHROPIC_API_KEY=replace-me-later
""".strip()
        + "\n"
    )

    return {
        "root": tmp_path,
        "openai": openai,
        "stripe_live": stripe_live,
        "stripe_test": stripe_test,
        "anthropic": anthropic,
        "openrouter": openrouter,
        "replicate": replicate,
        "resend": resend,
    }


class Args:
    def __init__(self, paths, **kwargs):
        self.paths = paths
        self.unknown = kwargs.get("unknown", False)
        self.group_by_variable = kwargs.get("group_by_variable", False)
        self.reused = kwargs.get("reused", False)
        self.financial = kwargs.get("financial", False)
        self.experimental = kwargs.get("experimental", False)
        self.debug = kwargs.get("debug", False)
        self.yes = kwargs.get("yes", True)
        self.placeholders = kwargs.get("placeholders", False)
        self.json = kwargs.get("json", False)
        self.no_color = kwargs.get("no_color", True)
        self.key_id = kwargs.get("key_id", "")
