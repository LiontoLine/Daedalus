"""The model endpoint, editable from the console (Spec §8).

The console can point Daedalus at a different model without editing the config and restarting.
That is useful and it is also the kind of feature that leaks a credential if nobody writes down
what must not happen, so these tests hold the four properties that make it safe:

* the key lives in memory only — never in the config file, the database, an event, an artifact or
  a response body;
* a non-loopback endpoint requires an explicit acknowledgement, because it sends the operator's
  source code off the machine on every call;
* the panel always reports which endpoint is actually answering and where that value came from,
  because "which model is answering?" otherwise has three indistinguishable answers;
* a key pasted into the model-name field is refused rather than sent as a model name and logged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from daedalus.application import model_settings
from daedalus.application.model_settings import ModelOverrideRejected
from daedalus.config import ProviderSettings, Settings, WorkspaceSettings

SECRET = "sk-live-do-not-leak-1234567890"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "ws")),
        providers={
            "planner": ProviderSettings(
                name="planner",
                base_url="http://127.0.0.1:11434/v1",
                model="configured-model",
                api_key_env="DAEDALUS_TEST_KEY",
            )
        },
        default_role="planner",
    )


# ------------------------------------------------------------------ validation


def test_a_non_loopback_endpoint_requires_an_acknowledgement() -> None:
    """Pointing at a remote endpoint sends the repository off the machine on every call.

    A legitimate choice, and a terrible one to make by accident — so it is refused until the
    operator says they know, and the reason names the host.
    """
    with pytest.raises(ModelOverrideRejected) as caught:
        model_settings.build(
            base_url="https://api.example.com/v1", model="gpt-4o-mini", api_key="k"
        )
    assert "不是本机地址" in str(caught.value)
    assert "api.example.com" in str(caught.value)

    accepted = model_settings.build(
        base_url="https://api.example.com/v1",
        model="gpt-4o-mini",
        api_key="k",
        acknowledged_remote=True,
    )
    assert accepted.is_loopback is False
    assert accepted.acknowledged_remote is True


@pytest.mark.parametrize(
    "base_url, model",
    [
        ("", "m"),
        ("ftp://127.0.0.1/v1", "m"),
        ("http://127.0.0.1:11434/v1", ""),
        ("not-a-url", "m"),
    ],
)
def test_an_unusable_endpoint_is_refused(base_url: str, model: str) -> None:
    with pytest.raises(ModelOverrideRejected):
        model_settings.build(base_url=base_url, model=model, api_key="k")


def test_a_key_pasted_into_the_model_field_is_refused() -> None:
    """Otherwise the key is sent as a model name and recorded as one, in plain text."""
    with pytest.raises(ModelOverrideRejected) as caught:
        model_settings.build(base_url="http://127.0.0.1:11434/v1", model=SECRET)
    assert "密钥" in str(caught.value)
    assert "模型名" in str(caught.value)


def test_loopback_endpoints_need_no_acknowledgement() -> None:
    for host in ("127.0.0.1", "localhost", "127.0.0.53"):
        override = model_settings.build(
            base_url=f"http://{host}:11434/v1", model="m", api_key=""
        )
        assert override.is_loopback, host
    # An empty key is legitimate for a local runtime and must not be refused.
    assert model_settings.build(
        base_url="http://127.0.0.1:11434/v1", model="m", api_key=""
    ).fingerprint() == ""


def test_the_timeout_is_bounded() -> None:
    with pytest.raises(ModelOverrideRejected):
        model_settings.build(base_url="http://127.0.0.1:1/v1", model="m", timeout_sec=0)
    with pytest.raises(ModelOverrideRejected):
        model_settings.build(base_url="http://127.0.0.1:1/v1", model="m", timeout_sec=99999)


# ------------------------------------------------------------------ the secret


def test_the_key_is_never_returned_and_only_a_fingerprint_is() -> None:
    """Everything the console sees about the key is a fingerprint it cannot reverse."""
    override = model_settings.build(
        base_url="http://127.0.0.1:11434/v1", model="m", api_key=SECRET
    )
    payload = override.describe()
    rendered = json.dumps(payload, ensure_ascii=False)
    assert SECRET not in rendered
    assert payload["key_set"] is True
    assert payload["key_fingerprint"]
    assert SECRET not in payload["key_fingerprint"]
    # Stable, so two keys can be told apart, and different keys give different tags.
    other = model_settings.build(
        base_url="http://127.0.0.1:11434/v1", model="m", api_key=SECRET + "x"
    )
    assert other.fingerprint() != override.fingerprint()


def test_temporary_override_does_not_claim_secure_persistence() -> None:
    """Building a temporary connection cannot imply a successful keychain save."""
    override = model_settings.build(
        base_url="http://127.0.0.1:11434/v1", model="m", api_key=SECRET
    )
    assert override.describe()["persisted"] is False
    report = model_settings.report(_settings(Path("/tmp")), override)
    assert report["persisted"] is False
    assert SECRET not in json.dumps(report, ensure_ascii=False)
    assert "临时连接只在当前会话生效" in report["note"]


def test_the_report_says_where_each_value_came_from(tmp_path, monkeypatch) -> None:
    """"Which model is answering?" has three possible answers and they must be distinguishable."""
    settings = _settings(tmp_path)
    monkeypatch.setenv("DAEDALUS_TEST_KEY", "from-the-environment")

    configured = model_settings.report(settings, None)
    assert configured["override"] is None
    assert [row["source"] for row in configured["roles"]] == ["配置文件"]
    assert configured["roles"][0]["key"] == "环境变量 DAEDALUS_TEST_KEY"
    assert configured["roles"][0]["model"] == "configured-model"

    override = model_settings.build(
        base_url="http://127.0.0.1:9999/v1", model="typed-in-console", api_key=SECRET
    )
    replaced = model_settings.report(settings, override)
    assert replaced["roles"][0]["source"] == "界面填写（当前会话）"
    assert replaced["roles"][0]["model"] == "typed-in-console"
    assert replaced["roles"][0]["base_url"] == "http://127.0.0.1:9999/v1"
    assert "内存密钥" in replaced["roles"][0]["key"]
    assert SECRET not in json.dumps(replaced, ensure_ascii=False)


def test_a_missing_environment_key_is_reported_not_implied(tmp_path, monkeypatch) -> None:
    """The most common reason a call fails is the least obvious from outside."""
    monkeypatch.delenv("DAEDALUS_TEST_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DAEDALUS_MODEL_API_KEY", raising=False)
    report = model_settings.report(_settings(tmp_path), None)
    assert "未设置" in report["roles"][0]["key"]


def test_a_remote_override_is_flagged_in_the_report(tmp_path) -> None:
    override = model_settings.build(
        base_url="https://api.example.com/v1", model="m", api_key="k", acknowledged_remote=True
    )
    report = model_settings.report(_settings(tmp_path), override)
    assert report["remote_warning"], "a remote endpoint must be stated, not left implicit"
    assert report["roles"][0]["loopback"] is False


def test_a_scoped_override_leaves_the_other_roles_on_the_config(tmp_path) -> None:
    """`role=""` means every role; naming one redirects only that one."""
    settings = Settings(
        workspace=WorkspaceSettings(root=str(tmp_path / "ws")),
        providers={
            "planner": ProviderSettings(name="planner", model="p"),
            "coder": ProviderSettings(name="coder", model="c"),
        },
        default_role="planner",
    )
    scoped = model_settings.build(
        base_url="http://127.0.0.1:11434/v1", model="only-the-coder", role="coder"
    )
    report = model_settings.report(settings, scoped)
    by_role = {row["role"]: row for row in report["roles"]}
    assert by_role["coder"]["model"] == "only-the-coder"
    assert by_role["planner"]["model"] == "p"
    assert by_role["planner"]["source"] == "配置文件"
    assert scoped.applies_to("coder") and not scoped.applies_to("planner")


# ------------------------------------------------------------------ the client


def test_the_client_uses_the_override_without_touching_the_environment(tmp_path, monkeypatch) -> None:
    """The key comes from the override object, so the broker and the environment are not used."""
    from daedalus.service.app import ServiceState

    monkeypatch.delenv("DAEDALUS_TEST_KEY", raising=False)
    state = ServiceState(_settings(tmp_path))
    try:
        # Without an override the configured environment variable is required and missing.
        from daedalus.errors import DaedalusError

        client = state.build_model_client("planner")
        assert client.model == "configured-model"
        with pytest.raises(DaedalusError):
            client.complete([])  # the resolver runs and finds no credential

        state.model_override = model_settings.build(
            base_url="http://127.0.0.1:11434/v1", model="typed", api_key=SECRET
        )
        client = state.build_model_client("planner")
        assert client.model == "typed"
        assert client.base_url == "http://127.0.0.1:11434/v1"
        # An empty key on a local endpoint is passed through rather than refused.
        assert client._api_key() == SECRET
        state.model_override = model_settings.build(
            base_url="http://127.0.0.1:11434/v1", model="typed", api_key=""
        )
        assert state.build_model_client("planner")._api_key() == ""
    finally:
        state.close(drain=False)


# ------------------------------------------------------------------ over HTTP


def _client(tmp_path: Path):
    from fastapi.testclient import TestClient

    from daedalus.service.app import create_app

    app = create_app(_settings(tmp_path))
    return TestClient(app)


def test_the_console_can_set_and_clear_the_endpoint_over_http(tmp_path) -> None:
    with _client(tmp_path) as client:
        initial = client.get("/api/model").json()
        assert initial["override"] is None
        assert initial["roles"][0]["source"] == "配置文件"

        saved = client.post("/api/model", json={
            "base_url": "http://127.0.0.1:11434/v1", "model": "typed", "api_key": SECRET,
        })
        assert saved.status_code == 200, saved.text
        body = saved.json()
        assert body["override"]["model"] == "typed"
        assert body["roles"][0]["source"] == "界面填写（当前会话）"
        assert SECRET not in saved.text, "the key must never come back"

        cleared = client.delete("/api/model").json()
        assert cleared["override"] is None
        assert cleared["roles"][0]["source"] == "配置文件"


def test_a_remote_endpoint_without_acknowledgement_is_a_422(tmp_path) -> None:
    with _client(tmp_path) as client:
        response = client.post("/api/model", json={
            "base_url": "https://api.example.com/v1", "model": "m", "api_key": "k",
        })
        assert response.status_code == 422, response.text
        assert "不是本机地址" in response.json()["detail"]
        # And the endpoint is unchanged, so a refused override cannot half-apply.
        assert client.get("/api/model").json()["override"] is None


def test_testing_a_dead_endpoint_reports_why_rather_than_raising(tmp_path) -> None:
    """The whole point of the button: find out here, not after typing a task."""
    with _client(tmp_path) as client:
        result = client.post("/api/model/test", json={
            "base_url": "http://127.0.0.1:9/v1", "model": "m", "timeout_sec": 5,
        })
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["ok"] is False
        assert body["error"]
        assert body["hint"]
        # A failed probe must not install anything.
        assert client.get("/api/model").json()["override"] is None


def test_the_key_is_not_written_anywhere_the_database_or_log_can_reach(tmp_path) -> None:
    """After setting an override, the key is in no table and in no event payload."""
    import sqlite3

    with _client(tmp_path) as client:
        assert client.post("/api/model", json={
            "base_url": "http://127.0.0.1:11434/v1", "model": "typed", "api_key": SECRET,
        }).status_code == 200
        settings = client.app.state.daedalus.settings  # type: ignore[attr-defined]
        database = Path(settings.workspace.database_path)

    connection = sqlite3.connect(str(database))
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        ]
        for table in tables:
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            for column in columns:
                found = connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE CAST({column} AS TEXT) LIKE ?",
                    (f"%{SECRET}%",),
                ).fetchone()[0]
                assert found == 0, f"the key reached {table}.{column}"
    finally:
        connection.close()

    # And the config file itself was never rewritten.
    assert not Path(settings.workspace.root_path, "daedalus.toml").exists()


def test_the_override_works_when_the_config_has_no_model_at_all(tmp_path) -> None:
    """The situation the panel exists for: a workspace with nothing configured.

    Resolving the configured provider before consulting the override raised "no model provider
    configured for role 'planner'", so the one case the feature is for was the one case it
    could not serve. Found by using it with the config's model removed.
    """
    from daedalus.service.app import ServiceState

    settings = Settings(workspace=WorkspaceSettings(root=str(tmp_path / "empty")))
    assert settings.providers == {}
    state = ServiceState(settings)
    try:
        report = model_settings.report(state.settings, state.model_override)
        assert report["roles"] == [], "nothing is configured, and the panel says so"

        state.model_override = model_settings.build(
            base_url="http://127.0.0.1:11434/v1", model="typed", api_key="k"
        )
        client = state.build_model_client("planner")
        assert client.model == "typed"
        assert client.base_url == "http://127.0.0.1:11434/v1"
        assert client._api_key() == "k"
        # And with the override cleared it is back to refusing, not to a silent default.
        state.model_override = None
        from daedalus.errors import DaedalusError

        with pytest.raises(DaedalusError):
            state.build_model_client("planner")
    finally:
        state.close(drain=False)


def test_the_console_can_be_used_with_no_model_configured_over_http(tmp_path) -> None:
    """Over HTTP too: set a model in an empty workspace, then clear it."""
    from fastapi.testclient import TestClient

    from daedalus.config import Settings as S
    from daedalus.service.app import create_app

    app = create_app(S(workspace=WorkspaceSettings(root=str(tmp_path / "empty"))))
    with TestClient(app) as client:
        report = client.get("/api/model").json()
        assert report["roles"] == []
        assert report["override"] is None

        assert client.post("/api/model", json={
            "base_url": "http://127.0.0.1:11434/v1", "model": "typed", "api_key": SECRET,
        }).status_code == 200
        # The intake now has a model to call, so it fails at the endpoint rather than at the
        # configuration — which is a different, and actionable, error.
        started = client.post("/api/intakes", json={
            "repo_path": str(tmp_path), "objective": "x",
        })
        assert started.status_code in {400, 422, 503}, started.text
        assert "没有配置任何模型" not in started.text
