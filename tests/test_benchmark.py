"""Offline benchmark protocol checks; these are never real-model results."""

import json
from pathlib import Path

import pytest

from daedalus.application.benchmark import MeteredClient, run_comparison, write_report
from daedalus.application.benchmark_cases import MODEL_CASES
from daedalus.model.base import Completion, Message, ModelError


def test_failed_completion_usage_still_consumes_comparison_budget():
    from daedalus.errors import ModelResponseIncomplete

    class Incomplete:
        name = model = "controlled-incomplete-response"

        def complete(self, *args, **kwargs):
            raise ModelResponseIncomplete("truncated", usage={"prompt_tokens": 10, "completion_tokens": 90})

    client = MeteredClient(Incomplete(), max_calls=3, max_tokens=100)
    with pytest.raises(ModelResponseIncomplete):
        client.complete([Message("user", "task")])
    assert client.total == 100 and client.records[0]["usage_available"]
    with pytest.raises(ModelError, match="budget exhausted"):
        client.complete([Message("user", "task")])
    assert len(client.records) == 1


def test_service_factory_uses_existing_client_without_environment_key(tmp_path, monkeypatch):
    monkeypatch.delenv("DAEDALUS_MODEL_API_KEY", raising=False)
    count = []

    class Unavailable:
        name = model = "controlled-unavailable-client"

        def complete(self, *args, **kwargs):
            raise ModelError("offline controlled failure")

    def factory():
        count.append(1)
        return Unavailable()

    report = run_comparison(tmp_path / "factory", mode="model", model="explicit",
                            client_factory=factory, cases=MODEL_CASES[:1], repeats=1)
    assert len(count) == 2 and report["real_model_completions"] == 0
    assert report["status"] == "BLOCKED"
    protocol = json.loads((tmp_path / "factory/protocol.json").read_text())
    assert protocol["client_source"] == "existing_service_profile"


def test_controlled_pairs_use_same_tree_and_measure_faults_and_overhead(tmp_path):
    report = run_comparison(tmp_path / "comparison", repeats=1)
    assert report["status"] == "COMPLETE"
    assert report["real_model_completions"] == 0
    rows = report["trials"]
    for case in {row["case"] for row in rows}:
        pair = [row for row in rows if row["case"] == case]
        assert len(pair) == 2 and len({row["initial_tree"] for row in pair}) == 1
        assert all(row["tokens"] is None and not row["model_evidence_valid"] for row in pair)
        assert all(not row.get("event_sequence_errors") for row in pair)
    single, daedalus = (report["summary"][arm] for arm in ("single", "daedalus"))
    assert single["normal_safe_deliveries"] == daedalus["normal_safe_deliveries"] == 2
    assert single["unsafe_deliveries"] == 2 and daedalus["unsafe_deliveries"] == 0
    assert single["faults_blocked"] == 0 and daedalus["faults_blocked"] == 2
    assert single["worker_calls"] == 5 and daedalus["worker_calls"] == 9
    assert all(row["wall_seconds"] > 0 for row in rows)
    root = tmp_path / "comparison"
    assert (root / "protocol.json").is_file() and (root / "trials.csv").is_file()
    page = (root / "report.html").read_text()
    assert "非模型能力测评" in page
    assert "row.cells[3]" in page  # arm filter follows CSV's added fault column
    with pytest.raises(ValueError, match="empty"):
        run_comparison(root, repeats=1)


def test_missing_credential_is_blocked_with_no_invented_quality_or_tokens(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_BENCHMARK_API_KEY", raising=False)
    root = tmp_path / "no-credential"
    report = run_comparison(
        root,
        mode="model",
        model="explicit",
        base_url="https://example.invalid/v1",
        api_key_env="TEST_BENCHMARK_API_KEY",
        repeats=1,
    )
    assert report["status"] == "BLOCKED" and report["real_model_completions"] == 0
    assert (root / "protocol.json").is_file()
    for arm in report["summary"].values():
        assert arm["quality_trials"] == 0 and arm["safe_deliveries"] is None
        assert arm["tokens"] is None and arm["median_wall_seconds"] is None
    assert "未测得" in (root / "report.html").read_text()


def test_transport_failure_is_not_a_zero_percent_quality_trial(tmp_path, monkeypatch):
    class Unavailable:
        model = "offline-transport-failure"
        name = "offline-test-double"

        def __init__(self, **kwargs):
            pass

        def complete(self, *args, **kwargs):
            raise ModelError("explicit offline failure")

    monkeypatch.setenv("TEST_BENCHMARK_API_KEY", "offline-test-only")
    monkeypatch.setattr("daedalus.application.benchmark.OpenAICompatibleClient", Unavailable)
    report = run_comparison(
        tmp_path / "failed",
        mode="model",
        model="offline-transport-failure",
        base_url="https://example.invalid/v1",
        api_key_env="TEST_BENCHMARK_API_KEY",
        repeats=1,
        cases=MODEL_CASES[:1],
    )
    assert report["status"] == "BLOCKED" and report["real_model_completions"] == 0
    assert len(report["trials"]) == 2
    for arm in report["summary"].values():
        assert arm["model_calls"] > 0
        assert arm["quality_trials"] == 0 and arm["unsafe_deliveries"] is None
        assert arm["tokens"] is None


def test_failed_calls_count_toward_budget_and_output_budget_is_capped():
    class Fake:
        model, name = "offline", "offline-test-double"
        limits = []

        def complete(self, messages, **kwargs):
            self.limits.append(kwargs["max_tokens"])
            if len(self.limits) == 1:
                raise ModelError("offline failure")
            return Completion("{}", self.model, 3, 2, 1)

    fake = Fake()
    client = MeteredClient(fake, max_calls=2, max_tokens=100)
    messages = [Message("user", "hello")]
    with pytest.raises(ModelError):
        client.complete(messages, max_tokens=500)
    client.complete(messages, max_tokens=500)
    with pytest.raises(ModelError, match="exhausted"):
        client.complete(messages)
    assert len(client.records) == 2 and fake.limits == [99, 99]
    assert client.total == 5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"repeats": 0},
        {"max_calls": 0},
        {"max_tokens": -1},
        {"timeout": 0},
        {"transport": "unknown"},
        {"mode": "model"},
    ],
)
def test_invalid_protocol_does_not_create_experiment(tmp_path, kwargs):
    destination = tmp_path / "invalid"
    with pytest.raises(ValueError):
        run_comparison(destination, **kwargs)
    assert not destination.exists()
