"""Real TLS handshakes over memory BIOs, without sockets or model API calls."""

import io
import json
import re
import ssl
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import certifi
import pytest
from fastapi.testclient import TestClient

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.orchestrator import RunOrchestrator
from daedalus.application.scheduler import Quota
from daedalus.config import Settings, WorkspaceSettings
from daedalus.domain.spec import PlanNode
from daedalus.errors import ErrorClass, ModelError
from daedalus.infrastructure.store import EventStore
from daedalus.model import tls
from daedalus.model.base import Message
from daedalus.model.multi_provider import MultiProviderClient, _NoRedirect
from daedalus.model.openai_compatible import OpenAICompatibleClient
from daedalus.service.app import create_app
from tests.conftest import TARGET
from tests.test_parallel_and_rebase import _bundle


@pytest.fixture(autouse=True)
def isolated_ca_environment(monkeypatch):
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "DAEDALUS_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def local_certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("memory-tls")
    certificate, key = directory / "certificate.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
        check=True,
    )
    return certificate, key


def handshake(client_context, certificate, key, hostname="localhost"):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    ci, co, si, so = [ssl.MemoryBIO() for _ in range(4)]
    client = client_context.wrap_bio(ci, co, server_hostname=hostname)
    server = server_context.wrap_bio(si, so, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        if co.pending:
            si.write(co.read())
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        if so.pending:
            ci.write(so.read())
        if client_done and server_done:
            return client
    raise AssertionError("memory handshake did not complete")


def test_missing_python_roots_loads_public_ca_bundle_without_disabling_verification(monkeypatch):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert context.cert_store_stats()["x509_ca"] == 0
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda **kwargs: context)
    configured = tls.create_tls_context()
    assert configured.cert_store_stats()["x509_ca"] > 0
    assert configured.check_hostname and configured.verify_mode == ssl.CERT_REQUIRED


def test_explicit_openssl_ca_selection_is_not_broadened(tmp_path, monkeypatch):
    pem = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        Path(certifi.where()).read_text(),
        re.S,
    ).group()
    single = tmp_path / "one-ca.pem"
    single.write_text(pem + "\n")
    monkeypatch.setenv("SSL_CERT_FILE", str(single))
    monkeypatch.setattr(certifi, "where", lambda: pytest.fail("must respect explicit CA selection"))
    assert tls.create_tls_context().cert_store_stats()["x509_ca"] == 1


@pytest.mark.parametrize("name", ["SSL_CERT_FILE", "DAEDALUS_CA_BUNDLE"])
def test_bad_ca_paths_fail_before_any_request(tmp_path, monkeypatch, name):
    monkeypatch.setenv(name, str(tmp_path / "missing.pem"))
    with pytest.raises(tls.ModelTLSConfigurationError):
        tls.create_tls_context()


def test_invalid_ca_file_is_not_silently_ignored(tmp_path, monkeypatch):
    invalid = tmp_path / "bad.pem"
    invalid.write_text("not a certificate")
    monkeypatch.setenv("DAEDALUS_CA_BUNDLE", str(invalid))
    with pytest.raises(tls.ModelTLSConfigurationError):
        tls.create_tls_context()


def test_untrusted_self_signed_chain_is_rejected(local_certificate):
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(tls.create_tls_context(), *local_certificate)


def test_operator_trusted_ca_accepts_chain_but_still_rejects_wrong_host(
    local_certificate, monkeypatch
):
    monkeypatch.setenv("DAEDALUS_CA_BUNDLE", str(local_certificate[0]))
    context = tls.create_tls_context()
    assert handshake(context, *local_certificate).getpeercert()["subject"]
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(context, *local_certificate, hostname="wrong-host.example")
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("wrapped", [True, False])
@pytest.mark.parametrize("protocol", ["openai_chat", "openai_responses", "anthropic", "gemini"])
def test_certificate_failures_are_terminal_for_every_native_protocol(
    monkeypatch, wrapped, protocol
):
    secret = "opaque-private-test-credential"
    error = ssl.SSLCertVerificationError(1, "self signed certificate " + secret)

    def fail(*args, **kwargs):
        raise urllib.error.URLError(error) if wrapped else error

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fail))
    with pytest.raises(tls.ModelTLSVerificationError) as caught:
        MultiProviderClient(api_format=protocol, api_key_resolver=lambda: secret).complete(
            [Message("user", "hello")]
        )
    assert caught.value.error_class == ErrorClass.TERMINAL
    assert secret not in str(caught.value)


def test_opener_uses_verified_context_and_keeps_redirect_blocking(monkeypatch):
    captured = []

    class Opener:
        def open(self, request, **kwargs):
            return io.BytesIO(b"{}")

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *handlers: captured.extend(handlers) or Opener()
    )
    MultiProviderClient._open(urllib.request.Request("https://api.deepseek.com/models"), timeout=5)
    handler = next(item for item in captured if isinstance(item, urllib.request.HTTPSHandler))
    assert handler._context.check_hostname and handler._context.verify_mode == ssl.CERT_REQUIRED
    assert handler._context.cert_store_stats()["x509_ca"] > 0
    assert any(isinstance(item, _NoRedirect) for item in captured)


def test_local_http_does_not_require_a_ca_bundle(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", "/does/not/exist")

    class Opener:
        def open(self, request, **kwargs):
            return io.BytesIO(b"{}")

    def build(*handlers):
        assert not any(isinstance(item, urllib.request.HTTPSHandler) for item in handlers)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build)
    MultiProviderClient._open(urllib.request.Request("http://127.0.0.1:11434/v1/models"), timeout=5)


def test_legacy_chat_client_uses_the_same_ca_policy(monkeypatch):
    def fake(request, **options):
        assert options["context"].cert_store_stats()["x509_ca"] > 0
        assert options["context"].check_hostname
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "self signed chain"))

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    with pytest.raises(tls.ModelTLSVerificationError):
        OpenAICompatibleClient(api_key_resolver=lambda: "").complete([Message("user", "hello")])


@pytest.mark.parametrize("configuration_error", [True, False])
def test_certificate_fault_parks_real_execution_without_retry_or_commit(
    git_repo, tmp_path, monkeypatch, configuration_error
):
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        if configuration_error:
            raise tls.ModelTLSConfigurationError("operator must fix CA configuration")
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "self signed chain"))

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fail))
    store = EventStore(tmp_path / "tls-run.db")
    try:
        orchestrator = RunOrchestrator(
            store=store,
            repo_path=git_repo,
            run_root=tmp_path / "worktrees",
            bundle=_bundle(
                (
                    PlanNode(
                        node_id="fix", objective="fix word count", expected_artifacts=(TARGET,)
                    ),
                ),
                whitelist=(TARGET,),
                attempts=3,
            ),
            worker=ModelWorker(client=MultiProviderClient(api_key_resolver=lambda: "test-only")),
            quota=Quota(max_parallel_steps=1),
        )
        orchestrator.register_spec()
        result = orchestrator.run()
        assert result.status == "AWAITING_APPROVAL", result.describe()
        assert len(calls) == 1
        assert len(result.steps) == 1
        assert result.steps[0].state == "ESCALATED" and result.steps[0].attempt == 1
        assert not result.commits and result.tokens_used == 0
        events = store.events_for_execution(result.execution_id)
        assert not any("Tier1" in e.event_type or "Tier2" in e.event_type for e in events)
    finally:
        store.close()


@pytest.mark.parametrize("status", [None, 401, 404, 405])
def test_model_discovery_does_not_mislabel_tls_or_authentication_as_missing_models(
    tmp_path, monkeypatch, status
):
    def fail(*args, **kwargs):
        if status is None:
            raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "self signed chain"))
        raise urllib.error.HTTPError(
            "https://api.deepseek.com/models", status, "failed", {}, io.BytesIO(b"{}")
        )

    monkeypatch.setattr(MultiProviderClient, "_open", staticmethod(fail))
    app = create_app(Settings(workspace=WorkspaceSettings(root=str(tmp_path / "workspace"))))
    with TestClient(app) as client:
        result = client.post(
            "/api/model/models",
            json={
                "base_url": "https://api.deepseek.com",
                "provider": "deepseek",
                "api_key": "test-only",
            },
        ).json()
        assert not result["ok"]
        if status is None:
            assert result["error_code"] == "model_tls_verification_failed"
            assert "不提供模型列表" not in result["hint"] and "证书" in result["error"]
        elif status == 401:
            assert "API Key" in result["hint"] and "不提供模型列表" not in result["hint"]
        else:
            assert "不提供模型列表" in result["hint"]
