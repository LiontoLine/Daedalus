"""Shared runtime construction policy for untrusted model coding workers."""

from __future__ import annotations

import time

from daedalus.application.coding_worker import ModelWorker
from daedalus.application.inspection import RepositoryInspector
from daedalus.application.worker_checks import DeclaredCheckRunner
from daedalus.errors import ModelBudgetExceeded, ModelError
from daedalus.model.base import TokenBudget, token_usage_details
from daedalus.model.tls import ModelTLSConfigurationError, ModelTLSVerificationError
from daedalus.security.outbound import SecretInPayload


class _RetrievalClient:
    """One retrieval's dispatch latch, including any derived retrieval profile."""

    def __init__(self, client, deadline):
        self._client = client
        self._deadline = deadline
        self._failure = None

    @property
    def name(self):
        return getattr(self._client, "name", "")

    @property
    def model(self):
        return getattr(self._client, "model", "")

    def for_retrieval(self):
        self.raise_failure()
        try:
            profile = getattr(self._client, "for_retrieval", None)
            if callable(profile):
                self._client = profile()
        except Exception as error:
            self._fail(error, dispatched=False)
        return self

    def raise_failure(self):
        if self._failure is not None:
            raise self._failure

    def complete(self, messages, **options):
        if self._failure is not None:
            # The first dispatch's usage belongs only to its original settlement.
            raise ModelError(
                "retrieval dispatch stopped after an earlier failure",
                stop_reason=self._failure.context["stop_reason"],
                request_not_dispatched=True,
            )
        if self._deadline and time.monotonic() >= self._deadline:
            self._failure = ModelError(
                "the shared worker deadline expired during retrieval",
                stop_reason="worker_deadline_exceeded", request_not_dispatched=True,
            )
            raise self._failure
        try:
            return self._client.complete(messages, **options)
        except Exception as error:
            self._fail(error, dispatched=True)

    def _fail(self, error, *, dispatched):
        original = getattr(error, "context", None)
        context = dict(original) if isinstance(original, dict) else {}
        if not dispatched:
            context["request_not_dispatched"] = True
            context.pop("usage", None)
        preserved = isinstance(error, (
            ModelBudgetExceeded, ModelTLSConfigurationError, ModelTLSVerificationError,
            SecretInPayload,
        ))
        usage = token_usage_details(context.get("usage"))
        unknown = (
            context.get("request_not_dispatched") is not True
            and not {"prompt_tokens", "completion_tokens"} <= usage.keys()
            and not preserved
        )
        context["stop_reason"] = "model_usage_unknown" if unknown else "model_call_failed"
        if preserved:
            error.context = context
            self._failure = error
            raise error
        self._failure = ModelError("retrieval model dispatch failed", **context)
        raise self._failure from error


def build_model_worker(
    client,
    *,
    budget=None,
    repo_path="",
    rag=None,
    reference_client=None,
    enable_inspection=True,
    enable_checks=True,
    initial_output_tokens=8192,
    review_headroom_tokens=2048,
):
    """Use common bounded tools without owning stores, clients or their lifecycle.

    Reference retrieval is optional and caller-owned: its events and knowledge must
    belong to the runtime workspace, never an implicit service or private store.
    """
    worker = ModelWorker(
        client=client,
        budget=budget if budget is not None else TokenBudget(),
        inspection_context=RepositoryInspector() if enable_inspection else None,
        check_context=DeclaredCheckRunner() if enable_checks else None,
        initial_output_tokens=initial_output_tokens,
        review_headroom_tokens=review_headroom_tokens,
    )
    if rag is not None and repo_path:
        reference_client = reference_client if reference_client is not None else client

        def retrieve(context, query, *, phase, mode="auto"):
            # Retrieval shares both accounting and admission with coding/review.
            # Hold review headroom while RAG reserves the coder's output allowance.
            guarded = _RetrievalClient(
                reference_client, getattr(context, "deadline_monotonic", 0),
            )
            try:
                with worker.budget.reservation(0, headroom=worker.review_headroom_tokens):
                    return rag.context(
                        str(repo_path), query, phase=phase, mode=mode,
                        client=guarded, budget=worker.budget,
                        target_paths=context.node.expected_artifacts,
                        output_tokens=worker.desired_output_tokens(context),
                    )
            finally:
                # RAG may retain coarse citations after controller/reranking errors;
                # that fallback must not authorize another paid coding dispatch.
                guarded.raise_failure()

        worker.reference_context = lambda context: retrieve(
            context, context.node.objective + "\n" + context.revision_feedback,
            phase="regression" if context.revision_feedback else "execution",
        )
        worker.investigate_context = lambda context, query, gap: retrieve(
            context, query + "\nEvidence gap: " + gap,
            phase="investigation", mode="deep",
        )
    return worker
