"""User-managed project references and inspectable retrieval receipts."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from daedalus.application.agentic_rag import route_query
from daedalus.application.replay import run_repo_path
from daedalus.errors import DaedalusError
from daedalus.model.base import TokenBudget


class KnowledgeRequest(BaseModel):
    repo_path: str
    kind: str = "document"
    title: str = Field(min_length=1, max_length=160)
    text: str = Field(min_length=1, max_length=24000)
    confirmed: bool = False


class RetrievalRequest(BaseModel):
    repo_path: str
    query: str = Field(min_length=1, max_length=1000)
    use_model: bool = False
    mode: str = Field(default="auto", pattern="^(auto|grep|lexical|hybrid|deep)$")


class RetrievalSetupRequest(BaseModel):
    enabled: bool = True
    download_models: bool = False


class IndexRequest(BaseModel):
    repo_path: str


def knowledge_router(state) -> APIRouter:
    router = APIRouter()

    def view(repo):
        try:
            return {
                "repo_path": state.knowledge.repository(repo),
                "records": state.knowledge.records(repo),
                "traces": state.knowledge.traces(repo),
                "retrieval": "direct repository search or bounded evidence investigation",
                "retrieval_status": state.retrieval.status(),
                "reranking": "available_on_request_with_model_controller",
            }
        except DaedalusError as error:
            raise HTTPException(400, detail=error.message) from None

    @router.get("/api/knowledge")
    def get_knowledge(repo_path: str):
        return view(repo_path)

    @router.get("/api/runs/{run_id}/knowledge")
    def run_knowledge(run_id: str):
        if state.store.get_run(run_id) is None:
            raise HTTPException(404, detail="task not found")
        return view(run_repo_path(state.store, run_id))

    @router.post("/api/knowledge", status_code=201)
    def add_knowledge(request: KnowledgeRequest):
        try:
            record = state.knowledge.add(
                **request.model_dump(exclude={"repo_path"}), repo=request.repo_path
            )
            return {"record": record}
        except DaedalusError as error:
            raise HTTPException(400, detail=error.message) from None

    @router.delete("/api/knowledge/{record_id}")
    def delete_knowledge(record_id: str, repo_path: str):
        try:
            if not state.knowledge.delete(repo_path, record_id):
                raise HTTPException(404, detail="knowledge not found")
            state.retrieval.index.invalidate(state.knowledge.repository(repo_path))
            return {"deleted": True}
        except DaedalusError as error:
            raise HTTPException(400, detail=error.message) from None

    @router.post("/api/knowledge/retrieve")
    def retrieve(request: RetrievalRequest):
        try:
            needs_controller = request.mode in {"hybrid", "deep"} or (
                request.mode == "auto" and route_query(request.query, phase="manual")[0] == "deep"
            )
            client = (
                state.build_model_client("planner")
                if request.use_model and needs_controller
                else None
            )
            return state.rag.retrieve(
                request.repo_path,
                request.query,
                client=client,
                mode=request.mode,
                budget=TokenBudget(max_tokens_per_step=24000, max_tokens_per_run=24000),
            )
        except DaedalusError as error:
            raise HTTPException(400, detail=error.message) from None

    @router.get("/api/knowledge/retrieval/status")
    def retrieval_status():
        return state.retrieval.status()

    @router.post("/api/knowledge/retrieval/setup")
    def retrieval_setup(request: RetrievalSetupRequest):
        try:
            return state.retrieval.prepare(
                download=request.download_models, enabled=request.enabled
            )
        except DaedalusError as error:
            raise HTTPException(
                409,
                detail={
                    "code": error.code,
                    "message": error.message,
                    "status": state.retrieval.status(),
                },
            ) from None

    @router.post("/api/knowledge/retrieval/index")
    def build_index(request: IndexRequest):
        try:
            repo = state.knowledge.repository(request.repo_path)
            epoch = state.retrieval.index.epoch(repo)
            from daedalus.infrastructure.retrieval_tools import RepositorySearch

            tools = RepositorySearch(repo)
            corpus = state.rag.corpus(repo, include_code=True, tools=tools)
            _, receipt = state.retrieval.search(
                repo, corpus, "project reference index", limit=1, expected_epoch=epoch
            )
            return receipt
        except DaedalusError as error:
            raise HTTPException(
                409, detail={"code": error.code, "message": error.message}
            ) from None

    return router
