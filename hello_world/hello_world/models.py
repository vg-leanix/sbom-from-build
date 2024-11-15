from pydantic import BaseModel
from typing import List, Optional


class WebhookEventHeader(BaseModel):
    event_type: str
    action: str
    installation_id: int


class WorkflowEvent(BaseModel):
    header: WebhookEventHeader
    run_id:  int
    owner: str
    repo: str
    status: str
    conclusion: str


class Artifact(BaseModel):
    id: int
    name: str
    size_in_bytes: int
    url: str
    archive_download_url: str


class ArtefactsResponse(BaseModel):
    total_count: int
    artifacts: List[Artifact]


class FullWorkflowEvent(BaseModel):
    workflow_event: WorkflowEvent
    artifacts: ArtefactsResponse


class SearchItem(BaseModel):
    name: str
    path: str
    git_url: str


class SearchResponse(BaseModel):
    incomplete_results: bool
    items: List[SearchItem]


class BlobResponse(BaseModel):
    url: str
    content: str
    encoding: str


class ManifestObject(BaseModel):
    external_id: Optional[str] = None
    sbom_name: str
