from pydantic import BaseModel
from typing import List, Optional
from enum import Enum


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


class HTTPAction(Enum):
    POST = 'POST'
    GET = 'GET'


class ManifestObject(BaseModel):
    service_name: str
    external_id: Optional[str] = None
    sbom_name: Optional[str] = None
    sbom_type: Optional[str] = None
    sbom_ingestion_url: Optional[str] = None
    http_action: Optional[HTTPAction] = None
    jq: Optional[str] = None


class Suggestion(BaseModel):
    objectId: str
    displayName: str
    type: str
    category: str


class Data(BaseModel):
    type: str
    suggestions: List[Suggestion]


class SearchResult(BaseModel):
    status: str
    data: List[Data]


class Match(BaseModel):
    is_matched: bool
    match: Optional[Suggestion] = None
