from pydantic import BaseModel
from typing import List


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
