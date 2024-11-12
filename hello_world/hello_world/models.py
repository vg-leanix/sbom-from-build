from pydantic import BaseModel
from datetime import datetime


class WebhookEventHeader(BaseModel):
    event_type: str
    action: str


class WorkflowEvent(BaseModel):
    header: WebhookEventHeader
    run_id:  int
    owner: str
    repo: str
    status: str
    conclusion: str


class Artefacts(BaseModel):
    id: int
    name: str
    size_in_bytes: int
    url: str
    download_url: str


class ArtefactsResponse(BaseModel):
    total_counts: int
    artefacts: Artefacts
