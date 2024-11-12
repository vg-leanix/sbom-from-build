from pydantic import BaseModel


class WebhookEventHeader(BaseModel):
    event_type: str
    action: str


class ReleaseEvent(BaseModel):
    pass
