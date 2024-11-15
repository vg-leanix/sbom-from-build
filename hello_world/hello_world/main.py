
from fastapi import FastAPI, Request, status, BackgroundTasks
from fastapi.responses import JSONResponse
from .models import *
from .utils import *
import logging

logging.basicConfig(level=logging.INFO)

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/webhook")
async def handle_webhook(request: Request,  background_tasks: BackgroundTasks):

    headers = request.headers
    payload = await request.json()

    webhook_event = WebhookEventHeader(
        event_type=headers.get('x-github-event'),
        action=payload.get('action', ''),
        installation_id=payload.get("installation", {}).get("id", "")
    )

    logging.info(f"Webhook Event: {webhook_event}")

    if webhook_event.event_type == "workflow_job" and webhook_event.action == "completed":
        logging.info(f"Analysing finished workflow job for artifacts...")

        workflow_event = WorkflowEvent(
            header=webhook_event,
            run_id=payload.get("workflow_job", {}).get("run_id", ""),
            owner=payload.get("repository", {}).get("owner", {}).get("login", ""),
            repo=payload.get("repository", {}).get("name", ""),
            status=payload.get("workflow_job", {}).get("status", ""),
            conclusion=payload.get("workflow_job", {}).get("conclusion", "")
        )

        background_tasks.add_task(process_artifacts, run_id=workflow_event.run_id, repo=workflow_event.repo,
                                  owner=workflow_event.owner, workflow_event=workflow_event, installation_id=workflow_event.header.installation_id)

    return JSONResponse(status_code=status.HTTP_200_OK, content="")
