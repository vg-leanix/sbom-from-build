from fastapi import FastAPI
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import requests
from .models import *
import time
import jwt
from dotenv import load_dotenv
import os
load_dotenv()

app = FastAPI()

PEM_PATH = os.getenv('PRIVATE_KEY')
APP_ID = os.getenv('APP_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
BASE_URL = "https://api.github.com"


async def generate_jwt(client_id: str = CLIENT_ID,  pem_path: str = PEM_PATH):
    #!/usr/bin/env python3

    # Open PEM
    with open(pem_path, 'rb') as pem_file:
        signing_key = pem_file.read()

    payload = {
        # Issued at time
        'iat': int(time.time()),
        # JWT expiration time (10 minutes maximum)
        'exp': int(time.time()) + 600,

        # GitHub App's client ID
        'iss': client_id
    }

    # Create JWT
    encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')

    return encoded_jwt


async def validate_jwt():

    jwt = await generate_jwt()

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }

    res = requests.get(url="https://api.github.com/app", headers=headers)

    if res.status_code == 200:
        return True
    else:
        return False


async def get_run_artefacts(run_id: str, owner: str, repo: str, jwt: str):

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }
    res = requests.get(url=f"{BASE_URL}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts", headers=headers)

    res.raise_for_status()

    return ArtefactsResponse(**res.json())


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/webhook")
async def handle_webhook(request: Request):
    # res = await validate_jwt()
    # print("Validation: ", res)

    jwt = await generate_jwt()
    headers = request.headers
    event_type = headers.get('x-github-event')

    payload = await request.json()
    action = payload.get('action', '')

    webhook_event = WebhookEventHeader(
        event_type=event_type,
        action=action
    )
    print("Webhook Event:", webhook_event)

    if webhook_event.event_type == "workflow_job" and webhook_event.action == "completed":

        workflow_event = WorkflowEvent(
            header=webhook_event,
            run_id=payload.get("workflow_job", {}).get("run_id", ""),
            owner=payload.get("workflow_job", {}).get("repository", {}).get("owner", {}).get("login", ""),
            repo=payload.get("workflow_job", {}).get("repository", {}).get("name", ""),
            status=payload.get("workflow_job", {}).get("status", ""),
            conclusion=payload.get("workflow_job", {}).get("conclusion", "")
        )

        artefacts = await get_run_artefacts(run_id=workflow_event.run_id, owner=workflow_event.owner, repo=workflow_event.repo, jwt=jwt)

        print("Artefacts: ", artefacts)

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Webhook received but no relevant action taken"})
