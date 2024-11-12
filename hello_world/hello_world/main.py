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


async def get_accesstoken_by_installation_id(installation_id: int):

    jwt = await generate_jwt()

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }

    res = requests.post(url=f"{BASE_URL}/app/installations/{installation_id}/access_tokens", headers=headers)

    res.raise_for_status()

    js = res.json()

    return js['token']


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


async def download_sbom(artifacts: FullWorkflowEvent, filename: str = "sbom.json", storage_dir="temp"):

    jwt = await get_accesstoken_by_installation_id(installation_id=artifacts.workflow_event.header.installation_id)

    i = 0
    for artifact in artifacts.artifacts.artifacts:
        if artifact.name == filename:
            headers = {
                "Authorization": f"Bearer {jwt}",
                "Accept": "application/vnd.github+json"
            }
            with requests.get(url=artifact.archive_download_url, headers=headers, stream=True) as r:
                r.raise_for_status()
                file_extension = r.headers.get("Content-Type", "zip")
                filename = f"{storage_dir}/sbom-{str(i)}.{file_extension}"
                with open(filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            i += 1


async def get_run_artefacts(run_id: str, owner: str, repo: str, installation_id: int):

    jwt = await get_accesstoken_by_installation_id(installation_id=installation_id)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }
    res = requests.get(url=f"{BASE_URL}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts", headers=headers)

    try:
        res.raise_for_status()
        return ArtefactsResponse(**res.json())

    except requests.HTTPError:
        err = res.text
        headers = res.headers

        print(f"Error message: {err}")
        print(f"Headers: {headers}")


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/webhook")
async def handle_webhook(request: Request):

    headers = request.headers
    payload = await request.json()

    webhook_event = WebhookEventHeader(
        event_type=headers.get('x-github-event'),
        action=payload.get('action', ''),
        installation_id=payload.get("installation", {}).get("id", "")
    )
    print("Webhook Event:", webhook_event)

    if webhook_event.event_type == "workflow_job" and webhook_event.action == "completed":

        workflow_event = WorkflowEvent(
            header=webhook_event,
            run_id=payload.get("workflow_job", {}).get("run_id", ""),
            owner=payload.get("repository", {}).get("owner", {}).get("login", ""),
            repo=payload.get("repository", {}).get("name", ""),
            status=payload.get("workflow_job", {}).get("status", ""),
            conclusion=payload.get("workflow_job", {}).get("conclusion", "")
        )

        # print(workflow_event)

        artifacts = await get_run_artefacts(run_id=workflow_event.run_id, owner=workflow_event.owner, repo=workflow_event.repo, installation_id=webhook_event.installation_id)

        ev = FullWorkflowEvent(
            workflow_event=workflow_event,
            artifacts=artifacts
        )
        d = await download_sbom(ev)

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Webhook received but no relevant action taken"})
