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


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/webhook")
async def handle_webhook(request: Request):
    # res = await validate_jwt()
    # print("Validation: ", res)

    headers = request.headers
    event_type = headers.get('x-github-event')

    payload = await request.json()
    action = payload.get('action', '')

    webhook_event = WebhookEventHeader(
        event_type=event_type,
        action=action
    )
    print(webhook_event)
    # Handling release events specifically
    if action == 'published' and 'release' in payload:
        release = payload['release']
        assets = release.get('assets', [])
        if assets:
            print("Release assets found:", assets)
            return JSONResponse(content={"status": "Assets found", "assets": assets})
        else:
            print("No assets were stored for release with tag:", release.get('tag_name', ''))
            return JSONResponse(content={"status": "No assets found"})

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Webhook received but no relevant action taken"})
