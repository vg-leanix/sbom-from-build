import requests
from .models import *
import base64
import uuid
import time
import jwt
from dotenv import load_dotenv
import yaml
import zipfile
import os
import logging


load_dotenv()


PEM_PATH = os.getenv('PRIVATE_KEY')
APP_ID = os.getenv('APP_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
BASE_URL = "https://api.github.com"

logging.basicConfig(level=logging.INFO)


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

    for artifact in artifacts.artifacts.artifacts:
        if artifact.name == filename:
            headers = {
                "Authorization": f"Bearer {jwt}",
                "Accept": "application/vnd.github+json"
            }
            if not os.path.exists(storage_dir):
                os.makedirs(storage_dir)

            with requests.get(url=artifact.archive_download_url, headers=headers, stream=True) as r:
                r.raise_for_status()

                file_extension = r.headers.get("Content-Type", "zip")
                filename_zip = f"{storage_dir}/sbom-{str(uuid.uuid4())}.{file_extension}"

                with open(filename_zip, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

            temp_store = f"{storage_dir}/sbom-{str(uuid.uuid4())}"
            with zipfile.ZipFile(filename_zip, 'r') as zip_ref:
                zip_ref.extractall(temp_store)

            os.remove(filename_zip)

        else:
            logging.info(f"Artifact:{artifact.name} - Target File: {filename}")


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

        logging.error(f"Error message: {err}")
        logging.error(f"Headers: {headers}")


async def get_file_content(url: str, jwt: str, installation_id: int = None) -> BlobResponse:

    if jwt is None:
        jwt = await get_accesstoken_by_installation_id(installation_id=installation_id)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }
    res = requests.get(url=url, headers=headers)

    res.raise_for_status()

    return BlobResponse(** res.json())


async def find_sbomname_from_manifest(url: str, jwt: str):

    data = await get_file_content(url=url, jwt=jwt)

    decoded_bytes = base64.b64decode(data.content)
    decoded_string = decoded_bytes.decode('utf-8')
    data = yaml.safe_load(decoded_string)

    sbom_name = data.get('sbom', {}).get('name', None)

    if sbom_name:
        logging.info(f"SBOM path set in manifest. Filename: {sbom_name}")
        return sbom_name

    else:
        raise "sbom.json"


async def process_manifest(installation_id: int, repo: str, owner: str):

    jwt = await get_accesstoken_by_installation_id(installation_id=installation_id)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "application/vnd.github+json"
    }
    url = f"{BASE_URL}/search/code?q=filename:leanix.yaml repo:{owner}/{repo}"

    res = requests.get(url=url, headers=headers)
    res.raise_for_status()

    search_res = SearchResponse(**res.json())

    if len(search_res.items) > 0:
        search_res.items = [search_res.items[0]]

        logging.info(f"Found {len(search_res.items)} matches when searching for leanix.yaml")

    sbom_name = await find_sbomname_from_manifest(url=search_res.items[0].git_url, jwt=jwt)

    return sbom_name


async def process_artifacts(workflow_event: WorkflowEvent, run_id: str, owner: str, repo: str, installation_id: int):
    artifacts = await get_run_artefacts(run_id=run_id, owner=owner, repo=repo, installation_id=installation_id)

    ev = FullWorkflowEvent(
        workflow_event=workflow_event,
        artifacts=artifacts
    )
    sbom_name = await process_manifest(installation_id=installation_id, repo=repo, owner=owner)
    await download_sbom(artifacts=ev, filename=sbom_name)
