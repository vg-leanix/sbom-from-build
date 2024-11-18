import requests
from .models import *
import base64
import uuid
import json
import time
import jwt
from dotenv import load_dotenv
import yaml
import zipfile
from .leanix import LeanIXClient
import os
import logging


load_dotenv()


PEM_PATH = os.getenv('PRIVATE_KEY')
APP_ID = os.getenv('APP_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
BASE_URL = "https://api.github.com"
TOKEN = os.getenv("TOKEN")
HOST = os.getenv("HOST")

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

    stored_file_path = None

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

            stored_file_path = f"{temp_store}/{filename}"

        else:
            logging.info(f"Artifact:{artifact.name} - Target File: {filename}")

    return stored_file_path


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


async def process_manifest(url: str, jwt: str) -> ManifestObject:

    data = await get_file_content(url=url, jwt=jwt)

    decoded_bytes = base64.b64decode(data.content)
    decoded_string = decoded_bytes.decode('utf-8')
    data = yaml.safe_load(decoded_string)

    logging.info(f"Manifest: {json.dumps(data, indent=2)} \n")

    service_name = data.get('metadata', {}).get('name')
    sbom_config = data.get('sbom', {}).get('name', None)
    external_id = data.get('metadata', {}).get('externalId', None)
    sbom_ingestion_type = data.get('sbom', {}).get('type', None)
    sbom_ingestion_url = data.get('sbom', {}).get('url', None)
    sbom_http_action = data.get('sbom', {}).get('http_action', None)
    jq = data.get('sbom', {}).get('jq', None)

    if sbom_config:
        logging.info(f"SBOM path set in manifest. Filename: {sbom_config}")

        return ManifestObject(service_name=service_name, external_id=external_id, sbom_name=sbom_config, sbom_type=sbom_ingestion_type, sbom_ingestion_url=sbom_ingestion_url, http_action=sbom_http_action, jq=jq)

    else:
        return ManifestObject(service_name=service_name, external_id=external_id, sbom_name="sbom.json", sbom_type=sbom_ingestion_type, sbom_ingestion_url=sbom_ingestion_url)


async def search_for_manifest(installation_id: int, repo: str, owner: str) -> ManifestObject:

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

    manifest_obj = await process_manifest(url=search_res.items[0].git_url, jwt=jwt)

    logging.info(search_res)

    return manifest_obj


async def get_attribute(obj, path):
    try:
        attrs = path.split('.')
        for attr in attrs:  # Traverse through each attribute in the path
            if isinstance(obj, dict):  # If it's a dictionary
                obj = obj[attr]  # Access the dictionary by key
            else:
                obj = getattr(obj, attr)  # Use getattr to access object's attribute
            return obj
    except (AttributeError, KeyError) as e:
        raise AttributeError(f"Attribute path '{path}' not found") from e


async def fetch_sbom_from_external_source(http_action: HTTPAction, bearer: str, url: str, jq: str = "sbom") -> str:
    # decide if GET Or POST

    if http_action == HTTPAction.POST:
        logging.info(f"Manifest requires external source. {http_action.value} to {url} by looking for: {jq}")
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/vnd.github+json"
        }
        res = requests.post(url=url, headers=headers)
        res.raise_for_status()

        core_dir = "temp"
        filename = f"{core_dir}/sbom-{str(uuid.uuid4())}.json"

        res_js = res.json()

        sbom = await get_attribute(res_js, jq)

        with open(filename, "w") as fs:
            json.dump(sbom, fs, indent=2)

        logging.info(f"Stored SBOM under {filename}")

    elif http_action == HTTPAction.GET:
        logging.info(f"Manifest requires external source. {http_action.value} to {url} by looking for: {jq}")
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/vnd.github+json"
        }
        res = requests.get(url=url, headers=headers)
        res.raise_for_status()
        res_js = res.json()

        core_dir = "temp"
        filename = f"{core_dir}/sbom-{str(uuid.uuid4())}.json"

        sbom = await get_attribute(res_js, jq)

        with open(filename, "w") as fs:
            json.dump(sbom, fs, indent=2)

        logging.info(f"Stored SBOM under {filename}")

    return filename


async def process_artifacts(workflow_event: WorkflowEvent, run_id: str, owner: str, repo: str, installation_id: int):
    artifacts = await get_run_artefacts(run_id=run_id, owner=owner, repo=repo, installation_id=installation_id)

    ev = FullWorkflowEvent(
        workflow_event=workflow_event,
        artifacts=artifacts
    )
    manifest = await search_for_manifest(installation_id=installation_id, repo=repo, owner=owner)

    if manifest.sbom_type == "artifact":
        file_path = await download_sbom(artifacts=ev, filename=manifest.sbom_name)
        logging.info(f"SBOM stored under: {file_path}")

    elif manifest.sbom_type == "api":

        jwt = await get_accesstoken_by_installation_id(installation_id=installation_id)
        file_path = await fetch_sbom_from_external_source(http_action=manifest.http_action, bearer=jwt, url=manifest.sbom_ingestion_url, jq=manifest.jq)

    lx = LeanIXClient(api_token=TOKEN, fqdn=HOST)

    found_fs = lx.search_for_microservice(search_term=manifest.service_name)
    if found_fs.is_matched:
        logging.info(f"Matched and found this existing FS:{json.dumps(found_fs.model_dump(), indent=2)}")
        found_fs_id = found_fs.match.objectId
        status = lx.post_sbom(file_path=file_path, factsheet_id=found_fs_id)
        logging.info(f"Uploaded SBOM - Status: {status}")
    else:
        logging.warning(f"No SBOM uploaded as no matching microservice FS could be found for {manifest.service_name}")
