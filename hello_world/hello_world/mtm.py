import requests
from dotenv import load_dotenv
import os
load_dotenv()

TOKEN = os.getenv("LX_TOKEN")
HOST = os.getenv("HOST")


class LeanIXClient:
    def __init__(self, api_token: str = None, fqdn: str = HOST):
        self.token = api_token
        self.fqdn = fqdn
        self.bearer = self.__authenticate()

    def __authenticate(self):
        TIMEOUT = 10
        OAUTH2_URL = f"https://{self.fqdn}.leanix.net/services/mtm/v1/oauth2/token"

        response = requests.post(
            OAUTH2_URL,
            auth=("apitoken", self.token),
            data={"grant_type": "client_credentials"},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        response_payload = response.json()
        access_token = response_payload["access_token"]
        return access_token

    def post_sbom(self, file_path: str, factsheet_id: str):

        headers = {
            "Authorization": f"Bearer {self.bearer}"
        }

        url = f"https://{
            self.fqdn}.leanix.net/services/technology-discovery/v1/microservices/{factsheet_id}/sboms"

        with open(file_path, 'rb') as f:
            sbom_contents = f.read()

        request_payload = {
            'sbom': (
                'spdx.json',
                sbom_contents,
                'application/json'
            )
        }
        response = requests.post(
            url=url, files=request_payload, headers=headers)
        response.raise_for_status()

        return response.json()['data']
