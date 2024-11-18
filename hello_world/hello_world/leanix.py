import requests
from .models import *
from dotenv import load_dotenv
load_dotenv()


class LeanIXClient:
    def __init__(self, api_token: str = None, fqdn: str = None):
        self.token = api_token
        self.fqdn = fqdn
        self.bearer = self.__authenticate()

    def __authenticate(self):

        auth_url = f'https://{self.fqdn}.leanix.net/services/mtm/v1/oauth2/token'
        response = requests.post(auth_url, auth=('apitoken', self.token),
                                 data={'grant_type': 'client_credentials'})

        response.raise_for_status()
        response_payload = response.json()
        access_token = response_payload["access_token"]
        return access_token

    def search_for_microservice(self, search_term: str, fs_type: str = "Application", category: str = "microservice") -> Match:
        url = f"https://{self.fqdn}.leanix.net/services/pathfinder/v1/suggestions?q={search_term}&count=1&perType=true"
        headers = {
            "Authorization": f"Bearer {self.bearer}"
        }
        res = requests.get(url=url, headers=headers)

        res.raise_for_status()

        js = SearchResult(**res.json())

        filtered_result_list = Match(is_matched=False)

        for i in js.data:
            for d in i.suggestions:
                if d.type == fs_type and d.category == category:
                    filtered_result_list = Match(is_matched=False, match=d)

        return filtered_result_list

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

        return response.status_code
