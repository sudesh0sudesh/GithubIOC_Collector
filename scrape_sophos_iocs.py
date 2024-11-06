import requests
import os
from iocparser import IOCParser

class SophosIOCFetcher:
    def __init__(self):
        self.base_url = "https://api.github.com/repos/sophoslabs/IoCs"
        self.commit_file = "latest_commit.txt"
        self.output_file = "sophos_iocs.txt"
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }

    def _get_latest_commit(self):
        response = requests.get(
            f"{self.base_url}/commits",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()[0]['sha']

    def _read_saved_commit(self):
        if not os.path.exists(self.commit_file):
            return ""
        with open(self.commit_file, "r") as f:
            return f.read().strip()

    def _save_commit(self, commit_sha):
        with open(self.commit_file, "w") as f:
            f.write(commit_sha)

    def _download_ioc_files(self):
        response = requests.get(
            f"{self.base_url}/contents",
            headers=self.headers
        )
        response.raise_for_status()
        
        iocs = []
        for file in response.json():
            if file['name'].lower().endswith(('.csv', '.txt')):
                file_response = requests.get(
                    file['download_url'],
                    headers=self.headers
                )
                file_response.raise_for_status()
                iocs.append(file_response.text)
        return iocs

    def _parse_iocs(self, data):
        iocs = []
        for item in data:
            parser = IOCParser(item)
            iocs.extend(parser.parse())
        return iocs

    def _save_iocs(self, iocs):
        with open(self.output_file, 'w') as f:
            f.write('\n'.join(iocs))

    def fetch_and_save(self):
        latest_commit = self._get_latest_commit()
        saved_commit = self._read_saved_commit()

        if latest_commit == saved_commit:
            return False

        ioc_data = self._download_ioc_files()
        if not ioc_data:
            return False

        parsed_iocs = self._parse_iocs(ioc_data)
        self._save_iocs(parsed_iocs)
        self._save_commit(latest_commit)
        return True

def main():
    fetcher = SophosIOCFetcher()
    return fetcher.fetch_and_save()

if __name__ == "__main__":
    main()