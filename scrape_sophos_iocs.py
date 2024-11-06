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
        response = requests.get(f"{self.base_url}/commits", headers=self.headers)
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
        response = requests.get(f"{self.base_url}/contents", headers=self.headers)
        response.raise_for_status()
        
        iocs = []
        for file in response.json():
            if file['name'].lower().endswith(('.csv', '.txt')):
                file_response = requests.get(file['download_url'], headers=self.headers)
                file_response.raise_for_status()
                iocs.append(file_response.text)
        return iocs

    def _parse_iocs(self, data):
        iocs = []
        for item in data:
            parser = IOCParser(item)
            results = parser.parse()
            # Extract the actual IOC value from each IOC object
            for ioc in results:
                if hasattr(ioc, 'value'):
                    iocs.append(ioc.value)
                elif hasattr(ioc, 'ioc'):
                    iocs.append(ioc.ioc)
                else:
                    # Try converting the object directly to string as fallback
                    iocs.append(str(ioc))
        return iocs

    def _save_iocs(self, iocs):
        # Remove any duplicates and sort
        unique_iocs = sorted(set(iocs))
        with open(self.output_file, 'a') as f:
            f.write('\n'.join(unique_iocs))

    def fetch_and_save(self):
        latest_commit = self._get_latest_commit()
        saved_commit = self._read_saved_commit()

        if latest_commit == saved_commit:
            print("No new IOCs to fetch")
            return False

        ioc_data = self._download_ioc_files()
        if not ioc_data:
            print("No IOC files found")
            return False

        parsed_iocs = self._parse_iocs(ioc_data)
        if parsed_iocs:
            self._save_iocs(parsed_iocs)
            self._save_commit(latest_commit)
            print(f"Successfully saved {len(parsed_iocs)} IOCs")
            return True
        return False

def main():
    fetcher = SophosIOCFetcher()
    return fetcher.fetch_and_save()

if __name__ == "__main__":
    main()
