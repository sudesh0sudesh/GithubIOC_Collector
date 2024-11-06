import requests
import os
from iocparser import IOCParser
from datetime import datetime

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
        
        iocs_data = []
        for file in response.json():
            if file['name'].lower().endswith(('.csv', '.txt')):
                file_response = requests.get(file['download_url'], headers=self.headers)
                file_response.raise_for_status()
                iocs_data.append({
                    'filename': file['name'],
                    'content': file_response.text
                })
        return iocs_data

    def _parse_iocs(self, data):
        iocs = []
        for ioc in data:
            if hasattr(ioc, 'value'):
                iocs.append(ioc.value)
            elif hasattr(ioc, 'ioc'):
                iocs.append(ioc.ioc)
            else:
                iocs.append(str(ioc))
        return iocs

    def _save_iocs(self, iocs_data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.output_file, 'a') as f:
            f.write(f"\n\n# Updated: {timestamp}\n")
            
            for item in iocs_data:
                filename = item['filename']
                parser = IOCParser(item['content'])
                results = parser.parse()
                parsed_iocs = self._parse_iocs(results)
                
                if parsed_iocs:
                    unique_iocs = sorted(set(parsed_iocs))
                    f.write(f"\n## Source: {filename}\n")
                    f.write('\n'.join(unique_iocs))
                    f.write('\n')
                    print(f"Saved {len(unique_iocs)} IOCs from {filename}")

    def fetch_and_save(self):
        latest_commit = self._get_latest_commit()
        saved_commit = self._read_saved_commit()

        if latest_commit == saved_commit:
            print("No new IOCs to fetch")
            return False

        iocs_data = self._download_ioc_files()
        if not iocs_data:
            print("No IOC files found")
            return False

        self._save_iocs(iocs_data)
        self._save_commit(latest_commit)
        return True

def main():
    fetcher = SophosIOCFetcher()
    return fetcher.fetch_and_save()

if __name__ == "__main__":
    main()
