import requests
import os
import csv
from datetime import datetime
from iocparser import IOCParser

class IOCFetcher:
    def __init__(self):
        self.repos_file = "ioc_sources.csv"
        self.output_file = "sophos_iocs.txt"
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self._init_repos_file()

    def _init_repos_file(self):
        if not os.path.exists(self.repos_file):
            with open(self.repos_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['repository_url', 'latest_commit', 'last_updated'])
                # Add initial repository
                writer.writerow(['sophoslabs/IoCs', '', ''])

    def _read_repos(self):
        repos = {}
        with open(self.repos_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                repos[row['repository_url']] = {
                    'latest_commit': row['latest_commit'],
                    'last_updated': row['last_updated']
                }
        return repos

    def _update_repo_commit(self, repo_url, commit_sha):
        repos = self._read_repos()
        repos[repo_url] = {
            'latest_commit': commit_sha,
            'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(self.repos_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['repository_url', 'latest_commit', 'last_updated'])
            for repo, data in repos.items():
                writer.writerow([repo, data['latest_commit'], data['last_updated']])

    def _get_latest_commit(self, repo_url):
        api_url = f"https://api.github.com/repos/{repo_url}/commits"
        response = requests.get(api_url, headers=self.headers)
        response.raise_for_status()
        return response.json()[0]['sha']

    def _download_ioc_files(self, repo_url):
        api_url = f"https://api.github.com/repos/{repo_url}/contents"
        response = requests.get(api_url, headers=self.headers)
        response.raise_for_status()
        
        iocs_data = []
        for file in response.json():
            if file['name'].lower().endswith(('.csv', '.txt')):
                file_response = requests.get(file['download_url'], headers=self.headers)
                file_response.raise_for_status()
                iocs_data.append({
                    'filename': file['name'],
                    'content': file_response.text,
                    'repo': repo_url
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
                repo = item['repo']
                filename = item['filename']
                parser = IOCParser(item['content'])
                results = parser.parse()
                parsed_iocs = self._parse_iocs(results)
                
                if parsed_iocs:
                    unique_iocs = sorted(set(parsed_iocs))
                    f.write(f"\n## Source: {repo}/{filename}\n")
                    f.write('\n'.join(unique_iocs))
                    f.write('\n')
                    print(f"Saved {len(unique_iocs)} IOCs from {repo}/{filename}")

    def fetch_and_save(self):
        repos = self._read_repos()
        updated = False

        for repo_url in repos:
            try:
                latest_commit = self._get_latest_commit(repo_url)
                if latest_commit != repos[repo_url]['latest_commit']:
                    print(f"Fetching new IOCs from {repo_url}")
                    iocs_data = self._download_ioc_files(repo_url)
                    if iocs_data:
                        self._save_iocs(iocs_data)
                        self._update_repo_commit(repo_url, latest_commit)
                        updated = True
                else:
                    print(f"No new IOCs in {repo_url}")
            except Exception as e:
                print(f"Error processing {repo_url}: {str(e)}")

        return updated

def main():
    fetcher = IOCFetcher()
    return fetcher.fetch_and_save()

if __name__ == "__main__":
    main()
