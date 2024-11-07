import requests
import os
import csv
from datetime import datetime
from iocparser import IOCParser
import logging
import validators
from stix2 import Bundle, DomainName, IPv4Address, IPv6Address, File, URL, EmailAddress, Vulnerability

class IOCFetcher:
    def __init__(self):
        self.repos_file = "ioc_sources.csv"
        self.base_folder = "repositories"
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self._init_structure()
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

    def _init_structure(self):
        if not os.path.exists(self.repos_file):
            with open(self.repos_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['repository_url', 'latest_commit', 'last_updated'])

        
        if not os.path.exists(self.base_folder):
            os.makedirs(self.base_folder)

    def _get_repo_folder(self, repo_url):
        return os.path.join(self.base_folder, repo_url.replace('/', '_'))

    def _read_repos(self):
        repos = {}
        try:
            with open(self.repos_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    repos[row['repository_url']] = {
                        'latest_commit': row['latest_commit'],
                        'last_updated': row['last_updated']
                    }
        except Exception as e:
            logging.error(f"Error reading repositories file: {str(e)}")
        return repos

    def _update_repo_commit(self, repo_url, commit_sha):
        repos = self._read_repos()
        repos[repo_url] = {
            'latest_commit': commit_sha,
            'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            with open(self.repos_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['repository_url', 'latest_commit', 'last_updated'])
                for repo, data in repos.items():
                    writer.writerow([repo, data['latest_commit'], data['last_updated']])
            return True
        except Exception as e:
            logging.error(f"Error updating repositories file: {str(e)}")
            return False

    def _get_latest_commit(self, repo_url):
        api_url = f"https://api.github.com/repos/{repo_url}/commits"
        try:
            response = requests.get(api_url, headers=self.headers)
            response.raise_for_status()
            return response.json()[0]['sha']
        except requests.RequestException as e:
            logging.error(f"Error fetching latest commit for {repo_url}: {str(e)}")
            return None

    def _get_contents_recursively(self, repo_url, path=''):
        """Recursively fetch all files and folders from a repository"""
        files = []
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{path}"
        try:
            response = requests.get(api_url, headers=self.headers)
            response.raise_for_status()
            
            for item in response.json():
                if item['type'] == 'file':
                    files.append((item['path'], item['download_url'],item['size']))
                elif item['type'] == 'dir':
                    # Recursively get contents of subdirectory
                    files.extend(self._get_contents_recursively(repo_url, item['path']))
        except requests.RequestException as e:
            logging.error(f"Error fetching contents for {repo_url} at path {path}: {str(e)}")
        return files

    def _get_changed_files(self, repo_url, current_commit, previous_commit=None):
        """Get all files or changed files between commits"""
        if not previous_commit:
            # If no previous commit, get all files recursively
            return self._get_contents_recursively(repo_url)
        else:
            # Get changed files between commits
            api_url = f"https://api.github.com/repos/{repo_url}/compare/{previous_commit}...{current_commit}"
            try:
                response = requests.get(api_url, headers=self.headers)
                response.raise_for_status()
                
                changed_files = []
                for file in response.json()['files']:
                    if file['status'] != 'removed':
                        # For modified or added files
                        if file['status'] in ['modified', 'added']:
                            file_contents_url=file['contents_url']
                            response = requests.get(file_contents_url, headers=self.headers)
                            response.raise_for_status()
                            file_details=response.json()
                            file_size=file_details.get('size')
                            changed_files.append((file['filename'], file['raw_url'], file_size))
                        # For renamed files
                        elif file['status'] == 'renamed':
                            file_contents_url=file['contents_url']
                            response = requests.get(file_contents_url, headers=self.headers)
                            response.raise_for_status()
                            file_details=response.json()
                            file_size=file_details.get('size')
                            changed_files.append((file['filename'], file['raw_url'], file_size))
                return changed_files
            except requests.RequestException as e:
                logging.error(f"Error fetching changed files for {repo_url}: {str(e)}")
                return []

    def _process_file(self, file_name, file_url, repo_folder,file_size):

        if file_url is not None:
            
    
            try:
                response = requests.get(file_url, headers=self.headers)
                response.raise_for_status()
                
                # Save original file
                file_path = os.path.join(repo_folder, 'original_files', file_name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                stix_objects = []
                # Extract IOCs if applicable
                if file_name.lower().endswith(('.txt', '.csv')) and file_size < 10000000:
                    logging.info(f"Processing {file_name}")
                    parser = IOCParser(response.text)
                    iocs = parser.parse()
                    if iocs:
                        ioc_path = os.path.join(repo_folder, 'iocs', f"{file_name}.iocs")
                        os.makedirs(os.path.dirname(ioc_path), exist_ok=True)
                        with open(ioc_path, 'w') as f:
                            for ioc in iocs:
                                if hasattr(ioc, 'value'):
                                    f.write(f"{ioc.value}\n")
                                    ioc_value = ioc.value
                                    if validators.ipv4(ioc_value):
                                        observable = IPv4Address(value=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    elif validators.ipv6(ioc_value):
                                        observable = IPv6Address(value=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    elif validators.url(ioc_value):
                                        observable = URL(value=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    elif validators.domain(ioc_value):
                                        observable = DomainName(value=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    elif validators.email(ioc_value):
                                        observable = EmailAddress(value=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    elif ioc.kind in ['md5', 'sha1', 'sha256']:
                                        hash_type = ioc.kind.upper()
                                        observable = File(hashes={hash_type: ioc_value}, allow_custom=True, x_opencti_description=file_name)
                                    elif ioc.kind == 'file':
                                        observable = File(name=ioc_value,   allow_custom=True, x_opencti_description=file_name)
                                    elif ioc.kind == 'CVE':
                                        observable = Vulnerability(name=ioc_value, allow_custom=True, x_opencti_description=file_name)
                                    else:
                                        logging.warning(f"Unsupported IOC kind or invalid value: {ioc_value}")
                                        continue
                                    stix_objects.append(observable)
                                elif hasattr(ioc, 'ioc'):
                                    f.write(f"{ioc.ioc}\n")
                                else:
                                    f.write(f"{str(ioc)}\n")
                    if stix_objects:
                        bundle = Bundle(objects=stix_objects)
                        stix_path = os.path.join(repo_folder, 'stix', f"{file_name}.json")
                        with open(stix_path, 'w') as f:
                            f.write(bundle.serialize(indent=2))
            except requests.RequestException as e:
                logging.error(f"Error processing file {file_name} from {file_url}: {str(e)}")
        else:
            return None
            

    def fetch_and_sync(self):
        repos = self._read_repos()
        updated = False

        for repo_url in repos:
            try:
                print(f"Processing repository: {repo_url}")
                repo_folder = self._get_repo_folder(repo_url)
                latest_commit = self._get_latest_commit(repo_url)
                if latest_commit is None:
                    continue
                previous_commit = repos[repo_url]['latest_commit']

                if latest_commit != previous_commit:
                    print(f"Found new changes in {repo_url}")
                    changed_files = self._get_changed_files(repo_url, latest_commit, previous_commit)
                    
                    for file_name, file_url, file_size in changed_files:
                        self._process_file(file_name, file_url, repo_folder,file_size)
                    
                    self._update_repo_commit(repo_url, latest_commit)
                    updated = True
                else:
                    print(f"No new changes in {repo_url}")

            except Exception as e:
                logging.error(f"Error processing {repo_url}: {str(e)}")
                continue

        return updated

def update_readme():
    def generate_sources_section(repos):
        sources_section = "## Sources\n\nThe following sources are being collected and parsed:\n\n"
        for idx, (repo_url, data) in enumerate(repos.items(), start=1):
            sources_section += f"{idx}. **{repo_url}**\n"
            sources_section += f"   - Repository: [{repo_url}](https://github.com/{repo_url})\n"
            sources_section += f"   - Latest commit: {data['latest_commit']}\n"
            sources_section += f"   - Last updated: {data['last_updated']}\n\n"
        return sources_section

    def write_readme(content):
        with open("README.md", "w") as f:
            f.write(content)

    repos = IOCFetcher()._read_repos()
    sources_section = generate_sources_section(repos)

    with open("README.md", "r") as f:
        readme_content = f.read()

    updated_content = readme_content.split("## Sources")[0] + sources_section

    write_readme(updated_content)

def main():
    fetcher = IOCFetcher()
    updated = fetcher.fetch_and_sync()
    update_readme()
   
        

if __name__ == "__main__":
    main()
