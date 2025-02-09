from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository

class DataIngestor:

    @staticmethod
    def construct_workflow_cache(yaml_results):
        """Creates a cache of workflow yaml files retrieved from GraphQL. Since
        GraphQL and REST do not have parity, we still need to use REST for most
        enumeration calls. This method saves off all yaml files, so during org
        level enumeration if we perform yaml enumeration the cached file is used
        instead of making GitHub REST requests.

        Args:
            yaml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """

        cache = CacheManager()
        for result in yaml_results:
            # If we get any malformed/missing data just skip it and 
            # Gato will fall back to the contents API for these few cases.
            if not result:
                continue
                
            if 'nameWithOwner' not in result:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)
            # Empty means no yaml files, so just skip.
            if result['object']:
                for yaml_node in result['object']['entries']:
                    yaml_name = yaml_node['name']
                    if yaml_name.lower().endswith('yaml') or yaml_name.lower().endswith('yml'):
                        contents = yaml_node['object']['text']
                        wf_wrapper = Workflow(owner, contents, yaml_name)
                        
                        cache.set_workflow(owner, yaml_name, wf_wrapper) 

            repo_data = {
                'full_name': result['nameWithOwner'],
                'html_url': result['url'],
                'visibility': 'private' if result['isPrivate'] else 'public',
                'default_branch': result['defaultBranchRef']['name'] if result['defaultBranchRef'] else 'main',
                'fork': result['isFork'],
                'stargazers_count': result['stargazers']['totalCount'],
                'pushed_at': result['pushedAt'],
                'permissions': {
                    'pull': (result['viewerPermission'] == 'READ' or
                             result['viewerPermission'] == 'TRIAGE' or
                             result['viewerPermission'] == 'WRITE' or
                             result['viewerPermission'] == 'MAINTAIN' or
                             result['viewerPermission'] == 'ADMIN'),
                    'push': (result['viewerPermission'] == 'WRITE' or
                             result['viewerPermission'] == 'MAINTAIN' or
                             result['viewerPermission'] == 'ADMIN'),
                    'admin': result['viewerPermission'] == 'ADMIN',
                    'maintain': result['viewerPermission'] == 'MAINTAIN'
                },
                'archived': result['isArchived'],
                'isFork': result['isFork'],
                'environments': [],
                'visibility_type': 'private' if result['isPrivate'] else 'public',
                'allow_forking': result['forkingAllowed']
            }

            if 'environments' in result and result['environments']:
                # Capture environments not named github-pages
                envs = [env['node']['name'] for env in result['environments']['edges'] if env['node']['name'] != 'github-pages']
                repo_data['environments'] = envs
                    
            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)