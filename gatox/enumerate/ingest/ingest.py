from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository

class DataIngestor:

    @staticmethod
    def construct_workflow_cache(yml_results):
        """Creates a cache of workflow YAML files retrieved from GraphQL. Since
        GraphQL and REST do not have parity, we still need to use REST for most
        enumeration calls. This method saves off all YAML files, so during org
        level enumeration if we perform YAML enumeration the cached file is used
        instead of making GitHub REST requests.

        Args:
            yml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """

        cache = CacheManager()
        for result in yml_results:
            # Skip if result is missing or does not contain 'nameWithOwner'
            if not result or 'nameWithOwner' not in result:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)

            # Skip if no YAML files are present
            if not result.get('object'):
                continue

            for yml_node in result['object']['entries']:
                yml_name = yml_node['name']
                if yml_name.lower().endswith(('.yml', '.yaml')):
                    contents = yml_node['object']['text']
                    wf_wrapper = Workflow(owner, contents, yml_name)
                    cache.set_workflow(owner, yml_name, wf_wrapper)

            repo_data = {
                'full_name': result['nameWithOwner'],
                'html_url': result['url'],
                'visibility': 'private' if result['isPrivate'] else 'public',
                'default_branch': result['defaultBranchRef']['name'] if result.get('defaultBranchRef') else 'main',
                'fork': result['isFork'],
                'stargazers_count': result['stargazers']['totalCount'],
                'pushed_at': result['pushedAt'],
                'permissions': {
                    'pull': result['viewerPermission'] in ['READ', 'TRIAGE', 'WRITE', 'MAINTAIN', 'ADMIN'],
                    'push': result['viewerPermission'] in ['WRITE', 'MAINTAIN', 'ADMIN'],
                    'admin': result['viewerPermission'] == 'ADMIN'
                },
                'archived': result['isArchived'],
                'isFork': result['isFork'],
                'environments': []
            }

            if result.get('environments'):
                # Capture environments not named github-pages
                envs = [env['node']['name'] for env in result['environments']['edges'] if env['node']['name'] != 'github-pages']
                repo_data['environments'] = envs

            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)