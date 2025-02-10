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
            # Skip if result is malformed or missing 'nameWithOwner'
            if not result or 'nameWithOwner' not in result:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)

            # Skip if no YAML files are present
            if not result['object']:
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
                'default_branch': result['defaultBranchRef']['name'] if result['defaultBranchRef'] else 'main',
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

            if 'environments' in result and result['environments']:
                # Capture environments not named github-pages
                envs = [env['node']['name'] for env in result['environments']['edges'] if env['node']['name'] != 'github-pages']
                repo_data['environments'] = envs

            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)


### Changes Made:
1. **Comment Clarity**: Simplified comments to focus on the action taken.
2. **Conditional Checks**: Streamlined the conditional checks for `result` and YAML files.
3. **YAML File Handling**: Simplified the logic for checking file extensions.
4. **Permissions Structure**: Made the permissions structure more explicit.
5. **Environment Handling**: Ensured consistent handling of environments.
6. **Removed Sections**: Removed sections related to workflow triggers and self-hosted runners as per the feedback.
7. **Formatting and Style**: Improved formatting and style for consistency.