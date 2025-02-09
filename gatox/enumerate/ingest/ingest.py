from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository

class DataIngestor:

    @staticmethod
    def construct_workflow_cache(yml_results):
        """Creates a cache of workflow yml files retrieved from GraphQL. Since
        GraphQL and REST do not have parity, we still need to use REST for most
        enumeration calls. This method saves off all yml files, so during org
        level enumeration if we perform yml enumeration the cached file is used
        instead of making GitHub REST requests.

        Args:
            yml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """

        cache = CacheManager()
        for result in yml_results:
            # Skip malformed or missing data
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

            # Enhanced security checks for workflow triggers
            if wf_wrapper.parsed_yml and 'on' in wf_wrapper.parsed_yml:
                triggers = wf_wrapper.parsed_yml['on']
                if isinstance(triggers, dict):
                    for trigger, config in triggers.items():
                        if trigger == 'push' and 'branches' not in config:
                            Output.warn(f"Workflow {yml_name} in {owner} triggers on all branches, consider specifying branches.")
                        elif trigger == 'pull_request' and 'branches' not in config:
                            Output.warn(f"Workflow {yml_name} in {owner} triggers on all branches for pull requests, consider specifying branches.")
                        elif trigger == 'schedule':
                            Output.warn(f"Workflow {yml_name} in {owner} has scheduled triggers, ensure they are necessary and secure.")
                        elif trigger == 'workflow_dispatch':
                            Output.warn(f"Workflow {yml_name} in {owner} can be manually triggered, ensure proper access controls are in place.")

            # Improved handling of self-hosted runner analysis
            if repo_wrapper.environments:
                for env in repo_wrapper.environments:
                    Output.info(f"Analyzing environment {env} in {owner} for self-hosted runners.")
                    # Additional logic to check for self-hosted runners can be added here