from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository

class DataIngestor:

    @staticmethod
    def construct_workflow_cache(yml_results):
        """Creates a cache of workflow YAML files retrieved from GraphQL. Since\n        GraphQL and REST do not have parity, we still need to use REST for most\n        enumeration calls. This method saves off all YAML files, so during org\n        level enumeration, if we perform YAML enumeration, the cached file is used\n        instead of making GitHub REST requests.\n\n        Args:\n            yml_results (list): List of results from individual GraphQL queries\n            (100 nodes at a time).\n        """

        cache = CacheManager()
        for result in yml_results:
            # If we get any malformed/missing data, just skip it and
            # Gato will fall back to the contents API for these few cases.
            if not result or 'nameWithOwner' not in result:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)

            # Skip if no YAMLs are present.
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
                repo_data['environments'] = [
                    env['node']['name'] for env in result['environments']['edges']
                    if env['node']['name'] != 'github-pages'
                ]

            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)

            # Enhanced security check for workflow triggers
            if not repo_wrapper.is_archived() and repo_wrapper.has_workflows():
                DataIngestor.check_workflow_triggers(repo_wrapper)

            # Improved handling of self-hosted runner analysis
            if repo_wrapper.has_self_hosted_runners():
                DataIngestor.analyze_self_hosted_runners(repo_wrapper)

    @staticmethod
    def check_workflow_triggers(repo_wrapper):
        """Checks the triggers of workflows for security concerns.\n\n        Args:\n            repo_wrapper (Repository): The repository wrapper containing workflows.\n        """
        for workflow in repo_wrapper.workflows:
            if workflow.is_public() and workflow.triggers_on_pull_request():
                Output.warn(f"Potential security risk: Workflow {workflow.workflow_name} in {repo_wrapper.full_name} triggers on pull requests.")

    @staticmethod
    def analyze_self_hosted_runners(repo_wrapper):
        """Analyzes self-hosted runners for security concerns.\n\n        Args:\n            repo_wrapper (Repository): The repository wrapper containing runner information.\n        """
        for runner in repo_wrapper.runners:
            if runner.is_self_hosted() and not runner.has_required_labels():
                Output.warn(f"Potential security risk: Self-hosted runner {runner.name} in {repo_wrapper.full_name} does not have required labels.")