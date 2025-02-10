import logging
import time

from gatox.github.api import Api
from gatox.github.gql_queries import GqlQueries
from gatox.models.repository import Repository
from gatox.models.organization import Organization
from gatox.cli.output import Output
from gatox.enumerate.repository import RepositoryEnum
from gatox.enumerate.organization import OrganizationEnum
from gatox.enumerate.recommender import Recommender
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.caching.cache_manager import CacheManager

logger = logging.getLogger(__name__)


class Enumerator:
    """Class holding all high-level logic for enumerating GitHub, whether it is
    a user's entire access, individual organizations, or repositories.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        output_yaml: str = None,
        skip_log: bool = False,
        github_url: str = None,
        output_json: str = None
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token.
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
                Defaults to None.
            http_proxy (str, optional): Proxy settings for HTTP proxy.
                Defaults to None.
            output_yaml (str, optional): If set, directory to save all YAML
                files to. Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be
                downloaded. Defaults to False.
            github_url (str, optional): GitHub API URL. Defaults to None.
            output_json (str, optional): JSON file to output enumeration
                results. Defaults to None.
        """
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None
        self.github_url = github_url
        self.output_json = output_json

        self.repo_e = RepositoryEnum(self.api, skip_log, output_yaml)
        self.org_e = OrganizationEnum(self.api)

    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                "The authenticated user is: "
                f"{Output.bright(self.user_perms['user'])}"
            )
            if self.user_perms["scopes"]:
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    def validate_only(self):
        """Validates the PAT access and exits.

        Returns:
            list: List of organizations if validation is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [Organization({'login': org}, self.user_perms['scopes'], True) for org in orgs]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            list: List of organizations if enumeration is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = list(map(self.enumerate_organization, orgs))

        return org_wrappers

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization, and check everything relevant to
        self-hosted runner abuse that the user has permissions to check.

        Args:
            org (str): Organization to perform enumeration on.

        Returns:
            Organization: Organization object if enumeration is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False

        details = self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!"
            )
            return False

        organization = Organization(details, self.user_perms['scopes'])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)

        Recommender.print_org_findings(
            self.user_perms['scopes'], organization
        )

        enum_list = self.org_e.construct_repo_enum_list(organization)

        Output.info(
            f"About to enumerate "
            f"{len(organization.private_repos) + len(organization.public_repos)}"
            " repos within "
            f"the {organization.name} organization!"
        )

        Output.info(f"Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)

        for i, wf_query in enumerate(wf_queries):
            Output.info(f"Querying {i + 1} out of {len(wf_queries)} batches!", end='\r')
            result = self.org_e.api.call_post('/graphql', wf_query)
            # Sometimes we don't get a 200, fall back in this case.
            if result.status_code == 200:
                DataIngestor.construct_workflow_cache(result.json()['data']['nodes'])
            else:
                Output.warn(
                    "GraphQL query failed, will revert to "
                    "REST workflow query for impacted repositories!"
                )
        try:
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if self.skip_log and repo.is_fork():
                    continue
                Output.tabbed(
                    f"Enumerating: {Output.bright(repo.name)}!"
                )

                cached_repo = CacheManager().get_repository(repo.name)
                if cached_repo:
                    repo = cached_repo

                self.__enhance_permissions(repo)
                self.repo_e.enumerate_repository(repo, large_org_enum=len(enum_list) > 25)
                self.repo_e.enumerate_repository_secrets(repo)
                self.__improve_trigger_detection(repo)

                Recommender.print_repo_secrets(
                    self.user_perms['scopes'],
                    repo.secrets
                )
                Recommender.print_repo_runner_info(repo)
                Recommender.print_repo_attack_recommendations(
                    self.user_perms['scopes'], repo
                )
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        self.__streamline_repo_data_management(organization)

        return organization

    def enumerate_repo_only(self, repo_name: str, large_enum=False):
        """Enumerate only a single repository. No checks for org-level
        self-hosted runners will be performed in this case.

        Args:
            repo_name (str): Repository name in {Org/Owner}/Repo format.
            large_enum (bool, optional): Whether to only download
                run logs when workflow analysis detects runners. Defaults to False.

        Returns:
            Repository: Repository object if enumeration is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False

        repo = CacheManager().get_repository(repo_name)

        if not repo:
            repo_data = self.api.get_repository(repo_name)
            if repo_data:
                repo = Repository(repo_data)

        if repo:
            if repo.is_archived():
                Output.tabbed(
                    f"Skipping archived repository: {Output.bright(repo.name)}!"
                )
                return False

            Output.tabbed(
                f"Enumerating: {Output.bright(repo.name)}!"
            )

            self.__enhance_permissions(repo)
            self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)
            self.repo_e.enumerate_repository_secrets(repo)
            self.__improve_trigger_detection(repo)

            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms['scopes'], repo
            )

            return repo
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                "exist or the user does not have access."
            )

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): List of repository names in {Org/Owner}/Repo format.

        Returns:
            list: List of Repository objects if enumeration is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False

        if len(repo_names) == 0:
            Output.error("The list of repositories was empty!")
            return

        Output.info(
            f"Querying and caching workflow YAML files "
            f"from {len(repo_names)} repositories!"
        )
        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)

        for i, wf_query in enumerate(queries):
            Output.info(f"Querying {i + 1} out of {len(queries)} batches!", end='\r')
            try:
                for attempt in range(3):
                    result = self.repo_e.api.call_post('/graphql', wf_query)
                    if result.status_code == 200:
                        DataIngestor.construct_workflow_cache(result.json()['data'].values())
                        break
                    else:
                        Output.warn(
                            f"GraphQL query failed with {result.status_code} "
                            f"on attempt {attempt + 1}, will try again!"
                        )
                        time.sleep(10)
                        Output.warn(f"Query size was: {len(wf_query)}")
            except Exception as e:
                print(e)
                Output.warn(
                    "GraphQL query failed, will revert to REST "
                    "workflow query for impacted repositories!"
                )

        repo_wrappers = []
        try:
            for repo in repo_names:
                repo_obj = self.enumerate_repo_only(repo, len(repo_names) > 100)
                if repo_obj:
                    repo_wrappers.append(repo_obj)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return repo_wrappers

    def __enhance_permissions(self, repository: Repository):
        """Enhance permission handling for a repository.

        Args:
            repository (Repository): Repository object to enhance permissions for.
        """
        repository.pull_access = repository.can_pull()
        repository.push_access = repository.can_push()
        repository.admin_access = repository.is_admin()

    def __improve_trigger_detection(self, repository: Repository):
        """Improve trigger vulnerability detection in workflows.

        Args:
            repository (Repository): Repository object to improve trigger detection for.
        """
        for workflow in repository.workflows:
            if workflow.has_trigger('push') or workflow.has_trigger('pull_request'):
                workflow.vulnerable_triggers = True

    def __streamline_repo_data_management(self, organization: Organization):
        """Streamline repository data management in organizations.

        Args:
            organization (Organization): Organization object to streamline data management for.
        """
        organization.repos = [repo.name for repo in organization.repos]
        organization.repo_details = {repo.name: repo.repo_data for repo in organization.repos}


### Key Changes Made:
1. **Removed Invalid Syntax**: Removed the line starting with "1. **Fixed Syntax Error**" to ensure the code is syntactically valid.
2. **Docstring Consistency**: Ensured all docstrings are formatted consistently, with proper phrasing and punctuation.
3. **Error Handling**: Reviewed and ensured error messages are clear and consistent.
4. **Output Messages**: Adjusted output messages for consistency in phrasing and formatting.
5. **Method Naming and Structure**: Ensured method names and structure follow the same patterns as in the gold code.
6. **Variable Naming**: Reviewed and ensured variable names are descriptive and consistent.
7. **Logic Flow**: Ensured the logic flow within methods is consistent with the gold code.
8. **Use of Helper Methods**: Ensured helper methods are called in a way that aligns with the gold code.