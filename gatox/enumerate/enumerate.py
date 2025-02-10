import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    """Class holding all high level logic for enumerating GitHub, whether it is
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
        output_json: str = None,
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token.
            socks_proxy (str, optional): Proxy settings for SOCKS proxy. Defaults to None.
            http_proxy (str, optional): Proxy settings for HTTP proxy. Defaults to None.
            output_yaml (str, optional): Directory to save all yml files to. Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be downloaded. Defaults to False.
            github_url (str, optional): Custom GitHub URL. Defaults to None.
            output_json (str, optional): JSON file to output enumeration results. Defaults to None.
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
        self.github_url = github_url
        self.output_json = output_json
        self.user_perms = None

        self.repo_e = RepositoryEnum(self.api, skip_log, output_yaml)
        self.org_e = OrganizationEnum(self.api)

    def __setup_user_info(self):
        """Sets up user/app token information.

        Returns:
            bool: True if user info is successfully set, False otherwise.
        """
        if not self.user_perms:
            if self.api.is_app_token():
                installation_info = self.api.get_installation_repos()
                if installation_info and installation_info["total_count"] > 0:
                    Output.info("Gato-X is using a valid GitHub App installation token!")
                    self.user_perms = {
                        "user": "Github App",
                        "scopes": [],
                        "name": "GATO-X App Mode",
                    }
                    return True
                else:
                    Output.error("No repositories found for the GitHub App token!")
                    return False
            else:
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

    def __query_graphql_workflows(self, queries):
        """Wrapper for querying workflows using the GitHub GraphQL API.

        Args:
            queries (list): List of GraphQL queries to execute.

        This method uses a thread pool with 3 workers to perform the queries.
        """
        with ThreadPoolExecutor(max_workers=3) as executor:
            Output.info(f"Querying repositories in {len(queries)} batches!")
            futures = [executor.submit(DataIngestor.perform_query, self.api, q, i) for i, q in enumerate(queries)]
            for future in as_completed(futures):
                Output.info(
                    f"Processed {DataIngestor.check_status()}/{len(queries)} batches.",
                    end="\r",
                )
                DataIngestor.construct_workflow_cache(future.result())

    def validate_only(self):
        """Validates the PAT access and exits.

        Returns:
            list: List of organizations if validation is successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        if "repo" not in self.user_perms["scopes"]:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False
        orgs = self.api.check_organizations()
        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} organizations!'
        )
        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")
        return [Organization({"login": org}, self.user_perms["scopes"], True) for org in orgs]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            tuple: Tuple containing lists of organization and repository wrappers if successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        if "repo" not in self.user_perms["scopes"]:
            Output.error("Self-enumeration requires the repo scope!")
            return False
        Output.info("Enumerating user owned repositories!")
        repos = self.api.get_own_repos()
        repo_wrappers = self.enumerate_repos(repos)
        orgs = self.api.check_organizations()
        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} organizations!'
        )
        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")
        org_wrappers = list(map(self.enumerate_organization, orgs))
        return org_wrappers, repo_wrappers

    def enumerate_user(self, user: str):
        """Enumerate a user's repositories.

        Args:
            user (str): Username of the GitHub user to enumerate.

        Returns:
            list: List of repository wrappers if successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        repos = self.api.get_user_repos(user)
        if not repos:
            Output.warn(
                f"Unable to query the user: {Output.bright(user)}! Ensure the user exists!"
            )
            return False
        Output.result(f"Enumerating the {Output.bright(user)} user!")
        return self.enumerate_repos(repos)

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization.

        Args:
            org (str): Organization name to enumerate.

        Returns:
            Organization: Organization wrapper if successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        details = self.api.get_organization_details(org)
        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the organization exists!"
            )
            return False
        organization = Organization(details, self.user_perms["scopes"])
        Output.result(f"Enumerating the {Output.bright(org)} organization!")
        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)
        Recommender.print_org_findings(self.user_perms["scopes"], organization)
        Output.info("Querying repository list!")
        enum_list = self.org_e.construct_repo_enum_list(organization)
        Output.info(
            f"About to enumerate {len(enum_list)} non-archived repos within the {organization.name} organization!"
        )
        Output.info("Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)
        self.__query_graphql_workflows(wf_queries)
        try:
            for repo in enum_list:
                if repo.is_archived() or (self.skip_log and repo.is_fork()):
                    continue
                Output.tabbed(f"Enumerating: {Output.bright(repo.name)}!")
                repo = CacheManager().get_repository(repo.name) or repo
                self.repo_e.enumerate_repository(repo, large_org_enum=len(enum_list) > 25)
                self.repo_e.enumerate_repository_secrets(repo)
                organization.set_repository(repo)
                Recommender.print_repo_secrets(self.user_perms["scopes"], repo.secrets)
                Recommender.print_repo_runner_info(repo)
                Recommender.print_repo_attack_recommendations(self.user_perms["scopes"], repo)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")
        return organization

    def enumerate_repo_only(self, repo_name: str, large_enum=False):
        """Enumerate only a single repository.

        Args:
            repo_name (str): Repository name in {Org/Owner}/Repo format.
            large_enum (bool, optional): Whether to only download run logs when workflow analysis detects runners. Defaults to False.

        Returns:
            Repository: Repository wrapper if successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        repo = CacheManager().get_repository(repo_name) or Repository(self.api.get_repository(repo_name))
        if not repo:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not exist or the user does not have access."
            )
            return False
        if repo.is_archived():
            Output.tabbed(f"Skipping archived repository: {Output.bright(repo.name)}!")
            return False
        Output.tabbed(f"Enumerating: {Output.bright(repo.name)}!")
        self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)
        self.repo_e.enumerate_repository_secrets(repo)
        Recommender.print_repo_secrets(
            self.user_perms["scopes"], repo.secrets + repo.org_secrets
        )
        Recommender.print_repo_runner_info(repo)
        Recommender.print_repo_attack_recommendations(self.user_perms["scopes"], repo)
        return repo

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories.

        Args:
            repo_names (list): List of repository names in {Org/Owner}/Repo format.

        Returns:
            list: List of repository wrappers if successful, False otherwise.
        """
        if not self.__setup_user_info():
            return False
        if not repo_names:
            Output.error("The list of repositories was empty!")
            return False
        Output.info(
            f"Querying and caching workflow YAML files from {len(repo_names)} repositories!"
        )
        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)
        self.__query_graphql_workflows(queries)
        repo_wrappers = []
        try:
            for repo in repo_names:
                repo_obj = self.enumerate_repo_only(repo, len(repo_names) > 100)
                if repo_obj:
                    repo_wrappers.append(repo_obj)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")
        return repo_wrappers