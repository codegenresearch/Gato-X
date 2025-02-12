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
    """Class holding all high level logic for enumerating GitHub, whether it is\n    a user's entire access, individual organizations, or repositories.\n    """

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
        """Initialize enumeration class with arguments sent by user.\n\n        Args:\n            pat (str): GitHub personal access token\n            socks_proxy (str, optional): Proxy settings for SOCKS proxy.\n            Defaults to None.\n            http_proxy (str, optional): Proxy gettings for HTTP proxy.\n            Defaults to None.\n            output_yaml (str, optional): If set, directory to save all yml\n            files to . Defaults to None.\n            skip_log (bool, optional): If set, then run logs will not be\n            downloaded.\n            output_json (str, optional): JSON file to output enumeration\n            results.\n        """
        if not pat:
            raise ValueError("Personal Access Token (PAT) is required.")
        if output_yaml and not isinstance(output_yaml, str):
            raise ValueError("output_yaml must be a string representing a directory path.")
        if output_json and not isinstance(output_json, str):
            raise ValueError("output_json must be a string representing a file path.")

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
        """Sets up user/app token information."""
        if not self.user_perms and self.api.is_app_token():
            installation_info = self.api.get_installation_repos()

            if installation_info and installation_info["total_count"] > 0:
                Output.info(
                    f"Gato-X is using valid a GitHub App installation token!"
                )
                self.user_perms = {
                    "user": "Github App",
                    "scopes": [],
                    "name": "GATO-X App Mode",
                }
                return True
            else:
                return False

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

    def __query_graphql_workflows(self, queries):
        """Wrapper for querying workflows using the github graphql API.\n\n        Since this is an IO heavy operation, we use a threadpool with 3 workers.\n        """
        if not queries:
            Output.warn("No queries provided for GraphQL workflow querying.")
            return

        with ThreadPoolExecutor(max_workers=3) as executor:
            Output.info(f"Querying repositories in {len(queries)} batches!")
            futures = [executor.submit(DataIngestor.perform_query, self.api, query, i) for i, query in enumerate(queries)]
            for future in as_completed(futures):
                Output.info(
                    f"Processed {DataIngestor.check_status()}/{len(queries)} batches.",
                    end="\r",
                )
                DataIngestor.construct_workflow_cache(future.result())

    def validate_only(self):
        """Validates the PAT access and exits."""
        if not self.__setup_user_info():
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        if not orgs:
            Output.warn("No organizations found for the user.")
            return []

        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} '
            "organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [
            Organization({"login": org}, self.user_perms["scopes"], True)
            for org in orgs
        ]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.\n\n        Returns:\n            bool: False if the PAT is not valid for enumeration.\n        """

        if not self.__setup_user_info():
            return False

        if not self.user_perms:
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        Output.info("Enumerating user owned repositories!")

        repos = self.api.get_own_repos()
        repo_wrappers = self.enumerate_repos(repos)
        orgs = self.api.check_organizations()

        if not orgs:
            Output.warn("No organizations found for the user.")
            return [], repo_wrappers

        Output.info(
            f'The user {self.user_perms["user"]} belongs to {len(orgs)} '
            "organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = list(map(self.enumerate_organization, orgs))

        return org_wrappers, repo_wrappers

    def enumerate_user(self, user: str):
        """Enumerate a user's repositories."""
        if not user:
            Output.error("User name is required for enumeration.")
            return False

        if not self.__setup_user_info():
            return False

        repos = self.api.get_user_repos(user)

        if not repos:
            Output.warn(
                f"Unable to query the user: {Output.bright(user)}! Ensure the "
                "user exists!"
            )
            return False

        Output.result(f"Enumerating the {Output.bright(user)} user!")

        repo_wrappers = self.enumerate_repos(repos)

        return repo_wrappers

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization, and check everything relevant to\n        self-hosted runner abuse that that the user has permissions to check.\n\n        Args:\n            org (str): Organization to perform enumeration on.\n\n        Returns:\n            bool: False if a failure occurred enumerating the organization.\n        """
        if not org:
            Output.error("Organization name is required for enumeration.")
            return False

        if not self.__setup_user_info():
            return False

        details = self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!"
            )
            return False

        organization = Organization(details, self.user_perms["scopes"])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)

        Recommender.print_org_findings(self.user_perms["scopes"], organization)

        Output.info("Querying repository list!")
        enum_list = self.org_e.construct_repo_enum_list(organization)

        if not enum_list:
            Output.warn("No repositories found to enumerate in the organization.")
            return False

        Output.info(
            f"About to enumerate "
            f"{len(enum_list)} "
            "non-archived repos within "
            f"the {organization.name} organization!"
        )

        Output.info(f"Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)
        self.__query_graphql_workflows(wf_queries)

        try:
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if self.skip_log and repo.is_fork():
                    continue
                Output.tabbed(f"Enumerating: {Output.bright(repo.name)}!")

                cached_repo = CacheManager().get_repository(repo.name)
                if cached_repo:
                    repo = cached_repo

                self.repo_e.enumerate_repository(
                    repo, large_org_enum=len(enum_list) > 25
                )
                self.repo_e.enumerate_repository_secrets(repo)

                organization.set_repository(repo)

                Recommender.print_repo_secrets(self.user_perms["scopes"], repo.secrets)
                Recommender.print_repo_runner_info(repo)
                Recommender.print_repo_attack_recommendations(
                    self.user_perms["scopes"], repo
                )
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return organization

    def enumerate_repo_only(self, repo_name: str, large_enum=False):
        """Enumerate only a single repository. No checks for org-level\n        self-hosted runners will be performed in this case.\n\n        Args:\n            repo_name (str): Repository name in {Org/Owner}/Repo format.\n            large_enum (bool, optional): Whether to only download\n            run logs when workflow analysis detects runners. Defaults to False.\n        """
        if not repo_name:
            Output.error("Repository name is required for enumeration.")
            return False

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

            Output.tabbed(f"Enumerating: {Output.bright(repo.name)}!")

            self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)
            self.repo_e.enumerate_repository_secrets(repo)
            Recommender.print_repo_secrets(
                self.user_perms["scopes"], repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms["scopes"], repo
            )

            return repo
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                "exist or the user does not have access."
            )

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories, each repo must be in Org/Repo name\n        format.\n\n        Args:\n            repo_names (list): Repository name in {Org/Owner}/Repo format.\n        """
        if not repo_names:
            Output.error("The list of repositories was empty!")
            return

        if not self.__setup_user_info():
            return False

        Output.info(
            f"Querying and caching workflow YAML files "
            f"from {len(repo_names)} repositories!"
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