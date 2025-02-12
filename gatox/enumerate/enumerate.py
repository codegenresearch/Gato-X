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
    """Class holding all high level logic for enumerating GitHub, whether it is\n    a user's entire access, individual organizations, or repositories.\n    """

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
        """Initialize enumeration class with arguments sent by user.\n\n        Args:\n            pat (str): GitHub personal access token\n            socks_proxy (str, optional): Proxy settings for SOCKS proxy.\n            Defaults to None.\n            http_proxy (str, optional): Proxy gettings for HTTP proxy.\n            Defaults to None.\n            output_yaml (str, optional): If set, directory to save all yml\n            files to . Defaults to None.\n            skip_log (bool, optional): If set, then run logs will not be\n            downloaded.\n            output_json (str, optional): JSON file to output enumeration\n            results.\n        """
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
            if len(self.user_perms["scopes"]):
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    def validate_only(self):
        """Validates the PAT access and exits.\n        """
        if not self.__setup_user_info():
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [Organization({'login': org, 'allow_forking': True}, self.user_perms['scopes'], True) for org in orgs]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.\n\n        Returns:\n            bool: False if the PAT is not valid for enumeration.\n        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = list(map(self.enumerate_organization, orgs))

        return org_wrappers

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization, and check everything relevant to\n        self-hosted runner abuse that that the user has permissions to check.\n\n        Args:\n            org (str): Organization to perform enumeration on.\n\n        Returns:\n            bool: False if a failure occurred enumerating the organization.\n        """

        if not self.__setup_user_info():
            return False

        details = self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!"
            )
            return False

        organization = Organization({**details, 'allow_forking': True}, self.user_perms['scopes'])

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
            Output.info(f"Querying {i} out of {len(wf_queries)} batches!", end='\r')
            result = self.org_e.api.call_post('/graphql', wf_query)
            # Sometimes we don't get a 200, fall back in this case.\n            if result.status_code == 200:\n                DataIngestor.construct_workflow_cache(result.json()['data']['nodes'])\n            else:\n                Output.warn(\n                    "GraphQL query failed, will revert to "\n                    "REST workflow query for impacted repositories!"\n                )\n        try:\n            for repo in enum_list:\n                if repo.is_archived():\n                    continue\n                if self.skip_log and repo.is_fork():\n                    continue\n                Output.tabbed(\n                    f"Enumerating: {Output.bright(repo.name)}!"\n                )\n\n                cached_repo = CacheManager().get_repository(repo.name)\n                if cached_repo:\n                    repo = cached_repo\n                \n                self.repo_e.enumerate_repository(repo, large_org_enum=len(enum_list) > 25)\n                self.repo_e.enumerate_repository_secrets(repo)\n\n                Recommender.print_repo_secrets(\n                    self.user_perms['scopes'],\n                    repo.secrets\n                )\n                Recommender.print_repo_runner_info(repo)\n                Recommender.print_repo_attack_recommendations(\n                    self.user_perms['scopes'], repo\n                )\n        except KeyboardInterrupt:\n            Output.warn("Keyboard interrupt detected, exiting enumeration!")\n\n        return organization\n\n    def enumerate_repo_only(self, repo_name: str, large_enum=False):\n        """Enumerate only a single repository. No checks for org-level\n        self-hosted runners will be performed in this case.\n\n        Args:\n            repo_name (str): Repository name in {Org/Owner}/Repo format.\n            large_enum (bool, optional): Whether to only download\n            run logs when workflow analysis detects runners. Defaults to False.\n        """\n        if not self.__setup_user_info():\n            return False\n\n        repo = CacheManager().get_repository(repo_name)\n\n        if not repo:\n            repo_data = self.api.get_repository(repo_name)\n            if repo_data:\n                repo = Repository({**repo_data, 'allow_forking': repo_data.get('allow_forking', True)})\n\n        if repo:\n            if repo.is_archived():\n                Output.tabbed(\n                    f"Skipping archived repository: {Output.bright(repo.name)}!"\n                )\n                return False\n            \n            Output.tabbed(\n                    f"Enumerating: {Output.bright(repo.name)}!"\n            )\n            \n            self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)\n            self.repo_e.enumerate_repository_secrets(repo)\n            Recommender.print_repo_secrets(\n                self.user_perms['scopes'],\n                repo.secrets + repo.org_secrets\n            )\n            Recommender.print_repo_runner_info(repo)\n            Recommender.print_repo_attack_recommendations(\n                self.user_perms['scopes'], repo\n            )\n\n            return repo\n        else:\n            Output.warn(\n                f"Unable to enumerate {Output.bright(repo_name)}! It may not "\n                "exist or the user does not have access."\n            )\n\n    def enumerate_repos(self, repo_names: list):\n        """Enumerate a list of repositories, each repo must be in Org/Repo name\n        format.\n\n        Args:\n            repo_names (list): Repository name in {Org/Owner}/Repo format.\n        """\n        if not self.__setup_user_info():\n            return False\n\n        if len(repo_names) == 0:\n            Output.error("The list of repositories was empty!")\n            return\n\n        Output.info(\n            f"Querying and caching workflow YAML files "\n            f"from {len(repo_names)} repositories!"\n        )\n        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)\n\n        for i, wf_query in enumerate(queries):\n            Output.info(f"Querying {i} out of {len(queries)} batches!", end='\r')\n            try:\n                for i in range (0, 3):\n                    result = self.repo_e.api.call_post('/graphql', wf_query)\n                    if result.status_code == 200:\n                        DataIngestor.construct_workflow_cache(result.json()['data'].values())\n                        break\n                    else:\n                        Output.warn(\n                            f"GraphQL query failed with {result.status_code} "\n                            f"on attempt {str(i+1)}, will try again!")\n                        time.sleep(10)\n                        Output.warn(f"Query size was: {len(wf_query)}")\n            except Exception as e:\n                print(e)\n                Output.warn(\n                    "GraphQL query failed, will revert to REST "\n                    "workflow query for impacted repositories!"\n                )\n\n        repo_wrappers = []\n        try:\n            for repo in repo_names:\n\n                repo_obj = self.enumerate_repo_only(repo, len(repo_names) > 100)\n                if repo_obj:\n                    repo_wrappers.append(repo_obj)\n        except KeyboardInterrupt:\n            Output.warn("Keyboard interrupt detected, exiting enumeration!")\n\n        return repo_wrappers