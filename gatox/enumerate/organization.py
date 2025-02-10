from typing import List
from multiprocessing import Process

from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.models.secret import Secret
from gatox.models.runner import Runner
from gatox.github.api import Api


class OrganizationEnum:
    """Helper class to wrap organization-specific enumeration functionality.
    """

    def __init__(self, api: Api):
        """Initialize the OrganizationEnum with a GitHub API wrapper object.

        Args:
            api (Api): Instantiated GitHub API wrapper object.
        """
        self.api = api

    def __assemble_repo_list(
            self, organization: str, visibility: str) -> List[Repository]:
        """Get a list of repositories with the specified visibility.

        Args:
            organization (str): Name of the organization.
            visibility (str): Visibility type (public, private, internal).

        Returns:
            List[Repository]: List of repositories with the specified visibility.
        """
        raw_repos = self.api.check_org_repos(organization, visibility)
        return [Repository(repo) for repo in raw_repos] if raw_repos else []

    def construct_repo_enum_list(
            self, organization: Organization) -> List[Repository]:
        """Constructs a list of repositories that a user has access to within
        an organization.

        Args:
            organization (Organization): Organization wrapper object.

        Returns:
            List[Repository]: List of repositories to enumerate.
        """
        org_private_repos = self.__assemble_repo_list(organization.name, 'private')
        org_internal_repos = self.__assemble_repo_list(organization.name, 'internal')
        org_public_repos = self.__assemble_repo_list(organization.name, 'public')

        # Combine private and internal repositories
        org_private_repos.extend(org_internal_repos)

        # Check SSO if there are private repositories
        if org_private_repos:
            sso_enabled = self.api.validate_sso(
                organization.name, org_private_repos[0].name
            )
            organization.sso_enabled = sso_enabled
        else:
            org_private_repos = []

        organization.set_public_repos(org_public_repos)
        organization.set_private_repos(org_private_repos)

        if organization.sso_enabled:
            return org_private_repos + org_public_repos
        else:
            return org_public_repos

    def admin_enum(self, organization: Organization):
        """Enumeration tasks to perform if the user is an org admin and the
        token has the necessary scopes.
        """
        if organization.org_admin_scopes and organization.org_admin_user:
            runners = self.api.check_org_runners(organization.name)
            if runners:
                org_runners = [
                    Runner(
                        runner['name'],
                        machine_name=None,
                        os=runner['os'],
                        status=runner['status'],
                        labels=runner['labels']
                    )
                    for runner in runners['runners']
                ]
                organization.set_runners(org_runners)

            org_secrets = self.api.get_org_secrets(organization.name)
            if org_secrets:
                org_secrets = [
                    Secret(secret, organization.name) for secret in org_secrets
                ]
                organization.set_secrets(org_secrets)


### Key Changes:
1. **Visibility Handling**: Separated the assembly of private and internal repositories and combined them into `org_private_repos`.
2. **Repository Assembly**: Modified `__assemble_repo_list` to accept a single visibility type and return a list of repositories.
3. **SSO Handling**: Ensured `org_private_repos` is initialized to an empty list if there are no private repositories.
4. **Runner Initialization**: Removed the `permissions` argument from the `Runner` initialization to match the expected parameters.
5. **Code Formatting**: Adjusted formatting for consistency and readability.