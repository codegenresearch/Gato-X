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
            self, organization: str, visibilities: list) -> List[Repository]:
        """Get a list of repositories with the specified visibility types.

        Args:
            organization (str): Name of the organization.
            visibilities (list): List of visibility types (public, private, internal).

        Returns:
            List[Repository]: List of repositories with the specified visibility types.
        """
        repos = []
        for visibility in visibilities:
            raw_repos = self.api.check_org_repos(organization, visibility)
            if raw_repos:
                repos.extend([Repository(repo) for repo in raw_repos])
        return repos

    def construct_repo_enum_list(
            self, organization: Organization) -> List[Repository]:
        """Constructs a list of repositories that a user has access to within
        an organization.

        Args:
            organization (Organization): Organization wrapper object.

        Returns:
            List[Repository]: List of repositories to enumerate.
        """
        org_private_repos = self.__assemble_repo_list(
            organization.name, ['private', 'internal']
        )

        # Check SSO if there are private repositories
        if org_private_repos:
            sso_enabled = self.api.validate_sso(
                organization.name, org_private_repos[0].name
            )
            organization.sso_enabled = sso_enabled
        else:
            org_private_repos = []

        org_public_repos = self.__assemble_repo_list(
            organization.name, ['public']
        )

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
1. **Removed Unterminated String Literal**: Ensured there are no unterminated string literals or comments mistakenly included as code.
2. **Class Definition**: Removed unnecessary parentheses from the class definition.
3. **Docstring Consistency**: Ensured docstrings are consistent in terminology and clarity.
4. **Visibility Parameter Type**: Changed the type hint for `visibilities` to `list` to match the gold code's style.
5. **Repository Assembly Logic**: Ensured the logic for assembling private and public repositories is clear and follows the same order as in the gold code.
6. **Comment Clarity**: Reviewed and ensured comments are clear and consistent with the gold code.
7. **Formatting and Indentation**: Reviewed and adjusted formatting and indentation for consistency.
8. **Variable Naming**: Ensured variable names are consistent with the gold code's style.

This should address the feedback and ensure the code is more aligned with the gold code.