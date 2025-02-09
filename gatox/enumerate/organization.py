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
        """Simple init method.

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
        return [Repository(repo, visibility=visibility) for repo in raw_repos]

    def construct_repo_enum_list(
            self, organization: Organization) -> List[Repository]:
        """Constructs a list of repositories that a user has access to within
        an organization.

        Args:
            organization (Organization): Organization wrapper object.

        Returns:
            List[Repository]: List of repositories to enumerate.
        """
        visibilities = ['private', 'internal', 'public']
        all_repos = []

        for visibility in visibilities:
            all_repos.extend(self.__assemble_repo_list(organization.name, visibility))

        org_private_repos = [repo for repo in all_repos if repo.visibility in ['private', 'internal']]
        org_public_repos = [repo for repo in all_repos if repo.visibility == 'public']

        # We might legitimately have no private repos despite being a member.
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
1. **Repository Initialization**: Modified the `__assemble_repo_list` method to pass the `visibility` attribute to the `Repository` constructor.
2. **Docstring Consistency**: Ensured consistent wording and formatting in docstrings.
3. **Variable Naming**: Used consistent naming conventions for variables.
4. **Comment Clarity**: Improved comments for clarity.
5. **Code Structure**: Refactored the `construct_repo_enum_list` method for better clarity and maintainability.