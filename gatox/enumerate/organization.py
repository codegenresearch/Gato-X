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
        """Initialize the OrganizationEnum with a GitHub API wrapper.

        Args:
            api (Api): Instantiated GitHub API wrapper object.
        """
        self.api = api

    def __assemble_repo_list(self, organization: str, visibilities: list) -> List[Repository]:
        """Retrieve a list of repositories that match the specified visibility types.

        Args:
            organization (str): Name of the organization.
            visibilities (list): List of visibility types (e.g., 'public', 'private', 'internal').

        Returns:
            List[Repository]: List of Repository objects.
        """
        repos = []
        for visibility in visibilities:
            raw_repos = self.api.check_org_repos(organization, visibility)
            if raw_repos:
                repos.extend([Repository(repo) for repo in raw_repos])

        return repos

    def construct_repo_enum_list(self, organization: Organization) -> List[Repository]:
        """Construct a list of repositories that a user has access to within an organization.

        Args:
            organization (Organization): Organization wrapper object.

        Returns:
            List[Repository]: List of repositories to enumerate.
        """
        org_private_repos = self.__assemble_repo_list(organization.name, ['private', 'internal'])

        # Determine SSO status if there are private repositories
        if org_private_repos:
            sso_enabled = self.api.validate_sso(organization.name, org_private_repos[0].name)
            organization.sso_enabled = sso_enabled

        org_public_repos = self.__assemble_repo_list(organization.name, ['public'])

        # Include forking allowance in repository data
        for repo in org_private_repos + org_public_repos:
            repo.forking_allowed = self.api.check_forking_allowed(repo.name)

        organization.set_public_repos(org_public_repos)
        organization.set_private_repos(org_private_repos)

        return org_private_repos + org_public_repos if organization.sso_enabled else org_public_repos

    def admin_enum(self, organization: Organization):
        """Perform enumeration tasks if the user is an org admin with the necessary scopes.

        Args:
            organization (Organization): Organization wrapper object.
        """
        if organization.org_admin_scopes and organization.org_admin_user:
            # Retrieve and set organization runners
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

            # Retrieve and set organization secrets
            org_secrets = self.api.get_org_secrets(organization.name)
            if org_secrets:
                org_secrets = [Secret(secret, organization.name) for secret in org_secrets]
                organization.set_secrets(org_secrets)


### Key Changes:
1. **Method Naming**: Changed `_assemble_repo_list` to `__assemble_repo_list` to indicate it is a private method.
2. **Docstring Consistency**: Simplified and standardized docstrings.
3. **Visibility List Handling**: Adjusted the order of operations to retrieve private repositories first and check SSO status before fetching public repositories.
4. **Return Statements**: Simplified the return logic.
5. **Formatting**: Ensured consistent formatting and indentation.
6. **Comment Clarity**: Made comments more concise and relevant.

### Note:
- The `Repository` class should have a `name` attribute that corresponds to the repository's name. If the `full_name` attribute is required, it should be added to the `Repository` class and used accordingly. In this snippet, I assumed `name` is the correct attribute based on the feedback. If `full_name` is necessary, replace `repo.name` with `repo.full_name` in the `check_forking_allowed` call.