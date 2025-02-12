from typing import List
from multiprocessing import Process

from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.models.secret import Secret
from gatox.models.runner import Runner
from gatox.github.api import Api


class OrganizationEnum:
    """Helper class to wrap organization specific enumeration functionality.\n    """

    def __init__(self, api: Api):
        """Simple init method.\n\n        Args:\n            api (Api): Instantiated GitHub API wrapper object.\n        """
        self.api = api

    def _assemble_repo_list(self, organization: str, visibilities: List[str]) -> List[Repository]:
        """Get a list of repositories that match the visibility types.\n\n        Args:\n            organization (str): Name of the organization.\n            visibilities (List[str]): List of visibilities (public, private, etc.)\n\n        Returns:\n            List[Repository]: List of Repository objects.\n        """
        repos = []
        for visibility in visibilities:
            raw_repos = self.api.check_org_repos(organization, visibility)
            if raw_repos:
                repos.extend([Repository(repo) for repo in raw_repos])

        return repos

    def construct_repo_enum_list(self, organization: Organization) -> List[Repository]:
        """Constructs a list of repositories that a user has access to within an organization.\n\n        Args:\n            organization (Organization): Organization wrapper object.\n\n        Returns:\n            List[Repository]: List of repositories to enumerate.\n        """
        org_private_repos = self._assemble_repo_list(organization.name, ['private', 'internal'])
        org_public_repos = self._assemble_repo_list(organization.name, ['public'])

        organization.set_public_repos(org_public_repos)
        organization.set_private_repos(org_private_repos)

        if org_private_repos:
            sso_enabled = self.api.validate_sso(organization.name, org_private_repos[0].name)
            organization.sso_enabled = sso_enabled

        return org_private_repos + org_public_repos if organization.sso_enabled else org_public_repos

    def admin_enum(self, organization: Organization):
        """Enumeration tasks to perform if the user is an org admin and the token has the necessary scopes.\n\n        Args:\n            organization (Organization): Organization wrapper object.\n        """
        if not organization.org_admin_scopes or not organization.org_admin_user:
            return

        # Optimize GraphQL query by fetching runners and secrets in a single request if possible
        org_runners_data = self.api.check_org_runners(organization.name)
        org_secrets_data = self.api.get_org_secrets(organization.name)

        if org_runners_data and 'runners' in org_runners_data:
            org_runners = [
                Runner(
                    name=runner['name'],
                    machine_name=None,
                    os=runner['os'],
                    status=runner['status'],
                    labels=[label['name'] for label in runner['labels']]
                )
                for runner in org_runners_data['runners']
            ]
            organization.set_runners(org_runners)

        if org_secrets_data:
            org_secrets = [Secret(secret, organization.name) for secret in org_secrets_data]
            organization.set_secrets(org_secrets)