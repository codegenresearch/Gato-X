from gatox.models.runner import Runner
from gatox.models.repository import Repository
from gatox.models.secret import Secret


class Organization:

    def __init__(self, org_data: dict, user_scopes: list, limited_data: bool = False):
        """Wrapper object for an organization.

        Args:
            org_data (dict): Org data from GitHub API
            user_scopes (list): List of OAuth scopes that the PAT has
            limited_data (bool): Whether limited org_data is present (default: False)
        """
        self.name = org_data.get('login')
        self.org_admin_user = False
        self.org_admin_scopes = False
        self.org_member = False
        self.secrets = []
        self.runners = []
        self.sso_enabled = False
        self.limited_data = limited_data
        self.public_repos = []
        self.private_repos = []

        self._determine_user_role(org_data, user_scopes)

    def _determine_user_role(self, org_data: dict, user_scopes: list):
        """Determine the user's role within the organization based on the provided data and scopes."""
        self.org_member = "billing_email" in org_data
        if self.org_member and "admin:org" in user_scopes:
            self.org_admin_scopes = True
            self.org_admin_user = True

    def set_repository(self, repo: Repository):
        """Add a single repository to the organization based on its visibility.

        Args:
            repo (Repository): Repository wrapper object.
        """
        if repo.is_public():
            self.public_repos.append(repo)
        else:
            self.private_repos.append(repo)

    def set_secrets(self, secrets: list):
        """Set organization-level secrets.

        Args:
            secrets (list): List of secrets at the organization level.
        """
        self.secrets = secrets

    def set_public_repos(self, repos: list):
        """Set the list of public repositories for the organization.

        Args:
            repos (list): List of Repository wrapper objects.
        """
        self.public_repos = repos

    def set_private_repos(self, repos: list):
        """Set the list of private repositories for the organization.

        Args:
            repos (list): List of Repository wrapper objects.
        """
        self.private_repos = repos

    def set_runners(self, runners: list):
        """Set the list of runners that the organization can access.

        Args:
            runners (list): List of runners attached to the organization.
        """
        self.runners = runners

    def has_admin_scopes(self) -> bool:
        """Check if the user has admin scopes for the organization."""
        return self.org_admin_scopes

    def has_admin_role(self) -> bool:
        """Check if the user has an admin role in the organization."""
        return self.org_admin_user

    def is_member(self) -> bool:
        """Check if the user is a member of the organization."""
        return self.org_member

    def toJSON(self):
        """Converts the organization to a Gato JSON representation."""
        if self.limited_data:
            return {"name": self.name}

        representation = {
            "name": self.name,
            "org_admin_user": self.org_admin_user,
            "org_member": self.org_member,
            "org_runners": [runner.toJSON() for runner in self.runners],
            "org_secrets": [secret.toJSON() for secret in self.secrets],
            "sso_access": self.sso_enabled,
            "public_repos": [repo.toJSON() for repo in self.public_repos],
            "private_repos": [repo.toJSON() for repo in self.private_repos]
        }

        return representation