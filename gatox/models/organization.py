from gatox.models.runner import Runner
from gatox.models.repository import Repository
from gatox.models.secret import Secret


class Organization():

    def __init__(self, org_data: dict, user_scopes: list, limited_data: bool = False):
        """Wrapper object for an organization.

        Args:
            org_data (dict): Org data from GitHub API
            user_scopes (list): List of OAuth scopes that the PAT has
            limited_data (bool): Whether limited org_data is present (default: False)
        """
        self.name = None
        self.org_admin_user = False
        self.org_admin_scopes = False
        self.org_member = False
        self.secrets: list[Secret] = []
        self.runners: list[Runner] = []
        self.sso_enabled = False
        self.limited_data = limited_data
        self.public_repos = []
        self.private_repos = []

        self.name = org_data['login']

        # Determine if the user is an admin or member based on billing_email
        if "billing_email" in org_data and org_data["billing_email"] is not None:
            self.org_member = True
            if "admin:org" in user_scopes:
                self.org_admin_scopes = True
                self.org_admin_user = True
        elif "billing_email" in org_data:
            self.org_member = True
        # If billing_email is not present, the user is neither an admin nor a member
        else:
            self.org_member = False

    def set_secrets(self, secrets: list[Secret]):
        """Set repo-level secrets.

        Args:
            secrets (list[Secret]): List of secrets at the organization level.
        """
        self.secrets = secrets

    def set_repository(self, repo: Repository):
        """Add a single repository object to the organization.

        Args:
            repo (Repository): Repository wrapper object to add.
        """
        if repo.is_private():
            self.private_repos.append(repo)
        else:
            self.public_repos.append(repo)

    def set_public_repos(self, repos: list[Repository]):
        """Set the list of public repository objects for the org.

        Args:
            repos (list[Repository]): List of Repository wrapper objects.
        """
        self.public_repos = repos

    def set_private_repos(self, repos: list[Repository]):
        """Set the list of private repository objects for the org.

        Args:
            repos (list[Repository]): List of Repository wrapper objects.
        """
        self.private_repos = repos

    def set_runners(self, runners: list[Runner]):
        """Set a list of runners that the organization can access.

        Args:
            runners (list[Runner]): List of runners that are attached to the organization.
        """
        self.runners = runners

    def can_access_repo(self, repo: Repository) -> bool:
        """Check if the user can access the repository based on its visibility.

        Args:
            repo (Repository): Repository to check access for.

        Returns:
            bool: True if the user can access the repository, False otherwise.
        """
        if repo.is_public():
            return True
        elif repo.is_private() and self.org_member:
            return True
        return False

    def toJSON(self):
        """Converts the organization to a Gato JSON representation.

        Returns:
            dict: JSON representation of the organization.
        """
        if self.limited_data:
            representation = {
                "name": self.name
            }
        else:
            representation = {
                "name": self.name,
                "org_admin_user": self.org_admin_user,
                "org_member": self.org_member,
                "org_runners": [runner.toJSON() for runner in self.runners],
                "org_secrets": [secret.toJSON() for secret in self.secrets],
                "sso_access": self.sso_enabled,
                "public_repos": [
                    repository.toJSON() for repository in self.public_repos
                ],
                "private_repos": [
                    repository.toJSON() for repository in self.private_repos
                ]
            }

        return representation