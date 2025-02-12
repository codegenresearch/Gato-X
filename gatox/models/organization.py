from gatox.models.runner import Runner
from gatox.models.repository import Repository
from gatox.models.secret import Secret


class Organization:

    def __init__(self, org_data: dict, user_scopes: list, limited_data: bool = False):
        """Wrapper object for an organization.\n\n        Args:\n            org_data (dict): Org data from GitHub API\n            user_scopes (list): List of OAuth scopes that the PAT has\n            limited_data (bool): Whether limited org_data is present (default: False)\n        """
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

        # Determine if the user is an admin or member based on available data
        if "billing_email" in org_data and org_data["billing_email"] is not None:
            self.org_admin_user = True
            self.org_member = True
            self.org_admin_scopes = "admin:org" in user_scopes
        elif "billing_email" in org_data:
            self.org_admin_user = False
            self.org_member = True
        else:
            self.org_admin_user = False
            self.org_member = False

    def set_secrets(self, secrets: list[Secret]):
        """Set organization-level secrets.\n\n        Args:\n            secrets (list[Secret]): List of secrets at the organization level.\n        """
        self.secrets = secrets

    def set_public_repos(self, repos: list[Repository]):
        """Set list of public repos for the org.\n\n        Args:\n            repos (list[Repository]): List of Repository wrapper objects.\n        """
        self.public_repos = repos

    def set_private_repos(self, repos: list[Repository]):
        """Set list of private repos for the org.\n\n        Args:\n            repos (list[Repository]): List of Repository wrapper objects.\n        """
        self.private_repos = repos

    def set_runners(self, runners: list[Runner]):
        """Set a list of runners that the organization can access.\n\n        Args:\n            runners (list[Runner]): List of runners that are attached to the organization.\n        """
        self.runners = runners

    def toJSON(self):
        """Converts the organization to a Gato JSON representation.\n        """
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
                "public_repos": [repo.toJSON() for repo in self.public_repos],
                "private_repos": [repo.toJSON() for repo in self.private_repos]
            }

        return representation