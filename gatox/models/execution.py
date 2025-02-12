import datetime

from gatox.models.organization import Organization
from gatox.models.repository import Repository


class Execution:
    """Simple wrapper class to provide accessor methods against a full Gato execution run."""

    def __init__(self):
        """Initialize wrapper class."""
        self.user_details = None
        self.organizations: list[Organization] = []
        self.repositories: list[Repository] = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations: list[Organization]):
        """Add list of organization wrapper objects.\n\n        Args:\n            organizations (List[Organization]): List of org wrappers.\n        """
        if not organizations:
            raise ValueError("The list of organizations cannot be empty.")
        self.organizations = organizations

    def add_repositories(self, repositories: list[Repository]):
        """Add list of repository wrapper objects.\n\n        Args:\n            repositories (List[Repository]): List of repo wrappers.\n        """
        if not repositories:
            raise ValueError("The list of repositories cannot be empty.")
        self.repositories = repositories

    def set_user_details(self, user_details: dict):
        """Set user details.\n\n        Args:\n            user_details (dict): Details about the user's permissions.\n        """
        if not user_details:
            raise ValueError("User details cannot be empty.")
        self.user_details = user_details

    def toJSON(self):
        """Converts the run to Gato JSON representation.\n\n        Returns:\n            dict: JSON representation of the execution run.\n        """
        if not self.user_details:
            return {}

        representation = {
            "username": self.user_details["user"],
            "scopes": self.user_details["scopes"],
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [
                    organization.toJSON() for organization in self.organizations
                ],
                "repositories": [
                    repository.toJSON() for repository in self.repositories
                ],
            },
        }

        return representation