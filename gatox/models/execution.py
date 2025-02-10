import datetime

from gatox.models.organization import Organization
from gatox.models.repository import Repository


class Execution:
    """Wrapper class to provide accessor methods for a full Gato execution run."""

    def __init__(self):
        """Initialize the wrapper class with default values."""
        self.user_details = None
        self.organizations = []
        self.repositories = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations):
        """Add a list of organization wrapper objects.

        Args:
            organizations (list[Organization]): List of organization wrappers.
        """
        self.organizations = organizations

    def add_repositories(self, repositories):
        """Add a list of repository wrapper objects.

        Args:
            repositories (list[Repository]): List of repository wrappers.
        """
        self.repositories = repositories

    def set_user_details(self, user_details):
        """Set the user details.

        Args:
            user_details (dict): Details about the user's permissions.
        """
        self.user_details = user_details

    def toJSON(self):
        """Convert the execution run to a Gato JSON representation.

        Returns:
            dict: JSON representation of the execution run.
        """
        if not self.user_details:
            raise ValueError("User details must be set before converting to JSON.")

        return {
            "username": self.user_details["user"],
            "scopes": self.user_details["scopes"],
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [org.toJSON() for org in self.organizations],
                "repositories": [repo.toJSON() for repo in self.repositories],
            },
        }