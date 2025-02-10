import datetime
from typing import List, Optional

from gatox.models.organization import Organization
from gatox.models.repository import Repository


class Execution:
    """A wrapper class to provide accessor methods for a full Gato execution run."""

    def __init__(self):
        """Initialize the wrapper class with default values."""
        self.user_details: Optional[dict] = None
        self.organizations: List[Organization] = []
        self.repositories: List[Repository] = []
        self.timestamp: datetime.datetime = datetime.datetime.now()

    def add_organizations(self, organizations: List[Organization]):
        """Add a list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of organization wrappers.
        """
        if not organizations:
            raise ValueError("The list of organizations cannot be empty.")
        self.organizations = organizations

    def add_repositories(self, repositories: List[Repository]):
        """Add a list of repository wrapper objects.

        Args:
            repositories (List[Repository]): List of repository wrappers.
        """
        if not repositories:
            raise ValueError("The list of repositories cannot be empty.")
        self.repositories = repositories

    def set_user_details(self, user_details: dict):
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
        if self.user_details is None:
            raise ValueError("User details must be set before converting to JSON.")

        return {
            "username": self.user_details["user"],
            "scopes": self.user_details["scopes"],
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [organization.toJSON() for organization in self.organizations],
                "repositories": [repository.toJSON() for repository in self.repositories],
            },
        }