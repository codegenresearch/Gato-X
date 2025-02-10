import datetime

from gatox.models.organization import Organization
from gatox.models.repository import Repository


class Execution:
    """A wrapper class to provide accessor methods for a full Gato execution run."""

    def __init__(self):
        """Initialize the wrapper class with default values."""
        self.user_details = None
        self.organizations = []
        self.repositories = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations):
        """Add a list of organization wrapper objects."""
        self.organizations = organizations

    def add_repositories(self, repositories):
        """Add a list of repository wrapper objects."""
        self.repositories = repositories

    def set_user_details(self, user_details):
        """Set the user details."""
        self.user_details = user_details

    def toJSON(self):
        """Convert the execution run to a Gato JSON representation."""
        representation = {
            "username": self.user_details["user"],
            "scopes": self.user_details["scopes"],
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [org.toJSON() for org in self.organizations],
                "repositories": [repo.toJSON() for repo in self.repositories],
            },
        }

        return representation