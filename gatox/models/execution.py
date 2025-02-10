import datetime

from gatox.models.organization import Organization, Repository


class Execution:
    """A wrapper class to provide accessor methods for a full Gato execution run."""

    def __init__(self):
        """Initialize the wrapper class with default values."""
        self.user_details = None
        self.organizations: list[Organization] = []
        self.repositories: list[Repository] = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations: list[Organization]):
        """Add a list of organization wrapper objects.

        Args:
            organizations (list[Organization]): List of organization wrappers.
        """
        if not all(isinstance(org, Organization) for org in organizations):
            raise ValueError("All items in the organizations list must be Organization instances.")
        self.organizations = organizations

    def add_repositories(self, repositories: list[Repository]):
        """Add a list of repository wrapper objects.

        Args:
            repositories (list[Repository]): List of repository wrappers.
        """
        if not all(isinstance(repo, Repository) for repo in repositories):
            raise ValueError("All items in the repositories list must be Repository instances.")
        self.repositories = repositories

    def set_user_details(self, user_details: dict):
        """Set the user details.

        Args:
            user_details (dict): Details about the user's permissions.
        """
        if not isinstance(user_details, dict):
            raise ValueError("User details must be provided as a dictionary.")
        self.user_details = user_details

    def to_json(self):
        """Convert the execution run to a Gato JSON representation.

        Returns:
            dict: JSON representation of the execution run.
        """
        if not self.user_details:
            raise ValueError("User details must be set before converting to JSON.")

        return {
            "username": self.user_details.get("user", "unknown"),
            "scopes": self.user_details.get("scopes", []),
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [org.to_json() for org in self.organizations],
                "repositories": [repo.to_json() for repo in self.repositories],
            },
        }