import datetime

from gatox.models.organization import Organization, Repository


class Execution:
    """A wrapper class to provide accessor methods for a full Gato execution run."""

    def __init__(self):
        """Initialize the wrapper class with empty lists for organizations and repositories."""
        self.user_details = None
        self.organizations: list[Organization] = []
        self.repositories: list[Repository] = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations: list[Organization]):
        """Add a list of organization wrapper objects.\n\n        Args:\n            organizations (list[Organization]): List of organization wrappers.\n        """
        if not all(isinstance(org, Organization) for org in organizations):
            raise ValueError("All items must be instances of Organization.")
        self.organizations = organizations

    def add_repositories(self, repositories: list[Repository]):
        """Add a list of repository wrapper objects.\n\n        Args:\n            repositories (list[Repository]): List of repository wrappers.\n        """
        if not all(isinstance(repo, Repository) for repo in repositories):
            raise ValueError("All items must be instances of Repository.")
        self.repositories = repositories

    def set_user_details(self, user_details: dict):
        """Set the user details.\n\n        Args:\n            user_details (dict): A dictionary containing user details, including username and scopes.\n        """
        if not isinstance(user_details, dict):
            raise TypeError("User details must be a dictionary.")
        required_keys = {"user", "scopes"}
        if not required_keys.issubset(user_details.keys()):
            raise ValueError("User details must contain 'user' and 'scopes'.")
        self.user_details = user_details

    def to_json(self):
        """Convert the execution run to a Gato JSON representation.\n\n        Returns:\n            dict: A dictionary representing the execution run in JSON format.\n        """
        if not self.user_details:
            raise ValueError("User details must be set before converting to JSON.")

        return {
            "username": self.user_details["user"],
            "scopes": self.user_details["scopes"],
            "enumeration": {
                "timestamp": self.timestamp.ctime(),
                "organizations": [org.to_json() for org in self.organizations],
                "repositories": [repo.to_json() for repo in self.repositories],
            },
        }