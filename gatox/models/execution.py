import datetime

from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.enumerate.repository import RepositoryEnum
from gatox.github.api import Api
import logging

logger = logging.getLogger(__name__)

class Execution:
    """Simple wrapper class to provide accessor methods against a full Gato
    execution run.
    """

    def __init__(self):
        """Initialize wrapper class."""
        self.user_details = None
        self.organizations: list[Organization] = []
        self.repositories: list[Repository] = []
        self.timestamp = datetime.datetime.now()
        self.api = Api()  # Assuming Api is needed for enumeration

    def add_organizations(self, organizations: list[Organization]):
        """Add list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of org wrappers.
        """
        self.organizations = organizations

    def add_repositories(self, repositories: list[Repository]):
        """Add list of repository wrapper objects.

        Args:
            repositories (List[Repository]): List of repo wrappers.
        """
        self.repositories = repositories

    def set_user_details(self, user_details):
        """Set user details.

        Args:
            user_details (dict): Details about the user's permissions.
        """
        self.user_details = user_details

    def enumerate_repositories(self):
        """Enumerate all repositories for vulnerabilities and self-hosted runners."""
        if not self.repositories:
            logger.warning("No repositories to enumerate.")
            return []

        repo_enum = RepositoryEnum(self.api, skip_log=False, output_yaml=False)
        results = []

        for repo in self.repositories:
            try:
                repo_enum.enumerate_repository(repo)
                results.append(repo.toJSON())
            except Exception as e:
                logger.error(f"Error enumerating repository {repo.name}: {str(e)}")
                results.append({"name": repo.name, "error": str(e)})

        return results

    def enumerate_organization_repositories(self, organization: Organization):
        """Enumerate all repositories within an organization."""
        if not organization.public_repos and not organization.private_repos:
            logger.warning(f"No repositories in organization {organization.name} to enumerate.")
            return []

        repo_enum = RepositoryEnum(self.api, skip_log=False, output_yaml=False)
        results = []

        for repo in organization.public_repos + organization.private_repos:
            try:
                repo_enum.enumerate_repository(repo)
                results.append(repo.toJSON())
            except Exception as e:
                logger.error(f"Error enumerating repository {repo.name}: {str(e)}")
                results.append({"name": repo.name, "error": str(e)})

        return results

    def toJSON(self):
        """Converts the run to Gato JSON representation."""
        if not self.user_details:
            logger.warning("User details not set.")
            return {}

        representation = {
            "username": self.user_details.get("user", "Unknown"),
            "scopes": self.user_details.get("scopes", []),
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