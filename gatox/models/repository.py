import datetime

from gatox.models.runner import Runner
from gatox.models.secret import Secret


class Repository:
    """Wrapper class for GitHub repository data."""

    def __init__(self, repo_data: dict):
        """Initialize the repository wrapper.

        Args:
            repo_data (dict): Dictionary from parsing JSON object returned from GitHub.
        """
        self.repo_data = repo_data
        if 'environments' not in self.repo_data:
            self.repo_data['environments'] = []

        self.name = self.repo_data['full_name']
        self.org_name = self.name.split('/')[0]
        self.secrets: list[Secret] = []
        self.org_secrets: list[Secret] = []
        self.sh_workflow_names = []
        self.enum_time = datetime.datetime.now()
        self.permission_data = self.repo_data['permissions']
        self.sh_runner_access = False
        self.accessible_runners: list[Runner] = []
        self.runners: list[Runner] = []
        self.pwn_req_risk = []
        self.injection_risk = []

    def is_admin(self) -> bool:
        """Check if the user has admin permissions."""
        return self.permission_data.get('admin', False)

    def is_maintainer(self) -> bool:
        """Check if the user has maintainer permissions."""
        return self.permission_data.get('maintain', False)

    def can_push(self) -> bool:
        """Check if the user can push to the repository."""
        return self.permission_data.get('push', False)

    def can_pull(self) -> bool:
        """Check if the user can pull from the repository."""
        return self.permission_data.get('pull', False)

    def is_private(self) -> bool:
        """Check if the repository is private."""
        return self.repo_data['private']

    def is_archived(self) -> bool:
        """Check if the repository is archived."""
        return self.repo_data['archived']

    def is_internal(self) -> bool:
        """Check if the repository is internal."""
        return self.repo_data['visibility'] == 'internal'

    def is_public(self) -> bool:
        """Check if the repository is public."""
        return self.repo_data['visibility'] == 'public'

    def is_fork(self) -> bool:
        """Check if the repository is a fork."""
        return self.repo_data['fork']

    def can_fork(self) -> bool:
        """Check if the repository can be forked."""
        return self.repo_data.get('allow_forking', False)

    def default_path(self) -> str:
        """Get the default path for the repository."""
        return f"{self.repo_data['html_url']}/blob/{self.repo_data['default_branch']}"

    def update_time(self):
        """Update the enumeration timestamp."""
        self.enum_time = datetime.datetime.now()

    def set_accessible_org_secrets(self, secrets: list[Secret]):
        """Set organization secrets accessible by this repository.

        Args:
            secrets (List[Secret]): List of Secret wrapper objects.
        """
        self.org_secrets = secrets

    def set_pwn_request(self, pwn_request_package: dict):
        """Add a pwn request risk package.

        Args:
            pwn_request_package (dict): Pwn request risk package to add.
        """
        self.pwn_req_risk.append(pwn_request_package)

    def clear_pwn_request(self, workflow_name: str):
        """Remove a pwn request risk package by workflow name.

        Args:
            workflow_name (str): Name of the workflow to remove.
        """
        self.pwn_req_risk = [element for element in self.pwn_req_risk if element['workflow_name'] != workflow_name]

    def has_pwn_request(self) -> bool:
        """Check if there are any pwn request risks."""
        return bool(self.pwn_req_risk)

    def set_injection(self, injection_package: dict):
        """Add an injection risk package.

        Args:
            injection_package (dict): Injection risk package to add.
        """
        self.injection_risk.append(injection_package)

    def has_injection(self) -> bool:
        """Check if there are any injection risks."""
        return bool(self.injection_risk)

    def set_secrets(self, secrets: list[Secret]):
        """Set secrets attached to this repository.

        Args:
            secrets (List[Secret]): List of repo-level Secret wrapper objects.
        """
        self.secrets = secrets

    def set_runners(self, runners: list[Runner]):
        """Set self-hosted runners attached at the repository level.

        Args:
            runners (List[Runner]): List of Runner wrapper objects.
        """
        self.sh_runner_access = True
        self.runners = runners

    def add_self_hosted_workflows(self, workflows: list[str]):
        """Add workflow file names that run on self-hosted runners.

        Args:
            workflows (List[str]): List of workflow names.
        """
        self.sh_workflow_names.extend(workflows)

    def add_accessible_runner(self, runner: Runner):
        """Add a runner accessible by this repository.

        Args:
            runner (Runner): Runner wrapper object.
        """
        self.sh_runner_access = True
        self.accessible_runners.append(runner)

    def toJSON(self) -> dict:
        """Convert the repository to a Gato JSON representation."""
        return {
            "name": self.name,
            "enum_time": self.enum_time.ctime(),
            "permissions": self.permission_data,
            "can_fork": self.can_fork(),
            "stars": self.repo_data['stargazers_count'],
            "runner_workflows": self.sh_workflow_names,
            "accessible_runners": [runner.toJSON() for runner in self.accessible_runners],
            "repo_runners": [runner.toJSON() for runner in self.runners],
            "repo_secrets": [secret.toJSON() for secret in self.secrets],
            "org_secrets": [secret.toJSON() for secret in self.org_secrets],
            "pwn_request_risk": self.pwn_req_risk,
            "injection_risk": self.injection_risk
        }


This revised code addresses the feedback by:
1. Ensuring all string literals are properly terminated.
2. Simplifying the class documentation to be more concise.
3. Ensuring the constructor's docstring accurately reflects the parameter name and is concise.
4. Simplifying boolean return statements.
5. Reviewing and refining method docstrings for clarity and consistency.
6. Maintaining consistent formatting throughout the code.
7. Reviewing and keeping only necessary attributes.
8. Simplifying the JSON representation construction.
9. Ensuring method names follow the same naming conventions as in the gold code.
10. Removing any unnecessary comments.