import datetime

from gatox.models.runner import Runner
from gatox.models.secret import Secret


class Repository():
    """
    Simple wrapper class to provide accessor methods against the repository
    JSON response from GitHub.
    """

    def __init__(self, repo_data: dict):
        """
        Initialize wrapper class.

        Args:
            repo_data (dict): Dictionary from parsing JSON object returned from GitHub
        """
        self.repo_data = repo_data
        # Temporary hack until full transition to GQL
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

    def is_admin(self):
        """
        Check if the user has admin permissions for the repository.
        """
        return self.permission_data.get('admin', False)

    def is_maintainer(self):
        """
        Check if the user has maintainer permissions for the repository.
        """
        return self.permission_data.get('maintain', False)

    def can_push(self):
        """
        Check if the user can push to the repository.
        """
        return self.permission_data.get('push', False)

    def can_pull(self):
        """
        Check if the user can pull from the repository.
        """
        return self.permission_data.get('pull', False)

    def is_private(self):
        """
        Check if the repository is private.
        """
        return not self.is_public()

    def is_archived(self):
        """
        Check if the repository is archived.
        """
        return self.repo_data['archived']

    def is_internal(self):
        """
        Check if the repository is internal.
        """
        return self.repo_data.get('visibility') == 'internal'

    def is_public(self):
        """
        Check if the repository is public.
        """
        return self.repo_data.get('visibility') == 'public'

    def is_fork(self):
        """
        Check if the repository is a fork.
        """
        return self.repo_data['fork']

    def can_fork(self):
        """
        Check if the repository can be forked.
        """
        return self.repo_data.get('allow_forking', False)

    def default_path(self):
        """
        Get the default path for the repository.
        """
        return f"{self.repo_data['html_url']}/blob/{self.repo_data['default_branch']}"

    def update_time(self):
        """
        Update the enumeration timestamp to the current time.
        """
        self.enum_time = datetime.datetime.now()

    def set_accessible_org_secrets(self, secrets: list[Secret]):
        """
        Set organization secrets that can be read using a workflow in this repository.

        Args:
            secrets (list[Secret]): List of Secret wrapper objects.
        """
        self.org_secrets = secrets

    def set_pwn_request(self, pwn_request_package: dict):
        """
        Set a pwn request risk package.

        Args:
            pwn_request_package (dict): The pwn request risk package.
        """
        self.pwn_req_risk.append(pwn_request_package)

    def clear_pwn_request(self, workflow_name: str):
        """
        Remove a pwn request entry since it's a false positive.

        Args:
            workflow_name (str): The name of the workflow to clear.
        """
        self.pwn_req_risk = [element for element in self.pwn_req_risk if element['workflow_name'] != workflow_name]

    def has_pwn_request(self):
        """
        Check if there are any pwn request risks.
        """
        return len(self.pwn_req_risk) > 0

    def set_injection(self, injection_package: dict):
        """
        Set an injection risk package.

        Args:
            injection_package (dict): The injection risk package.
        """
        self.injection_risk.append(injection_package)

    def has_injection(self):
        """
        Check if there are any injection risks.
        """
        return len(self.injection_risk) > 0

    def set_secrets(self, secrets: list[Secret]):
        """
        Set secrets that are attached to this repository.

        Args:
            secrets (list[Secret]): List of repo level secret wrapper objects.
        """
        self.secrets = secrets

    def set_runners(self, runners: list[Runner]):
        """
        Set list of self-hosted runners attached at the repository level.

        Args:
            runners (list[Runner]): List of Runner wrapper objects.
        """
        self.sh_runner_access = True
        self.runners = runners

    def add_self_hosted_workflows(self, workflows: list[str]):
        """
        Add a list of workflow file names that run on self-hosted runners.

        Args:
            workflows (list[str]): List of workflow names.
        """
        self.sh_workflow_names.extend(workflows)

    def add_accessible_runner(self, runner: Runner):
        """
        Add a runner that is accessible by this repo. This runner could be org level or repo level.

        Args:
            runner (Runner): Runner wrapper object.
        """
        self.sh_runner_access = True
        self.accessible_runners.append(runner)

    def toJSON(self) -> dict:
        """
        Convert the repository to a Gato JSON representation.
        """
        representation = {
            "name": self.name,
            "enum_time": self.enum_time.ctime(),
            "permissions": self.permission_data,
            "can_fork": self.can_fork(),
            "stars": self.repo_data.get('stargazers_count', 0),
            "runner_workflows": self.sh_workflow_names,
            "accessible_runners": [runner.toJSON() for runner in self.accessible_runners],
            "repo_runners": [runner.toJSON() for runner in self.runners],
            "repo_secrets": [secret.toJSON() for secret in self.secrets],
            "org_secrets": [secret.toJSON() for secret in self.org_secrets],
            "pwn_request_risk": self.pwn_req_risk,
            "injection_risk": self.injection_risk
        }
        return representation