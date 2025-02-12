"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""
import re

from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.\n    """
    LARGER_RUNNER_REGEX_LIST = re.compile(
        r'(windows|ubuntu)-(22\.04|20\.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    )
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(
        r'{{\s*matrix\.([\w-]+)\s*}}'
    )

    EVALUATOR = ExpressionEvaluator()

    def __init__(self, job_data: dict, job_name: str):
        """Constructor for job wrapper.\n        """
        self.job_name = job_name
        self.job_data = job_data
        self.needs = []
        self.steps = []
        self.env = {}
        self.permissions = []
        self.deployments = []
        self.if_condition = None
        self.uses = None
        self.caller = False
        self.external_caller = False
        self.has_gate = False
        self.self_hosted_runner = False
        self.evaluated = False

        self._initialize_job_data()

    def _initialize_job_data(self):
        """Initialize job data attributes."""
        if 'environment' in self.job_data:
            self.deployments = self.job_data['environment'] if isinstance(self.job_data['environment'], list) else [self.job_data['environment']]

        if 'env' in self.job_data:
            self.env = self.job_data['env']

        if 'permissions' in self.job_data:
            self.permissions = self.job_data['permissions']

        if 'if' in self.job_data:
            self.if_condition = self.job_data['if']

        if 'needs' in self.job_data:
            self.needs = self.job_data['needs']

        if 'uses' in self.job_data:
            self.uses = self.job_data['uses']
            self.caller = self.uses.startswith('./')
            self.external_caller = not self.caller

        if 'runs-on' in self.job_data:
            self.self_hosted_runner = self._is_self_hosted(self.job_data['runs-on'])

        if 'steps' in self.job_data:
            self.steps = [Step(step) for step in self.job_data['steps']]
            self.has_gate = any(step.is_gate for step in self.steps)

    def _is_self_hosted(self, runs_on):
        """Determine if the job uses a self-hosted runner."""
        if isinstance(runs_on, str):
            return not self.LARGER_RUNNER_REGEX_LIST.match(runs_on)
        elif isinstance(runs_on, list):
            return not all(self.LARGER_RUNNER_REGEX_LIST.match(runner) for runner in runs_on)
        return False

    def evaluateIf(self):
        """Evaluate the If expression by parsing it into an AST\n        and then evaluating it in the context of an external user\n        triggering it.\n        """
        if self.if_condition and not self.evaluated:
            try:
                parser = ExpressionParser(self.if_condition)
                if self.EVALUATOR.evaluate(parser.get_node()):
                    self.if_condition = f"EVALUATED: {self.if_condition}"
                else:
                    self.if_condition = f"RESTRICTED: {self.if_condition}"
            except (ValueError, NotImplementedError, SyntaxError, IndexError):
                pass
            finally:
                self.evaluated = True

        return self.if_condition

    def gated(self):
        """Check if the job is gated."""
        return self.has_gate or (self.evaluateIf() and self.evaluateIf().startswith("RESTRICTED"))

    def getJobDependencies(self):
        """Returns Job objects for jobs that must complete \n        successfully before this one.\n        """
        return self.needs

    def isCaller(self):
        """Returns true if the job is a caller (meaning it \n        references a reusable workflow that runs on workflow_call)\n        """
        return self.caller

    def isSelfHosted(self):
        """Returns true if the job uses a self-hosted runner."""
        return self.self_hosted_runner