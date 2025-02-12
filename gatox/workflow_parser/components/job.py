"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""
import re

from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.\n    """
    LARGER_RUNNER_REGEX = re.compile(
        r'(windows|ubuntu)-(22\.04|20\.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    )
    MATRIX_KEY_REGEX = re.compile(
        r'{{\s*matrix\.([\w-]+)\s*}}'
    )

    EVALUATOR = ExpressionEvaluator()

    def __init__(self, job_data: dict, job_name: str):
        """Constructor for job wrapper.\n        """
        self.job_name = job_name
        self.job_data = job_data
        self.needs = self.job_data.get('needs', [])
        self.steps = [Step(step) for step in self.job_data.get('steps', [])]
        self.env = self.job_data.get('env', {})
        self.permissions = self.job_data.get('permissions', [])
        self.deployments = self._extract_deployments()
        self.if_condition = self.job_data.get('if')
        self.uses = self.job_data.get('uses')
        self.caller = self.uses and self.uses.startswith('./')
        self.external_caller = self.uses and not self.caller
        self.has_gate = any(step.is_gate for step in self.steps)
        self.runner_type = self._determine_runner_type()
        self.evaluated = False

    def _extract_deployments(self):
        """Extracts deployment environments from job data."""
        environment = self.job_data.get('environment')
        if isinstance(environment, list):
            return environment
        elif environment:
            return [environment]
        return []

    def _determine_runner_type(self):
        """Determines the type of runner based on job data."""
        runner = self.job_data.get('runs-on')
        if runner and self.LARGER_RUNNER_REGEX.match(runner):
            return 'self-hosted'
        return 'github-hosted'

    def evaluate_if(self):
        """Evaluate the If expression by parsing it into an AST\n        and then evaluating it in the context of an external user\n        triggering it.\n        """
        if self.if_condition and not self.evaluated:
            try:
                parser = ExpressionParser(self.if_condition)
                result = self.EVALUATOR.evaluate(parser.get_node())
                self.if_condition = f"EVALUATED: {self.if_condition}" if result else f"RESTRICTED: {self.if_condition}"
            except (ValueError, NotImplementedError, SyntaxError, IndexError):
                pass
            finally:
                self.evaluated = True
        return self.if_condition

    def is_gated(self):
        """Check if the job is gated."""
        return self.has_gate or (self.evaluate_if() and self.evaluate_if().startswith("RESTRICTED"))

    def get_job_dependencies(self):
        """Returns job names that must complete successfully before this one."""
        return self.needs

    def is_caller(self):
        """Returns true if the job is a caller."""
        return self.caller

    def is_self_hosted(self):
        """Returns true if the job uses a self-hosted runner."""
        return self.runner_type == 'self-hosted'