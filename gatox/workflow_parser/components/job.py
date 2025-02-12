"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""

from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.\n    """

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
        self.self_hosted = False
        self.sh_callees = []

        if 'environment' in self.job_data:
            environments = self.job_data['environment']
            if isinstance(environments, list):
                self.deployments.extend(environments)
            else:
                self.deployments.append(environments)

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

        if 'steps' in self.job_data:
            self.steps = []

            for step in self.job_data['steps']:
                added_step = Step(step)
                if added_step.is_gate:
                    self.has_gate = True
                self.steps.append(added_step)

        if 'runs-on' in self.job_data:
            self.self_hosted = self._is_self_hosted(self.job_data['runs-on'])

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

    def gated(self):
        """Check if the workflow is gated.\n        """
        return self.has_gate or (self.evaluate_if() and self.evaluate_if().startswith("RESTRICTED"))

    def _is_self_hosted(self, runner):
        """Determine if the runner is self-hosted."""
        return not runner.startswith(('windows', 'ubuntu', 'macos'))

    def get_job_dependencies(self):
        """Returns Job objects for jobs that must complete \n        successfully before this one.\n        """
        return self.needs

    def is_caller(self):
        """Returns true if the job is a caller (meaning it \n        references a reusable workflow that runs on workflow_call)\n        """
        return self.caller