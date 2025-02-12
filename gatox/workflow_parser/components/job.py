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
        self.needs = job_data.get('needs', [])
        self.steps = [Step(step) for step in job_data.get('steps', [])]
        self.env = job_data.get('env', {})
        self.permissions = job_data.get('permissions', [])
        self.deployments = job_data.get('environment', [])
        if not isinstance(self.deployments, list):
            self.deployments = [self.deployments]
        self.if_condition = job_data.get('if')
        self.uses = job_data.get('uses')
        self.caller = self.uses and self.uses.startswith('./')
        self.external_caller = self.uses and not self.caller
        self.has_gate = any(step.is_gate for step in self.steps)
        self.evaluated = False

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
        """Check if the workflow is gated.\n        """
        return self.has_gate or (self.evaluateIf() and self.evaluateIf().startswith("RESTRICTED"))

    def getJobDependencies(self):
        """Returns Job objects for jobs that must complete \n        successfully before this one.\n        """
        return self.needs

    def isCaller(self):
        """Returns true if the job is a caller (meaning it \n        references a reusable workflow that runs on workflow_call)\n        """
        return self.caller

    def isSelfHosted(self):
        """Check if the job uses a self-hosted runner."""
        runner = self.job_data.get('runs-on', '')
        return 'self-hosted' in runner