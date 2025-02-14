"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""

import re
from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.\n    """

    def __init__(self, job_data: dict, job_name: str):
        """Constructor for job wrapper.\n        """
        self.job_name = job_name
        self.job_data = job_data
        self.needs = job_data.get('needs', [])
        self.steps = [Step(step) for step in job_data.get('steps', [])]
        self.env = job_data.get('env', {})
        self.permissions = job_data.get('permissions', [])
        self.deployments = job_data.get('environment', [])
        self.if_condition = job_data.get('if')
        self.uses = job_data.get('uses')
        self.caller = False
        self.external_caller = False
        self.has_gate = False
        self.evaluated = False

        if self.uses and self.uses.startswith('./'):
            self.caller = True
            self.external_caller = True

        if self.job_data.get('environment'):
            self.deployments = self.job_data['environment']

        if self.job_data.get('env'):
            self.env = self.job_data['env']

        if self.job_data.get('permissions'):
            self.permissions = self.job_data['permissions']

        if self.job_data.get('if'):
            self.if_condition = self.job_data['if']

        if self.job_data.get('needs'):
            self.needs = self.job_data['needs']

        self.has_gate = any(step.is_gate for step in self.steps)

    def evaluateIf(self):
        """Evaluate the If expression by parsing it into an AST\n        and then evaluating it in the context of an external user\n        triggering it.\n        """
        if self.if_condition and not self.evaluated:
            try:
                parser = ExpressionParser(self.if_condition)
                if self.EVALUATOR.evaluate(parser.get_node()):
                    self.if_condition = f"EVALUATED: {self.if_condition}"
                else:
                    self.if_condition = f"RESTRICTED: {self.if_condition}"
            except ValueError as ve:
                self.if_condition = self.if_condition
            except NotImplementedError as ni:
                self.if_condition = self.if_condition
            except (SyntaxError, IndexError) as e:
                self.if_condition = self.if_condition
            finally:
                self.evaluated = True

        return self.if_condition

    def gated(self):
        """Check if the workflow is gated.\n        """
        return self.has_gate or (self.evaluateIf() and self.evaluateIf().startswith("RESTRICTED"))

    EVALUATOR = ExpressionEvaluator()