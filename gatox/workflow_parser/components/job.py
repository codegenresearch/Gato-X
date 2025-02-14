"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""
import re

from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.\n    """
    LARGER_RUNNER_REGEX_LIST = re.compile(
        r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    )
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(
        r'{{\s*matrix\.([\w-]+)\s*}}'
    )

    EVALUATOR = ExpressionEvaluator()

    def __init__(self, job_data: dict, job_name: str):
        """Constructor for job wrapper.\n        """
        self.job_name = job_name
        self.job_data = job_data
        self.needs = job_data.get('needs', [])
        self.steps = []
        self.env = job_data.get('env', {})
        self.permissions = job_data.get('permissions', [])
        self.deployments = job_data.get('environment', [])
        self.if_condition = job_data.get('if', None)
        self.uses = job_data.get('uses', None)
        self.caller = False
        self.external_caller = False
        self.has_gate = False
        self.evaluated = False

        self.__process_runner()

        if self.deployments:
            self.deployments = [self.deployments]

        if 'steps' in job_data:
            for step in job_data['steps']:
                added_step = Step(step)
                if added_step.is_gate:
                    self.has_gate = True
                self.steps.append(added_step)

        if self.uses and self.uses.startswith('./'):
            self.caller = True
            self.external_caller = False
        elif self.uses:
            self.caller = False
            self.external_caller = True

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
        if_eval = self.evaluateIf()
        return self.has_gate or (if_eval and if_eval.startswith("RESTRICTED"))

    def __process_runner(self):
        """\n        Processes the runner for the job.\n        """
        if 'runs-on' in self.job_data:
            if 'self-hosted' in self.job_data['runs-on'].lower():
                self.self_hosted = True
            else:
                self.self_hosted = False
        else:
            self.self_hosted = False

    def getJobDependencies(self):
        """Returns Job objects for jobs that must complete \n        successfully before this one.\n        """
        return [job for job in self.needs]

    def isCaller(self):
        """Returns true if the job is a caller (meaning it \n        references a reusable workflow that runs on workflow_call)\n        """
        return self.caller