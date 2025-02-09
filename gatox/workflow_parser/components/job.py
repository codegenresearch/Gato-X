"""
Copyright 2024, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
from typing import Any, List, Dict
from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

class Job():
    """Wrapper class for a Github Actions workflow job.
    """
    LARGER_RUNNER_REGEX_LIST = re.compile(
        r'(windows|ubuntu)-(22\.04|20\.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    )
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(
        r'{{\s*matrix\.([\w-]+)\s*}}'
    )

    EVALUATOR = ExpressionEvaluator()

    def __init__(self, job_data: Dict[str, Any], job_name: str):
        """Constructor for job wrapper.
        """
        if isinstance(job_data, list) and len(job_data) == 1:
            job_data = job_data[0]
        elif not isinstance(job_data, dict):
            raise ValueError("job_data must be a dictionary or a single-element list containing a dictionary")

        self.job_name = job_name
        self.job_data = job_data
        self.needs = job_data.get('needs', [])
        self.steps = [Step(step) for step in job_data.get('steps', [])]
        self.env = job_data.get('env', {})
        self.permissions = job_data.get('permissions', {})
        self.deployments = []
        self.if_condition = job_data.get('if', None)
        self.uses = job_data.get('uses', None)
        self.caller = self.uses and self.uses.startswith('./')
        self.external_caller = self.uses and not self.caller
        self.has_gate = any(step.is_gate for step in self.steps)
        self.evaluated = False
        self.has_self_hosted = False
        self.has_larger_runner = False
        self.has_matrix = False

        if 'environment' in self.job_data:
            env_data = self.job_data['environment']
            if type(env_data) is list:
                self.deployments.extend(env_data)
            else:
                self.deployments.append(env_data)

        self.__process_runner()
        self.__process_matrix()

    def evaluateIf(self) -> str:
        """Evaluate the If expression by parsing it into an AST
        and then evaluating it in the context of an external user
        triggering it.
        """
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

    def gated(self) -> bool:
        """Check if the workflow is gated.
        """
        return self.has_gate or (self.evaluateIf() and self.evaluateIf().startswith("RESTRICTED"))

    def getJobDependencies(self) -> List[str]:
        """Returns Job objects for jobs that must complete 
        successfully before this one.
        """
        return self.needs

    def isCaller(self) -> bool:
        """Returns true if the job is a caller (meaning it 
        references a reusable workflow that runs on workflow_call)
        """
        return self.caller

    def isSelfHosted(self) -> bool:
        """Check if the job uses a self-hosted runner."""
        return self.has_self_hosted

    def __process_runner(self) -> None:
        """
        Processes the runner for the job.
        """
        runner = self.job_data.get('runs-on', '')
        if type(runner) is list:
            for r in runner:
                self.__check_runner(r)
        else:
            self.__check_runner(runner)

    def __check_runner(self, runner: str) -> None:
        """
        Checks if the runner is self-hosted or a larger runner.
        """
        if 'self-hosted' in runner:
            self.has_self_hosted = True
        elif self.LARGER_RUNNER_REGEX_LIST.match(runner):
            self.has_larger_runner = True

    def __process_matrix(self) -> None:
        """
        Processes matrix jobs.
        """
        strategy = self.job_data.get('strategy', {})
        matrix = strategy.get('matrix', {})
        for key, values in matrix.items():
            if type(values) is list:
                for value in values:
                    self.__process_matrix_value(key, value)

    def __process_matrix_value(self, key: str, value: Any) -> None:
        """
        Processes individual matrix values.
        """
        if type(value) is str:
            if self.MATRIX_KEY_EXTRACTION_REGEX.search(value):
                self.has_matrix = True