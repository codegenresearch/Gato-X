"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""

import logging

from pathlib import Path
import os
import re

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.utility import filter_tokens, decompose_action_ref
from gatox.workflow_parser.components.job import Job
from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class WorkflowParser():
    """Parser for YML files.\n\n    This class is structured to take a yaml file as input, it will then\n    expose methods that aim to answer questions about the yaml file.\n\n    This will allow for growing what kind of analytics this tool can perform\n    as the project grows in capability.\n\n    This class should only perform static analysis. The caller is responsible for \n    performing any API queries to augment the analysis.\n    """

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.\n\n        Args:\n            workflow_wrapper (Workflow): Workflow object containing parsed YML and metadata.\n        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml
        self.jobs = self._parse_jobs()
        self.raw_yaml = workflow_wrapper.workflow_contents
        self.repo_name = workflow_wrapper.repo_name
        self.wf_name = workflow_wrapper.workflow_name
        self.callees = []
        self.external_ref = self._determine_external_ref(workflow_wrapper, non_default)
        self.branch = workflow_wrapper.branch if workflow_wrapper.special_path else non_default
        self.composites = self.extract_referenced_actions()

    def _parse_jobs(self):
        """Parse jobs from the workflow YML."""
        jobs = self.parsed_yml.get('jobs', {})
        return [Job(job_data, job_name) for job_name, job_data in jobs.items()]

    def _determine_external_ref(self, workflow_wrapper, non_default):
        """Determine if the workflow is an external reference."""
        if workflow_wrapper.special_path:
            return True
        elif non_default:
            return False
        return False

    def is_referenced(self):
        return self.external_ref

    def has_trigger(self, trigger):
        """Check if the workflow has a specific trigger.\n\n        Args:\n            trigger (str): The trigger to check for.\n        Returns:\n            bool: Whether the workflow has the specified trigger.\n        """
        return self.get_vulnerable_triggers(trigger)

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.\n\n        Args:\n            dirpath (str): Directory to save the yaml file to.\n\n        Returns:\n            bool: Whether the file was successfully written.\n        """
        output_path = Path(dirpath) / self.repo_name
        output_path.mkdir(parents=True, exist_ok=True)
        file_path = output_path / self.wf_name

        with file_path.open('w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True

    def extract_referenced_actions(self):
        """Extracts composite actions from the workflow file."""
        referenced_actions = {}
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers:
            return referenced_actions

        for job in self.jobs:
            for step in job.steps:
                if step.type == 'ACTION':
                    action_parts = decompose_action_ref(step.uses, step.step_data, self.repo_name)
                    if action_parts:
                        referenced_actions[step.uses] = action_parts

        return referenced_actions

    def get_vulnerable_triggers(self, alternate=False):
        """Analyze if the workflow is set to execute on potentially risky triggers.\n\n        Returns:\n            list: List of triggers within the workflow that could be vulnerable\n            to GitHub Actions script injection vulnerabilities.\n        """
        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 
                          'issue_comment', 'issues', 'discussion_comment', 'discussion',
                          'fork', 'watch']
        if alternate:
            risky_triggers = [alternate]

        triggers = self.parsed_yml.get('on', {})
        if isinstance(triggers, list):
            for trigger in triggers:
                if trigger in risky_triggers:
                    vulnerable_triggers.append(trigger)
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger in risky_triggers:
                    if trigger_conditions and 'types' in trigger_conditions:
                        if 'labeled' in trigger_conditions['types'] and len(trigger_conditions['types']) == 1:
                            vulnerable_triggers.append(f"{trigger}:{trigger_conditions['types'][0]}")
                        else:
                            vulnerable_triggers.append(trigger)
                    else:
                        vulnerable_triggers.append(trigger)

        return vulnerable_triggers

    def backtrack_gate(self, needs_name):
        """Attempts to find if a job needed by a specific job has a gate check."""
        if isinstance(needs_name, list):
            return any(self.backtrack_gate(need) for need in needs_name)
        for job in self.jobs:
            if job.job_name == needs_name and job.gated():
                return True
            elif job.job_name == needs_name and not job.gated():
                return self.backtrack_gate(job.needs)
        return False

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the \n        'actions/checkout' action with a 'ref' parameter.\n\n        Returns:\n            dict: Dictionary of job names and checkout analysis results.\n        """
        job_checkouts = {}
        for job in self.jobs:
            job_content = {
                "check_steps": [],
                "if_check": job.evaluateIf(),
                "confidence": "UNKNOWN",
                "gated": False
            }
            step_details = []
            bump_confidence = False

            if job.isCaller():
                self.callees.append(job.uses.split('/')[-1])
            elif job.external_caller:
                self.callees.append(job.uses)

            if job_content['if_check'] and job_content['if_check'].startswith("RESTRICTED"):
                job_content['gated'] = True

            for step in job.steps:
                if step.is_gate:
                    job_content['gated'] = True
                    break
                elif step.is_checkout:
                    if job.needs:
                        job_content['gated'] = self.backtrack_gate(job.needs)
                    if job_content['gated'] and ('github.event.pull_request.head.sha' in step.metadata.lower() 
                                                 or ('sha' in step.metadata.lower() and 'env.' in step.metadata.lower())):
                        break
                    else:
                        if_check = step.evaluateIf()
                        if if_check and if_check.startswith('EVALUATED'):
                            bump_confidence = True
                        elif if_check and 'RESTRICTED' in if_check:
                            bump_confidence = False
                        step_details.append({"ref": step.metadata, "if_check": if_check, "step_name": step.name})

                elif step_details and step.is_sink:
                    job_content['confidence'] = 'HIGH' if \
                        (job_content['if_check'] and job_content['if_check'].startswith('EVALUATED')) \
                        or (bump_confidence and not job_content['if_check']) \
                        or (not job_content['if_check'] and (not step.evaluateIf() or step.evaluateIf().startswith('EVALUATED'))) \
                        else 'MEDIUM'

            job_content["check_steps"] = step_details
            job_checkouts[job.job_name] = job_content

        return job_checkouts

    def check_pwn_request(self, bypass=False):
        """Check for potential pwn request vulnerabilities.\n\n        Returns:\n            dict: A dictionary containing the job names as keys and a \n            list of potentially vulnerable tokens as values.\n        """
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

        checkout_info = self.analyze_checkouts()
        candidates = {job_name: job_content for job_name, job_content in checkout_info.items() if job_content['check_steps']}

        if candidates:
            return {'candidates': candidates, 'triggers': vulnerable_triggers}
        return {}

    def check_rules(self, gate_rules):
        """Checks environment protection rules from the API against those specified in the job.\n\n        Args:\n            gate_rules (list): List of rules to check against.\n\n        Returns:\n            bool: Whether the job is violating any of the rules.\n        """
        for rule in gate_rules:
            for job in self.jobs:
                for deploy_rule in job.deployments:
                    if rule in deploy_rule:
                        return False
        return True

    def check_injection(self, bypass=False):
        """Check for potential script injection vulnerabilities.\n\n        Returns:\n            dict: A dictionary containing the job names as keys and a list \n            of potentially vulnerable tokens as values.\n        """
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

        injection_risk = {}

        for job in self.jobs:
            for step in job.steps:
                if step.is_gate:
                    break
                if not step.is_script:
                    continue
                tokens = filter_tokens(step.getTokens())
                tokens = self._filter_environment_tokens(tokens, job, step)

                if tokens:
                    if job.needs and self.backtrack_gate(job.needs):
                        break
                    if job.job_name not in injection_risk:
                        injection_risk[job.job_name] = {'if_check': job.evaluateIf()}
                    injection_risk[job.job_name][step.name] = {
                        "variables": list(set(tokens))
                    }
                    if step.evaluateIf():
                        injection_risk[job.job_name][step.name]['if_checks'] = step.evaluateIf()

        if injection_risk:
            injection_risk['triggers'] = vulnerable_triggers
        return injection_risk

    def _filter_environment_tokens(self, tokens, job, step):
        """Filter out tokens that map to workflow or job level environment variables."""
        env_sources = [self.parsed_yml, job.job_data, step.step_data]
        for env_source in env_sources:
            if 'env' in env_source:
                tokens = [token for token in tokens if self._check_token(token, env_source)]
        return tokens

    def _check_token(self, token, container):
        """Check if a token is vulnerable to injection."""
        if token.startswith('env.') and token.split('.')[1] in container['env']:
            value = container['env'][token.split('.')[1]]
            if value and type(value) not in [int, float] and '${{' in value:
                return True
        return False

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.\n\n        Returns:\n           list: List of jobs within the workflow that utilize self-hosted\n           runners.\n        """
        sh_jobs = []
        github_hosted_labels = ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS']
        larger_runner_regex = re.compile(r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb')

        for job_name, job_details in self.parsed_yml.get('jobs', {}).items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                if 'self-hosted' in runs_on:
                    sh_jobs.append((job_name, job_details))
                elif 'matrix.' in runs_on:
                    matrix_key = self._extract_matrix_key(runs_on)
                    if matrix_key:
                        os_list = self._get_matrix_os_list(job_details, matrix_key)
                        if any(not self._is_github_hosted(os) for os in os_list):
                            sh_jobs.append((job_name, job_details))
                elif not self._is_github_hosted(runs_on):
                    sh_jobs.append((job_name, job_details))

        return sh_jobs

    def _extract_matrix_key(self, runs_on):
        """Extract the matrix key from a 'runs-on' string."""
        matrix_match = re.search(r'{{\s*matrix\.([\w-]+)\s*}}', runs_on)
        return matrix_match.group(1) if matrix_match else None

    def _get_matrix_os_list(self, job_details, matrix_key):
        """Get the list of operating systems from the matrix strategy."""
        matrix = job_details.get('strategy', {}).get('matrix', {})
        if matrix_key in matrix:
            return matrix[matrix_key]
        elif 'include' in matrix:
            return [inclusion[matrix_key] for inclusion in matrix['include'] if matrix_key in inclusion]
        return []

    def _is_github_hosted(self, os_label):
        """Check if the OS label is a GitHub-hosted runner."""
        github_hosted_labels = ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS']
        larger_runner_regex = re.compile(r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb')
        return os_label in github_hosted_labels or larger_runner_regex.match(os_label)