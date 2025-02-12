"""\nCopyright 2024, Adnan Khan\n\nLicensed under the Apache License, Version 2.0 (the "License");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\n    http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an "AS IS" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"""

import logging
import os
import re
from pathlib import Path

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.utility import filter_tokens, decompose_action_ref
from gatox.workflow_parser.components.job import Job
from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)

class WorkflowParser:
    """Parser for YML files.\n\n    This class is structured to take a yaml file as input and expose methods\n    that aim to answer questions about the yaml file. This will allow for growing\n    what kind of analytics this tool can perform as the project grows in capability.\n\n    This class should only perform static analysis. The caller is responsible for\n    performing any API queries to augment the analysis.\n    """

    LARGER_RUNNER_REGEX_LIST = re.compile(r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb')
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(r'{{\s*matrix\.([\w-]+)\s*}}')

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.\n\n        Args:\n            workflow_wrapper (Workflow): Wrapper for the workflow file.\n            non_default (str, optional): Non-default branch. Defaults to None.\n        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml
        self.jobs = [Job(job_data, job_name) for job_name, job_data in self.parsed_yml.get('jobs', {}).items()]
        self.raw_yaml = workflow_wrapper.workflow_contents
        self.repo_name = workflow_wrapper.repo_name
        self.wf_name = workflow_wrapper.workflow_name
        self.callees = []
        self.external_ref = False

        if workflow_wrapper.special_path:
            self.external_ref = True
            self.external_path = workflow_wrapper.special_path
            self.branch = workflow_wrapper.branch
        elif non_default:
            self.branch = non_default
        else:
            self.branch = None

        self.composites = self.extract_referenced_actions()
        self.cache = {}

    def is_referenced(self):
        return self.external_ref

    def has_trigger(self, trigger):
        """Check if the workflow has a specific trigger.\n\n        Args:\n            trigger (str): The trigger to check for.\n\n        Returns:\n            bool: Whether the workflow has the specified trigger.\n        """
        return bool(self.get_vulnerable_triggers(trigger))

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.\n\n        Args:\n            dirpath (str): Directory to save the yaml file to.\n\n        Returns:\n            bool: Whether the file was successfully written.\n        """
        directory = Path(dirpath) / self.repo_name
        directory.mkdir(parents=True, exist_ok=True)
        file_path = directory / self.wf_name

        if file_path.exists() and file_path.read_text() == self.raw_yaml:
            logger.info(f"No changes detected for {self.wf_name}. Skipping write.")
            return True

        file_path.write_text(self.raw_yaml)
        logger.info(f"Successfully wrote {self.wf_name} to {directory}.")
        return True

    def extract_referenced_actions(self):
        """Extracts composite actions from the workflow file.\n\n        Returns:\n            dict: Referenced actions in the workflow.\n        """
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
        """Analyze if the workflow is set to execute on potentially risky triggers.\n\n        Args:\n            alternate (str, optional): Alternate trigger to check. Defaults to False.\n\n        Returns:\n            list: List of vulnerable triggers.\n        """
        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 'issue_comment', 'issues']
        if alternate:
            risky_triggers = [alternate]

        triggers = self.parsed_yml.get('on', {})
        if isinstance(triggers, list):
            vulnerable_triggers = [trigger for trigger in triggers if trigger in risky_triggers]
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
        """Attempts to find if a job needed by a specific job has a gate check.\n\n        Args:\n            needs_name (str or list): Job name or list of job names to check.\n\n        Returns:\n            bool: Whether a gate check is found.\n        """
        if isinstance(needs_name, list):
            return any(self.backtrack_gate(need) for need in needs_name)
        else:
            for job in self.jobs:
                if job.job_name == needs_name:
                    if job.gated():
                        return True
                    elif job.needs:
                        return self.backtrack_gate(job.needs)
        return False

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the\n        'actions/checkout' action with a 'ref' parameter.\n\n        Returns:\n            dict: Checkout analysis results.\n        """
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
                        elif if_check == '':
                            pass
                        step_details.append({"ref": step.metadata, "if_check": if_check, "step_name": step.name})

                elif step_details and step.is_sink:
                    job_content['confidence'] = 'HIGH' if (job_content['if_check'] and job_content['if_check'].startswith('EVALUATED')) \
                        or (bump_confidence and not job_content['if_check']) else 'MEDIUM'

            job_content["check_steps"] = step_details
            job_checkouts[job.job_name] = job_content

        return job_checkouts

    def check_pwn_request(self, bypass=False):
        """Check for potential pwn request vulnerabilities.\n\n        Args:\n            bypass (bool, optional): Bypass the vulnerability check. Defaults to False.\n\n        Returns:\n            dict: Pwn request analysis results.\n        """
        key = ('check_pwn_request', bypass)
        if key in self.cache:
            logger.info("Returning cached result for check_pwn_request.")
            return self.cache[key]

        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            self.cache[key] = {}
            return self.cache[key]

        checkout_risk = {}
        candidates = {}

        checkout_info = self.analyze_checkouts()
        for job_name, job_content in checkout_info.items():
            steps_risk = job_content['check_steps']
            if steps_risk:
                candidates[job_name] = {
                    'confidence': job_content['confidence'],
                    'gated': job_content['gated'],
                    'steps': steps_risk,
                    'if_check': job_content.get('if_check', '')
                }

        if candidates:
            checkout_risk['candidates'] = candidates
            checkout_risk['triggers'] = vulnerable_triggers

        self.cache[key] = checkout_risk
        logger.info("Caching result for check_pwn_request.")
        return self.cache[key]

    def check_rules(self, gate_rules):
        """Checks environment protection rules from the API against those specified in the job.\n\n        Args:\n            gate_rules (list): List of rules to check against.\n\n        Returns:\n            bool: Whether the job is violating any of the rules.\n        """
        for rule in gate_rules:
            for job in self.jobs:
                for deploy_rule in job.deployments:
                    if rule in deploy_rule:
                        return False
        return True

    def check_injection(self, bypass=False):
        """Check for potential script injection vulnerabilities.\n\n        Args:\n            bypass (bool, optional): Bypass the vulnerability check. Defaults to False.\n\n        Returns:\n            dict: Injection analysis results.\n        """
        key = ('check_injection', bypass)
        if key in self.cache:
            logger.info("Returning cached result for check_injection.")
            return self.cache[key]

        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            self.cache[key] = {}
            return self.cache[key]

        injection_risk = {}

        for job in self.jobs:
            for step in job.steps:
                if step.is_gate:
                    break

                if step.is_script:
                    tokens = step.getTokens()
                else:
                    continue

                tokens = filter_tokens(tokens)

                def check_token(token, container):
                    if token.startswith('env.') and token.split('.')[1] in container['env']:
                        value = container['env'][token.split('.')[1]]
                        if value and not isinstance(value, (int, float)) and '${{' in value:
                            return True
                    return False

                if 'env' in self.parsed_yml:
                    tokens = [token for token in tokens if check_token(token, self.parsed_yml)]
                if 'env' in job.job_data:
                    tokens = [token for token in tokens if check_token(token, job.job_data)]
                if 'env' in step.step_data:
                    tokens = [token for token in tokens if check_token(token, step.step_data)]

                if tokens:
                    if job.needs and self.backtrack_gate(job.needs):
                        break

                    if job.job_name not in injection_risk:
                        injection_risk[job.job_name] = {
                            'if_check': job.evaluateIf()
                        }

                    injection_risk[job.job_name][step.name] = {
                        "variables": list(set(tokens))
                    }
                    if step.evaluateIf():
                        injection_risk[job.job_name][step.name]['if_checks'] = step.evaluateIf()

        if injection_risk:
            injection_risk['triggers'] = vulnerable_triggers

        self.cache[key] = injection_risk
        logger.info("Caching result for check_injection.")
        return self.cache[key]

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.\n\n        Returns:\n            list: List of jobs using self-hosted runners.\n        """
        sh_jobs = []

        if not self.parsed_yml.get('jobs'):
            return sh_jobs

        for jobname, job_details in self.parsed_yml['jobs'].items():
            if 'runs-on' not in job_details:
                continue

            runs_on = job_details['runs-on']
            if 'self-hosted' in runs_on:
                sh_jobs.append((jobname, job_details))
            elif 'matrix.' in runs_on:
                matrix_match = self.MATRIX_KEY_EXTRACTION_REGEX.search(runs_on)
                if not matrix_match:
                    continue
                matrix_key = matrix_match.group(1)

                if 'strategy' not in job_details or 'matrix' not in job_details['strategy']:
                    continue

                matrix = job_details['strategy']['matrix']
                if matrix_key in matrix:
                    os_list = matrix[matrix_key]
                elif 'include' in matrix:
                    inclusions = matrix['include']
                    os_list = [inclusion[matrix_key] for inclusion in inclusions if matrix_key in inclusion]
                else:
                    continue

                for key in os_list:
                    if isinstance(key, str) and key not in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] \
                            and not self.LARGER_RUNNER_REGEX_LIST.match(key):
                        sh_jobs.append((jobname, job_details))
                        break
            else:
                if isinstance(runs_on, list):
                    for label in runs_on:
                        if label in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] \
                                or self.LARGER_RUNNER_REGEX_LIST.match(label):
                            break
                    else:
                        sh_jobs.append((jobname, job_details))
                elif isinstance(runs_on, str):
                    if runs_on in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] \
                            or self.LARGER_RUNNER_REGEX_LIST.match(runs_on):
                        continue
                    sh_jobs.append((jobname, job_details))

        return sh_jobs