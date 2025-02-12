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
    """Parser for YML files.\n\n    This class is structured to take a yaml file as input and expose methods that aim to answer questions about the yaml file.\n    It allows for growing the tool's analytics capabilities as the project evolves.\n    This class performs only static analysis; the caller is responsible for performing any API queries to augment the analysis.\n    """

    LARGER_RUNNER_REGEX_LIST = re.compile(r'(windows|ubuntu)-(22\.04|20\.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb')
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(r'{{\s*matrix\.([\w-]+)\s*}}')

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.\n\n        Args:\n            workflow_wrapper (Workflow): Workflow object containing parsed YAML and other metadata.\n        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml
        self.jobs = [Job(job_data, job_name) for job_name, job_data in self.parsed_yml.get('jobs', {}).items()]
        self.raw_yaml = workflow_wrapper.workflow_contents
        self.repo_name = workflow_wrapper.repo_name
        self.wf_name = workflow_wrapper.workflow_name
        self.callees = []
        self.external_ref = False
        self.branch = None
        self.composites = {}

        if workflow_wrapper.special_path:
            self.external_ref = True
            self.external_path = workflow_wrapper.special_path
            self.branch = workflow_wrapper.branch
        elif non_default:
            self.branch = non_default

        self._cache = {}
        self._load_cached_data()

    def _load_cached_data(self):
        """Load cached data if available."""
        cache_file = Path(f"{self.repo_name}/{self.wf_name}.cache")
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                self._cache = eval(f.read())

    def _save_cached_data(self):
        """Save current state to cache."""
        cache_file = Path(f"{self.repo_name}/{self.wf_name}.cache")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            f.write(repr(self._cache))

    def is_referenced(self):
        return self.external_ref

    def has_trigger(self, trigger):
        """Check if the workflow has a specific trigger.\n\n        Args:\n            trigger (str): The trigger to check for.\n        Returns:\n            bool: Whether the workflow has the specified trigger.\n        """
        return trigger in self.get_vulnerable_triggers()

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.\n\n        Args:\n            dirpath (str): Directory to save the yaml file to.\n\n        Returns:\n            bool: Whether the file was successfully written.\n        """
        output_path = Path(dirpath) / self.repo_name / self.wf_name
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True

    def extract_referenced_actions(self):
        """Extracts composite actions from the workflow file."""
        if 'jobs' not in self.parsed_yml:
            return {}

        if 'referenced_actions' in self._cache:
            return self._cache['referenced_actions']

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

        self._cache['referenced_actions'] = referenced_actions
        self._save_cached_data()
        return referenced_actions

    def get_vulnerable_triggers(self, alternate=False):
        """Analyze if the workflow is set to execute on potentially risky triggers.\n\n        Args:\n            alternate (str): Optional alternate trigger to check.\n\n        Returns:\n            list: List of triggers within the workflow that could be vulnerable to GitHub Actions script injection vulnerabilities.\n        """
        if 'vulnerable_triggers' in self._cache:
            return self._cache['vulnerable_triggers']

        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 'issue_comment', 'issues']
        if alternate:
            risky_triggers = [alternate]

        if not self.parsed_yml or 'on' not in self.parsed_yml:
            return vulnerable_triggers

        triggers = self.parsed_yml['on']
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

        self._cache['vulnerable_triggers'] = vulnerable_triggers
        self._save_cached_data()
        return vulnerable_triggers

    def backtrack_gate(self, needs_name):
        """Attempts to find if a job needed by a specific job has a gate check."""
        if isinstance(needs_name, list):
            return any(self.backtrack_gate(need) for need in needs_name)

        for job in self.jobs:
            if job.job_name == needs_name:
                if job.gated():
                    return True
                elif not job.gated():
                    return self.backtrack_gate(job.needs)

        return False

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the 'actions/checkout' action with a 'ref' parameter."""
        if 'analyze_checkouts' in self._cache:
            return self._cache['analyze_checkouts']

        job_checkouts = {}
        if 'jobs' not in self.parsed_yml:
            return job_checkouts

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
                    if job_content['gated'] and ('github.event.pull_request.head.sha' in step.metadata.lower() or
                                                 ('sha' in step.metadata.lower() and 'env.' in step.metadata.lower())):
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
                    job_content['confidence'] = 'HIGH' if (job_content['if_check'] and job_content['if_check'].startswith('EVALUATED')) or \
                                                  (bump_confidence and not job_content['if_check']) else 'MEDIUM'

            job_content["check_steps"] = step_details
            job_checkouts[job.job_name] = job_content

        self._cache['analyze_checkouts'] = job_checkouts
        self._save_cached_data()
        return job_checkouts

    def check_pwn_request(self, bypass=False):
        """Check for potential pwn request vulnerabilities."""
        if 'check_pwn_request' in self._cache and not bypass:
            return self._cache['check_pwn_request']

        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

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

        self._cache['check_pwn_request'] = checkout_risk
        self._save_cached_data()
        return checkout_risk

    def check_rules(self, gate_rules):
        """Checks environment protection rules from the API against those specified in the job."""
        for rule in gate_rules:
            for job in self.jobs:
                for deploy_rule in job.deployments:
                    if rule in deploy_rule:
                        return False
        return True

    def check_injection(self, bypass=False):
        """Check for potential script injection vulnerabilities."""
        if 'check_injection' in self._cache and not bypass:
            return self._cache['check_injection']

        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

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
                        if value and type(value) not in [int, float] and '${{' in value:
                            return True
                    return False

                if 'env' in self.parsed_yml and tokens:
                    tokens = [token for token in tokens if check_token(token, self.parsed_yml)]
                if 'env' in job.job_data and tokens:
                    tokens = [token for token in tokens if check_token(token, job.job_data)]
                if 'env' in step.step_data and tokens:
                    tokens = [token for token in tokens if check_token(token, step.step_data)]

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

        self._cache['check_injection'] = injection_risk
        self._save_cached_data()
        return injection_risk

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners."""
        if 'self_hosted' in self._cache:
            return self._cache['self_hosted']

        sh_jobs = []

        if not self.parsed_yml or 'jobs' not in self.parsed_yml or not self.parsed_yml['jobs']:
            return sh_jobs

        for jobname, job_details in self.parsed_yml['jobs'].items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                if 'self-hosted' in runs_on:
                    sh_jobs.append((jobname, job_details))
                elif 'matrix.' in runs_on:
                    matrix_match = self.MATRIX_KEY_EXTRACTION_REGEX.search(runs_on)
                    if matrix_match:
                        matrix_key = matrix_match.group(1)
                        if 'strategy' in job_details and 'matrix' in job_details['strategy']:
                            matrix = job_details['strategy']['matrix']
                            if matrix_key in matrix:
                                os_list = matrix[matrix_key]
                            elif 'include' in matrix:
                                os_list = [inclusion[matrix_key] for inclusion in matrix['include'] if matrix_key in inclusion]
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
                            if label in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] or \
                               self.LARGER_RUNNER_REGEX_LIST.match(label):
                                break
                        else:
                            sh_jobs.append((jobname, job_details))
                    elif isinstance(runs_on, str):
                        if runs_on in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] or \
                           self.LARGER_RUNNER_REGEX_LIST.match(runs_on):
                            continue
                        sh_jobs.append((jobname, job_details))

        self._cache['self_hosted'] = sh_jobs
        self._save_cached_data()
        return sh_jobs