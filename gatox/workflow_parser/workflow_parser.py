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

    LARGER_RUNNER_REGEX_LIST = re.compile(r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb')
    MATRIX_KEY_EXTRACTION_REGEX = re.compile(r'{{\s*matrix\.([\w-]+)\s*}}')

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.\n\n        Args:\n            workflow_yml (str): String containing yaml file read in from\n            repository.\n            repo_name (str): Name of the repository.\n            workflow_name (str): name of the workflow file\n        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml
        
        if 'jobs' in self.parsed_yml and self.parsed_yml['jobs'] is not None:
            self.jobs = [Job(job_data, job_name) for job_name, job_data in self.parsed_yml.get('jobs', []).items()]
        else:
            self.jobs = []  
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

    def is_referenced(self):
        return self.external_ref

    def has_trigger(self, trigger):
        """Check if the workflow has a specific trigger.\n\n        Args:\n            trigger (str): The trigger to check for.\n        Returns:\n            bool: Whether the workflow has the specified trigger.\n        """
        return self.get_vulnerable_triggers(trigger)

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.\n\n        Args:\n            dirpath (str): Directory to save the yaml file to.\n\n        Returns:\n            bool: Whether the file was successfully written.\n        """
        Path(os.path.join(dirpath, f'{self.repo_name}')).mkdir(
            parents=True, exist_ok=True)

        with open(os.path.join(
                dirpath, f'{self.repo_name}/{self.wf_name}'), 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True
        
    def extract_referenced_actions(self):
        """\n        Extracts composite actions from the workflow file.\n        """
        referenced_actions = {}
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers:
            return referenced_actions

        if 'jobs' not in self.parsed_yml:
            return referenced_actions
        
        for job in self.jobs:
            for step in job.steps:
                # Local action referenced
                if step.type == 'ACTION':
                    action_parts = decompose_action_ref(step.uses, step.step_data, self.repo_name)
                    # Save off by uses as key
                    if action_parts:
                        referenced_actions[step.uses] = action_parts
            
        return referenced_actions

    def get_vulnerable_triggers(self, alternate=False):
        """Analyze if the workflow is set to execute on potentially risky triggers.\n\n        Returns:\n            list: List of triggers within the workflow that could be vulnerable\n            to GitHub Actions script injection vulnerabilities.\n        """
        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 
                          'issue_comment', 'issues', 'discussion_comment', 'discussion'
                          'fork', 'watch']
        if alternate:
            risky_triggers = [alternate]

        if not self.parsed_yml or 'on' not in self.parsed_yml:
            return vulnerable_triggers
        triggers = self.parsed_yml['on']
        if isinstance(triggers, list):
            for trigger in triggers:
                if trigger in risky_triggers:
                    vulnerable_triggers.append(trigger)
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger in risky_triggers:
                    if trigger_conditions and 'types' in trigger_conditions:
                        if 'labeled' in trigger_conditions['types'] and \
                            len(trigger_conditions['types']) == 1:
                            vulnerable_triggers.append(f"{trigger}:{trigger_conditions['types'][0]}")
                        else:
                            vulnerable_triggers.append(trigger)
                    else:
                        vulnerable_triggers.append(trigger)

        return vulnerable_triggers

    def backtrack_gate(self, needs_name):
        """Attempts to find if a job needed by a specific job has a gate check.\n        """
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
        """Analyze if any steps within the workflow utilize the \n        'actions/checkout' action with a 'ref' parameter.\n\n        Returns:\n            job_checkouts: List of 'ref' values within the 'actions/checkout' steps.\n        """
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
                # If the step is a gate, exit now, we can't reach the rest of the job.\n                if step.is_gate:\n                    job_content['gated'] = True\n                elif step.is_checkout:\n                    # Check if the dependant jobs are gated.\n                    if job.needs:\n                        job_content['gated'] = self.backtrack_gate(job.needs)\n                    # If the step is a checkout and the ref is pr sha, then no TOCTOU is possible.\n                    if job_content['gated'] and ('github.event.pull_request.head.sha' in step.metadata.lower() \n                                                 or ('sha' in step.metadata.lower() \n                                                 and 'env.' in step.metadata.lower())):\n                        # Break out of this job.\n                        break\n                    else:\n                        if_check = step.evaluateIf()   \n                        if if_check and if_check.startswith('EVALUATED'):\n                            bump_confidence = True\n                        elif if_check and 'RESTRICTED' in if_check:\n                            # In the future, we will exit here.\n                            bump_confidence = False\n                        elif if_check == '':\n                            pass\n                        step_details.append({"ref": step.metadata, "if_check": if_check, "step_name": step.name})\n\n                elif step_details and step.is_sink:\n                    # Confirmed sink, so set to HIGH if reachable via expression parser or no check at all\n                    job_content['confidence'] = 'HIGH' if \
                        (job_content['if_check'] and job_content['if_check'].startswith('EVALUATED')) \
                        or (bump_confidence and not job_content['if_check']) \
                        or (not job_content['if_check'] and (not step.evaluateIf() or step.evaluateIf().startswith('EVALUATED'))) \
                        else 'MEDIUM'\n\n            job_content["check_steps"] = step_details\n            job_checkouts[job.job_name] = job_content\n\n        return job_checkouts\n\n    def check_pwn_request(self, bypass=False):\n        """Check for potential pwn request vulnerabilities.\n\n        Returns:\n            dict: A dictionary containing the job names as keys and a \n            list of potentially vulnerable tokens as values.\n        """\n        vulnerable_triggers = self.get_vulnerable_triggers()\n        if not vulnerable_triggers and not bypass:\n            return {}\n        \n        checkout_risk = {}\n        candidates = {}\n\n        checkout_info = self.analyze_checkouts()\n        for job_name, job_content in checkout_info.items():\n\n            steps_risk = job_content['check_steps']\n            if steps_risk:\n                \n                candidates[job_name] = {}\n                candidates[job_name]['confidence'] = job_content['confidence']\n                candidates[job_name]['gated'] = job_content['gated']\n                candidates[job_name]['steps'] = steps_risk\n                if 'if_check' in job_content and job_content['if_check']:\n                    candidates[job_name]['if_check'] = job_content['if_check']\n                else:\n                    candidates[job_name]['if_check'] = ''\n                \n        if candidates:\n            checkout_risk['candidates'] = candidates\n            checkout_risk['triggers'] = vulnerable_triggers\n\n        return checkout_risk\n    \n    def check_rules(self, gate_rules):\n        """Checks environment protection rules from the API against those specified in the job.\n\n        Args:\n            gate_rules (list): List of rules to check against.\n\n        Returns:\n            bool: Whether the job is violating any of the rules.\n        """\n        for rule in gate_rules:\n            for job in self.jobs:\n                for deploy_rule in job.deployments:\n                    if rule in deploy_rule:\n                        return False\n        return True\n            \n    def check_injection(self, bypass=False):\n        """Check for potential script injection vulnerabilities.\n\n        Returns:\n            dict: A dictionary containing the job names as keys and a list \n            of potentially vulnerable tokens as values.\n        """\n        vulnerable_triggers = self.get_vulnerable_triggers()\n        if not vulnerable_triggers and not bypass:\n            return {}\n\n        injection_risk = {}\n\n        for job in self.jobs:\n\n            for step in job.steps:\n                # No TOCTOU possible for injection\n                if step.is_gate:\n                    break\n\n                # Check if we marked the step as being an injectable script of some kind.\n                if step.is_script:\n                    tokens = step.getTokens()\n                else:\n                    continue\n                tokens = filter_tokens(tokens)\n                \n                def check_token(token, container):\n                    if token.startswith('env.') and token.split('.')[1] in container['env']:\n                        value = container['env'][token.split('.')[1]]\n\n                        if value and type(value) not in [int, float] and '${{' in value:\n                            return True\n                        else:\n                            return False\n                    return True\n                # Remove tokens that map to workflow or job level environment variables, as\n                # these will not be vulnerable to injection unless they reference\n                # something by context expression.\n                env_sources = [self.parsed_yml, job.job_data, step.step_data]\n                for env_source in env_sources:\n                    if 'env' in env_source and tokens:\n                        tokens = [token for token in tokens if check_token(token, env_source)]\n                \n                if tokens:\n                    if job.needs and self.backtrack_gate(job.needs):\n                        break\n\n                    if job.job_name not in injection_risk:\n                        injection_risk[job.job_name] = {}\n                        injection_risk[job.job_name]['if_check'] = job.evaluateIf()\n   \n                    injection_risk[job.job_name][step.name] = {\n                        "variables": list(set(tokens))\n                    }\n                    if step.evaluateIf():\n                        injection_risk[job.job_name][step.name]['if_checks'] = step.evaluateIf()\n        if injection_risk:\n            injection_risk['triggers'] = vulnerable_triggers \n\n        return injection_risk\n\n    def self_hosted(self):\n        """Analyze if any jobs within the workflow utilize self-hosted runners.\n\n        Returns:\n           list: List of jobs within the workflow that utilize self-hosted\n           runners.\n        """\n        sh_jobs = []\n\n        if not self.parsed_yml or 'jobs' not in self.parsed_yml or not self.parsed_yml['jobs']:\n            return sh_jobs\n\n        for jobname, job_details in self.parsed_yml['jobs'].items():\n            if 'runs-on' in job_details:\n                runs_on = job_details['runs-on']\n                if 'self-hosted' in runs_on:\n                    sh_jobs.append((jobname, job_details))\n                elif 'matrix.' in runs_on:\n                    matrix_key = self.extract_matrix_key(runs_on)\n                    if matrix_key:\n                        os_list = self.get_matrix_os_list(job_details, matrix_key)\n                        if any(self.is_self_hosted_os(os) for os in os_list):\n                            sh_jobs.append((jobname, job_details))\n                else:\n                    if isinstance(runs_on, list):\n                        if any(self.is_self_hosted_os(label) for label in runs_on):\n                            sh_jobs.append((jobname, job_details))\n                    elif isinstance(runs_on, str):\n                        if self.is_self_hosted_os(runs_on):\n                            sh_jobs.append((jobname, job_details))\n\n        return sh_jobs\n\n    def extract_matrix_key(self, runs_on):\n        matrix_match = self.MATRIX_KEY_EXTRACTION_REGEX.search(runs_on)\n        return matrix_match.group(1) if matrix_match else None\n\n    def get_matrix_os_list(self, job_details, matrix_key):\n        matrix = job_details.get('strategy', {}).get('matrix', {})\n        if matrix_key in matrix:\n            return matrix[matrix_key]\n        elif 'include' in matrix:\n            return [inclusion[matrix_key] for inclusion in matrix['include'] if matrix_key in inclusion]\n        return []\n\n    def is_self_hosted_os(self, os_label):\n        return os_label not in ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'] and not self.LARGER_RUNNER_REGEX_LIST.match(os_label)