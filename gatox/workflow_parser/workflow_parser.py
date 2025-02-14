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

class WorkflowParser():
    """Parser for YML files.\n\n    This class is structured to take a yaml file as input, it will then\n    expose methods that aim to answer questions about the yaml file.\n\n    This will allow for growing what kind of analytics this tool can perform\n    as the project grows in capability.\n\n    This class should only perform static analysis. The caller is responsible for \n    performing any API queries to augment the analysis.\n    """

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.\n\n        Args:\n            workflow_wrapper (Workflow): Workflow object containing parsed yaml data.\n        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml
        if 'jobs' in self.parsed_yml and self.parsed_yml['jobs'] is not None:
            self.jobs = [Job(job_data, job_name) for job_name, job_data in self.parsed_yml.get('jobs', {}).items()]
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
        return trigger in self.parsed_yml.get('on', {})

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.\n\n        Args:\n            dirpath (str): Directory to save the yaml file to.\n\n        Returns:\n            bool: Whether the file was successfully written.\n        """
        Path(os.path.join(dirpath, f'{self.repo_name}')).mkdir(parents=True, exist_ok=True)

        with open(os.path.join(dirpath, f'{self.repo_name}/{self.wf_name}'), 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True
        
    def extract_referenced_actions(self):
        """\n        Extracts composite actions from the workflow file.\n        """
        referenced_actions = {}
        risky_triggers = self.get_vulnerable_triggers()
        if not risky_triggers:
            return referenced_actions

        for job in self.jobs:
            for step in job.steps:
                if step.type == 'ACTION':
                    action_parts = decompose_action_ref(step.uses, step.step_data, self.repo_name)
                    if action_parts:
                        referenced_actions[step.uses] = action_parts
            
        return referenced_actions

    def get_vulnerable_triggers(self):
        """Analyze if the workflow is set to execute on potentially risky triggers.\n\n        Returns:\n            list: List of triggers within the workflow that could be vulnerable\n            to GitHub Actions script injection vulnerabilities.\n        """
        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 
                          'issue_comment', 'issues', 'discussion_comment', 'discussion'
                          'fork', 'watch']

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
        """Attempts to find if a job needed by a specific job has a gate check.\n        """
        for need in needs_name:
            for job in self.jobs:
                if job.job_name == need and job.gated():
                    return True
                elif job.job_name == need and not job.gated():
                    return self.backtrack_gate(job.needs)
        return False

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the \n        'actions/checkout' action with a 'ref' parameter.\n\n        Returns:\n            job_checkouts: List of 'ref' values within the 'actions/checkout' steps.\n        """
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
                    if_check = step.evaluateIf()   
                    if if_check and if_check.startswith('EVALUATED'):
                        bump_confidence = True
                    elif if_check and 'RESTRICTED' in if_check:
                        bump_confidence = False
                    elif if_check == '':
                        pass
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
        
        checkout_risk = {}
        candidates = {}

        checkout_info = self.analyze_checkouts()
        for job_name, job_content in checkout_info.items():

            steps_risk = job_content['check_steps']
            if steps_risk:
                
                candidates[job_name] = {}
                candidates[job_name]['confidence'] = job_content['confidence']
                candidates[job_name]['gated'] = job_content['gated']
                candidates[job_name]['steps'] = steps_risk
                if 'if_check' in job_content:
                    candidates[job_name]['if_check'] = job_content['if_check']
                else:
                    candidates[job_name]['if_check'] = ''
                
        if candidates:
            checkout_risk['candidates'] = candidates
            checkout_risk['triggers'] = vulnerable_triggers

        return checkout_risk
    
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

                if step.is_script:
                    tokens = step.getTokens()
                else:
                    continue
                tokens = filter_tokens(tokens)
                
                def check_token(token, container):
                    if token.startswith('env.') and token.split('.')[1] in container['env']:
                        value = container['env'][token.split('.')[1]]

                        if value and '${{' in value:
                            return True
                        else:
                            return False
                    return True

                env_sources = [self.parsed_yml, job.job_data, step.step_data]
                for env_source in env_sources:
                    if 'env' in env_source and tokens:
                        tokens = [token for token in tokens if check_token(token, env_source)]
                
                if tokens:
                    if job.needs and self.backtrack_gate(job.needs):
                        break

                    if job.job_name not in injection_risk:
                        injection_risk[job.job_name] = {}
                        injection_risk[job.job_name]['if_check'] = job.evaluateIf()
   
                    injection_risk[job.job_name][step.name] = {
                        "variables": list(set(tokens))
                    }
                    if step.evaluateIf():
                        injection_risk[job.job_name][step.name]['if_checks'] = step.evaluateIf()
        if injection_risk:
            injection_risk['triggers'] = vulnerable_triggers 

        return injection_risk

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.\n\n        Returns:\n           list: List of jobs within the workflow that utilize self-hosted\n           runners.\n        """
        sh_jobs = []

        for jobname, job_details in self.parsed_yml.get('jobs', {}).items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                if 'self-hosted' in runs_on or (isinstance(runs_on, list) and any(label == 'self-hosted' for label in runs_on)):
                    sh_jobs.append((jobname, job_details))

        return sh_jobs