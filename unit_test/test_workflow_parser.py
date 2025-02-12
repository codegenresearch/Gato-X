import pytest
import os
import pathlib

from unittest.mock import patch, ANY, mock_open

from gatox.workflow_parser.workflow_parser import WorkflowParser
from gatox.models.workflow import Workflow
from gatox.workflow_parser.utility import check_sus

TEST_WF = """\nname: 'Test WF'\n\non:\n  pull_request_target:\n  workflow_dispatch:\n\njobs:\n  test:\n    runs-on: ['self-hosted']\n    steps:\n\n    - name: Execution\n      run: |\n          echo "Hello World and bad stuff!"\n"""

TEST_WF2 = """\nname: 'Test WF2'\n\non:\n  pull_request_target:\n\njobs:\n  test:\n    runs-on: 'ubuntu-latest'\n    steps:\n    - name: Execution\n      uses: actions/checkout@v4\n      with:\n        ref: ${{ github.event.pull_request.head.ref }}\n"""

TEST_WF3 = """\nname: Update Snapshots\non:\n  issue_comment:\n    types: [created]\njobs:\n  updatesnapshots:\n    if: ${{ github.event.issue.pull_request && github.event.comment.body == '/update-snapshots'}}\n    timeout-minutes: 20\n    runs-on: macos-latest\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          fetch-depth: 0\n          token: ${{ secrets.GITHUB_TOKEN }}\n      - name: Get SHA and branch name\n        id: get-branch-and-sha\n        run: |\n          sha_and_branch=$(\
            curl \
              -H 'authorization: Bearer ${{ secrets.GITHUB_TOKEN }}' \
              https://api.github.com/repos/${{ github.repository }}/pulls/${{ github.event.issue.number }} \
            | jq -r '.head.sha," ",.head.ref');\n          echo "sha=$(echo $sha_and_branch | cut -d " " -f 1)" >> $GITHUB_OUTPUT\n          echo "branch=$(echo $sha_and_branch | cut -d " " -f 2)" >> $GITHUB_OUTPUT\n      - name: Fetch Branch\n        run: git fetch\n      - name: Checkout Branch\n        run: git checkout ${{ steps.get-branch-and-sha.outputs.branch }}\n      - uses: actions/setup-node@v3\n        with:\n          node-version: '19'\n      - name: Install dependencies\n        run: yarn\n      - name: Install Playwright browsers\n        run: npx playwright install --with-deps chromium\n      - name: Update snapshots\n        env:\n          VITE_TENDERLY_ACCESS_KEY: ${{ secrets.VITE_TENDERLY_ACCESS_KEY }}\n          VITE_CHAIN_RPC_URL: ${{ secrets.VITE_CHAIN_RPC_URL }}\n          CI: true\n        run: npx playwright test --update-snapshots --reporter=list\n      - uses: stefanzweifel/git-auto-commit-action@v4\n        with:\n          commit_message: '[CI] Update Snapshots'\n"""

TEST_WF4 = """\nname: Benchmarks\non:\n  issue_comment:\n    types: [created]\njobs:\n  check-permission:\n    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/bench')\n    runs-on: ubuntu-latest\n    steps:\n    - name: Check permission\n      uses: actions/github-script@v6\n      with:\n        result-encoding: string\n        script: |\n          const response = await github.rest.repos.getCollaboratorPermissionLevel({\n            owner: context.repo.owner,\n            repo: context.repo.repo,\n            username: context.actor\n          });\n\n          const actorPermissionLevel = response.data.permission;\n          console.log(actorPermissionLevel);\n\n          // <- lower higher ->\n          // ["none", "read", "write", "admin"]\n          if (!(actorPermissionLevel == "admin" || actorPermissionLevel == "write")) {\n            core.setFailed("Permission denied.");\n          }\n\n  benchmarks:\n    # run only when PR comments start with '/bench'.\n    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/bench')\n    needs: check-permission\n    runs-on: [self-hosted, Linux, X64]\n    steps:\n    - name: Validate and set inputs\n      id: bench-input\n      uses: actions/github-script@v6\n      with:\n        result-encoding: string\n        script: |\n          const command = `${{ github.event.comment.body }}`.split(" ");\n          console.log(command);\n\n          // command should be '/bench chain_name pallets'\n          if (command.length != 3) {\n            core.setFailed("Invalid input. It should be '/bench [chain_name] [pallets]'");\n          }\n\n          core.setOutput("chain", command[1]);\n          core.setOutput("pallets", command[2]);\n\n    - name: Free disk space\n      run: |\n        sudo rm -rf /usr/share/dotnet\n        sudo rm -rf /usr/local/lib/android\n        sudo rm -rf /opt/ghc\n        sudo rm -rf "/usr/local/share/boost"\n        sudo rm -rf "$AGENT_TOOLSDIRECTORY"\n        df -h\n\n    - name: Get branch and sha\n      id: get_branch_sha\n      uses: actions/github-script@v6\n      with:\n        github-token: ${{secrets.GITHUB_TOKEN}}\n        result-encoding: string\n        script: |\n          const pull_request = await github.rest.pulls.get({\n            owner: context.repo.owner,\n            repo: context.repo.repo,\n            pull_number: context.issue.number\n          })\n\n          core.setOutput("branch", pull_request.data.head.ref)\n          core.setOutput("sha", pull_request.data.head.sha)\n\n    - name: Post starting comment\n      uses: actions/github-script@v6\n      env:\n        MESSAGE: |\n          Benchmarks job is scheduled at ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}.\n          Please wait for a while.\n          Branch: ${{ steps.get_branch_sha.outputs.branch }}\n          SHA: ${{ steps.get_branch_sha.outputs.sha }}\n      with:\n        github-token: ${{secrets.GITHUB_TOKEN}}\n        result-encoding: string\n        script: |\n          github.rest.issues.createComment({\n            issue_number: context.issue.number,\n            owner: context.repo.owner,\n            repo: context.repo.repo,\n            body: process.env.MESSAGE\n          })\n\n    - name: Checkout the source code\n      uses: actions/checkout@v3\n      with:\n        ref: ${{ steps.get_branch_sha.outputs.sha }}\n        submodules: true\n\n    - name: Install deps\n      run: sudo apt -y install protobuf-compiler\n\n    - name: Install & display rust toolchain\n      run: rustup show\n\n    - name: Check targets are installed correctly\n      run: rustup target list --installed\n\n    - name: Execute benchmarking\n      run: |\n        mkdir -p ./benchmark-results\n        chmod +x ./scripts/run_benchmarks.sh\n        ./scripts/run_benchmarks.sh -o ./benchmark-results -c ${{ steps.bench-input.outputs.chain }} -p ${{ steps.bench-input.outputs.pallets }}\n"""

TEST_WF5 = """\nname: 'Test WF5'\n\non:\n  pull_request_target:\n\njobs:\n"""


TEST_WF6 = """\nname: 'Test WF6'\n\non:\n  pull_request_target:\n\njobs:\n  steps:\n    - name: Execution\n      uses: actions/checkout@v4\n"""


def test_parse_workflow():

    workflow = Workflow('unit_test', TEST_WF, 'main.yml')
    parser = WorkflowParser(workflow)

    sh_list = parser.self_hosted()

    assert len(sh_list) > 0


def test_workflow_write():

    workflow = Workflow('unit_test', TEST_WF, 'main.yml')
    parser = WorkflowParser(workflow)

    curr_path = pathlib.Path(__file__).parent.resolve()
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    with patch("builtins.open", mock_open(read_data="")) as mock_file:
        parser.output(test_repo_path)

        mock_file().write.assert_called_once_with(
            parser.raw_yaml
        )

def test_check_injection_no_vulnerable_triggers():
    workflow = Workflow('unit_test', TEST_WF, 'main.yml')
    parser = WorkflowParser(workflow)

    with patch.object(parser, 'get_vulnerable_triggers', return_value=[]):
        result = parser.check_injection()
        assert result == {}

def test_check_injection_no_job_contents():
    workflow = Workflow('unit_test', TEST_WF5, 'main.yml')
    parser = WorkflowParser(workflow)


    result = parser.check_injection()
    assert result == {}

def test_check_injection_no_step_contents():
    workflow = Workflow('unit_test', TEST_WF6, 'main.yml')
    parser = WorkflowParser(workflow)

    result = parser.check_injection()
    assert result == {}

def test_check_injection_comment():
    workflow = Workflow('unit_test', TEST_WF3, 'main.yml')
    parser = WorkflowParser(workflow)

    result = parser.check_injection()
    assert 'updatesnapshots' in result

def test_check_injection_no_tokens():
    workflow = Workflow('unit_test', TEST_WF, 'main.yml')
    parser = WorkflowParser(workflow)
  
    result = parser.check_injection()
    assert result == {}

def test_check_pwn_request():
    workflow = Workflow('unit_test', TEST_WF4, 'benchmark.yml')
    parser = WorkflowParser(workflow)

    result = parser.check_pwn_request()
    assert result['candidates']