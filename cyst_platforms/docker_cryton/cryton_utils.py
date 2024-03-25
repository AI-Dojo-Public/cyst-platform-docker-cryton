import copy
from typing import Any, Tuple, Dict, List, Type
import requests
import yaml
import time

TEMPLATE = {
    "plan": {
        "name": "Dynamic plan equivalent",
        "owner": "Cryton",
        "dynamic": True,
        "stages": []
    }
}

STAGE_TEMPLATE = {
    "name": "Global stage",
    "trigger_type": "delta",
    "trigger_args": {
        "seconds": 0
    },
    "steps": []
}


def get_request(api_url: str, parameters: dict = None):
    try:
        response = requests.get(api_url, json=parameters)
    except requests.exceptions.ConnectionError:
        return RuntimeError
    except requests.exceptions.HTTPError:
        return RuntimeError
    except requests.exceptions.Timeout:
        return RuntimeError

    print(response.json())
    return response


def post_request(api_url: str, files: dict = None, data: dict = None):
    try:
        response = requests.post(api_url, data=data, files=files)
    except requests.exceptions.ConnectionError:
        raise RuntimeError
    except requests.exceptions.HTTPError:
        raise RuntimeError
    except requests.exceptions.Timeout:
        raise RuntimeError

    print(response.json())
    return response


class Cryton:

    def __init__(self, cryton_core_ip: str, cryton_core_port: int):
        self.cryton_core_ip = cryton_core_ip
        self.cryton_core_port = cryton_core_port
        self.api_root = f"http://{self.cryton_core_ip}:{self.cryton_core_port}/api/"

    def create_worker(self, name: str, description: str) -> int:

        api_response = get_request(api_url=self.api_root + "workers/")

        for worker in api_response.json():
            if "state" not in worker:
                # Worker not yet created
                break

            if worker["name"] == name and worker["state"] == "UP":
                # If the desired worker already exists, there is no need to create it again
                return worker["id"]

            elif worker["name"] == name and worker["state"] == "DOWN":
                # If the desired worker already exists, but in DOWN state, it may be a state after a connection loss
                #  right after creating the worker in the last run.

                # Healthcheck worker ("wake-up" message)
                api_response = post_request(api_url=self.api_root + f"workers/{worker['id']}/healthcheck/")
                if api_response.json()["state"] == "UP":
                    # The worker was able to wake up
                    return worker["id"]

                # Worker cannot wake up, (Cryton may be incorrectly installed)
                return 0

        print("creating worker")

        worker_json = {"name": name, "description": description}
        api_response = requests.post(url=self.api_root + "workers/", data=worker_json)

        worker_id = api_response.json()["id"]

        # Healthcheck worker (Worker will be DOWN otherwise)
        api_response = post_request(api_url=self.api_root + f"workers/{worker_id}/healthcheck/")

        return worker_id

    def create_template(self, template: dict) -> int:
        r_create_template = post_request(f"{self.api_root}templates/", files={"file": yaml.dump(template)})
        return r_create_template.json()["id"]

    def create_plan(self, template_id: int) -> int:
        r_create_plan = post_request(f"{self.api_root}plans/", data={"template_id": template_id})
        return r_create_plan.json()["id"]

    def create_stage(self, template: dict, plan_id: int) -> int:
        r_create_stage = post_request(api_url=self.api_root + "stages/", data={"plan_id": plan_id},
                                      files={"file": yaml.dump(template)})
        return r_create_stage.json()["id"]

    def create_run(self, plan_id: int, worker_ids: List[int]) -> int:
        r_create_run = post_request(f"{self.api_root}runs/",
                                    data={"plan_id": plan_id, "worker_ids": worker_ids})
        return r_create_run.json()["id"]

    def execute_run(self, run_id: int):
        r_execute_run = post_request(f"{self.api_root}runs/{run_id}/execute/", data={"run_id": run_id})
        print(f"Run response: {r_execute_run.text}")

    def create_step(self, step: dict, stage_id: int) -> int:
        r_create_step = post_request(f"{self.api_root}steps/", data={"stage_id": stage_id},
                                     files={"file": yaml.dump(step)})
        print(r_create_step.json())
        step_id = r_create_step.json()["id"]
        print(f"Step id: {step_id}")

        return step_id

    def execute_step(self, step_id: int, stage_execution_id: int) -> int:
        r_execute_step = post_request(f"{self.api_root}steps/{step_id}/execute/",
                                      data={"stage_execution_id": stage_execution_id})
        print(f"Step execution started: {r_execute_step.text}")
        return r_execute_step.json()["execution_id"]

    def wait_for_step(self, step_execution_id: int):
        while get_request(f"{self.api_root}step_executions/{step_execution_id}/").json()["state"] != "FINISHED":
            time.sleep(3)
        print("Step execution finished.")

    def get_action_report(self, cryton_step_ex_id: int) -> dict:
        return get_request(api_url=f"{self.api_root}step_executions/{cryton_step_ex_id}/report/").json()

    def init_new_agent(self, plan_name: str, owner: str, cryton_worker_id: int) -> int:
        """
        Creates Plan, Run, and Executes the Run.
        """
        # 1. Create a template
        template = copy.deepcopy(TEMPLATE)
        template["plan"]["name"] = plan_name
        template["plan"]["owner"] = owner

        template_id = self.create_template(template)
        print(f"Template id: {template_id}")

        # 2. Create a Plan
        plan_id = self.create_plan(template_id)
        print(f"Plan id: {plan_id}")

        # 3. Get Stage ID
        template = copy.deepcopy(STAGE_TEMPLATE)
        template["name"] = owner
        stage_id = self.create_stage(template, plan_id)
        # print(self.stage_id)

        # 4. Create a new Run
        run_id = self.create_run(plan_id, worker_ids=[cryton_worker_id])
        print(f"Run id: {run_id}")

        self.execute_run(run_id)

        return stage_id
    
    def execute_action(self, template: dict, stage_id: int) -> dict:

        stage_ex_id = stage_id

        cryton_step_id = self.create_step(template, stage_id)
        execution_id = self.execute_step(cryton_step_id, stage_ex_id)
        cryton_step_ex_id = execution_id

        self.wait_for_step(execution_id)
        return self.get_action_report(cryton_step_ex_id)
