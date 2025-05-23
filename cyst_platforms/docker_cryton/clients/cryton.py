import copy
import yaml
from dataclasses import dataclass
import asyncio
import json
import re
import uuid

from cyst_platforms.docker_cryton.utility import get_request, post_request


@dataclass
class WorkerMetadata:
    id: int
    name: str
    node_id: str
    plan_id: int
    run_id: int
    plan_execution_id: int
    stage_id: int
    stage_execution_id: int
    update_rules: dict[str, str]


class Cryton:
    STEP_FINAL_STATES = ["FINISHED", "ERROR", "FAILED"]
    TEMPLATE = {
        "name": "Dynamic plan equivalent",
        "metadata": {"owner": "CYST",},
        "dynamic": True,
        "stages": {
            "Global stage": {
                "steps": {},
            }
        }
    }

    def __init__(self, address: str, port: int):
        self._api_root = f"http://{address}:{port}/api/"
        self._workers: dict[str, WorkerMetadata] = dict()

    def check_connection(self):
        print("Checking connection to Cryton.. ", end="")
        get_request(self._api_root)
        print("OK")

    def _create_worker(self, name: str, description: str) -> int:
        response = post_request(f"{self._api_root}workers/", data={"name": name, "description": description})

        if response.status_code == 201:
            return response.json()["id"]
        else:
            response = get_request(f"{self._api_root}workers/?name={name}")
            for w in response.json():
                if w["name"] == name:
                    return w["id"]

        raise RuntimeError(f"Unable to set/get Worker with name `{name}`.")

    def _healthcheck_worker(self, worker_id: int):
        response = post_request(f"{self._api_root}workers/{worker_id}/healthcheck/")
        if "UP" in response.json()["detail"]:
            return True

        return False

    def _create_template(self, template: dict) -> int:
        return post_request(f"{self._api_root}templates/", files={"file": yaml.dump(template)}).json()["id"]

    def _create_plan(self, template_id: int) -> int:
        return post_request(f"{self._api_root}plans/", data={"template_id": template_id}).json()["id"]

    def _create_stage(self, template: dict, plan_id: int) -> int:
        return post_request(
            self._api_root + "stages/",
            data={"plan_id": plan_id},
            files={"file": yaml.dump(template)},
        ).json()["id"]

    def _get_stage_id(self, plan_id: int) -> int:
        return get_request(f"{self._api_root}stages/?plan_id={plan_id}").json()[0]["id"]

    def _create_run(self, plan_id: int, worker_ids: list[int]) -> tuple[int, list[int]]:
        r = post_request(f"{self._api_root}runs/", json={"plan_id": plan_id, "worker_ids": worker_ids}).json()
        return r["id"], r["plan_execution_ids"]

    def _execute_run(self, run_id: int):
        if post_request(f"{self._api_root}runs/{run_id}/execute/", data={"run_id": run_id}).status_code != 200:
            raise RuntimeError(f"Unable to execute run {run_id}.")

    def _create_step(self, step: dict, stage_id: int) -> int:
        return post_request(
            f"{self._api_root}steps/", data={"stage_id": stage_id}, files={"file": yaml.dump(step)}
        ).json()["id"]

    def _execute_step(self, step_id: int, stage_execution_id: int) -> int:
        return post_request(
            f"{self._api_root}steps/{step_id}/execute/",
            data={"stage_execution_id": stage_execution_id},
        ).json()["execution_id"]

    def _get_step_state(self, step_execution_id: int):
        return get_request(f"{self._api_root}step_executions/{step_execution_id}/").json()["state"]

    async def _wait_for_step(self, step_execution_id: int):
        while self._get_step_state(step_execution_id) not in self.STEP_FINAL_STATES:
            await asyncio.sleep(1)

    def _get_step_report(self, cryton_step_ex_id: int) -> dict:
        return get_request(f"{self._api_root}step_executions/{cryton_step_ex_id}/report/").json()

    def _get_run_report(self, run_id: int) -> dict:
        return get_request(f"{self._api_root}runs/{run_id}/report/").json()

    def _set_ex_vars(self, plan_ex_id: int, ex_vars: dict) -> None:
        post_request(
            f"{self._api_root}execution_variables/",
            data={"plan_execution_id": plan_ex_id},
            files={"file": json.dumps(ex_vars)},
        )

    @staticmethod
    def _add_update_rules_to_template(step_template: dict, update_rules: dict) -> None:
        inner_template = step_template[next(iter(step_template))]
        if inner_template.get("output") is None:
            inner_template["output"] = dict()
        output_parameter: dict = inner_template["output"]

        if output_parameter.get("replace") is None:
            output_parameter["replace"] = dict()
        update_rules_parameter: dict = output_parameter["replace"]
        update_rules_parameter.update(update_rules)

    @staticmethod
    def _update_template_ips(step_template: dict, update_rules: dict) -> dict:
        converted_step_template = json.dumps(step_template)
        for emulation_ip, simulation_id in update_rules.items():
            converted_step_template = re.sub(simulation_id, emulation_ip, converted_step_template)

        return json.loads(converted_step_template)

    def register_worker(self, node_id: str, worker_name: str, output_update_rules: dict[str, str]):
        print("Registering Cryton Worker.. ", end="")
        worker_id = self._create_worker(
            worker_name,
            f"Worker on node {node_id} used for running actions in the emulated environment.",
        )
        if not self._healthcheck_worker(worker_id):
            raise RuntimeError(f"Worker with ID {worker_id} ({worker_name}) is unreachable.")

        template = copy.deepcopy(self.TEMPLATE)
        template["name"] = f"CYST Plan for Worker {worker_id}"

        template_id = self._create_template(template)
        plan_id = self._create_plan(template_id)
        stage_id = self._get_stage_id(plan_id)
        run_id, plan_ex_ids = self._create_run(plan_id, [worker_id])
        stage_execution_id = self._get_run_report(run_id)["detail"]["plan_executions"][0]["stage_executions"][0]["id"]
        self._execute_run(run_id)

        self._workers[node_id] = WorkerMetadata(
            worker_id,
            worker_name,
            node_id,
            plan_id,
            run_id,
            plan_ex_ids[0],
            stage_id,
            stage_execution_id,
            dict(reversed(sorted(output_update_rules.items(), key=lambda item: len(item[1])))),
        )
        print("OK")

    def create_session(self, node_id, session_id: str):
        print(f"Creating session {session_id} on node {node_id}")
        step_ex_id = self.execute_action({
            f"session-listener-{uuid.uuid4()}": {
                "module": "metasploit",
                "arguments": {
                    "module_name": "multi/handler",
                    "datastore": {"payload": "python/shell_reverse_tcp", "LHOST": "0.0.0.0", "LPORT": 4444},
                },
            }
        }, node_id)
        report = asyncio.run(self.wait_for_action_result(step_ex_id))
        sess_id = report["serialized_output"]["session_id"]

        step_ex_id = self.execute_action({
            f"upgrade-session-{uuid.uuid4()}": {
                "module": "metasploit",
                "arguments": {
                    "module_name": "multi/manage/shell_to_meterpreter",
                    "datastore": {
                        "LHOST": node_id,
                        "SESSION": sess_id,
                    },
                },
            }
        }, node_id)
        report = asyncio.run(self.wait_for_action_result(step_ex_id))
        sess_id = report["serialized_output"]["session_id"]
        self._set_ex_vars(self._workers[node_id].plan_execution_id, {session_id: sess_id})
        print(f"Session {session_id} on node {node_id} created.")

    def execute_action(self, step_template: dict, node_id: str) -> int:
        worker_metadata = self._workers[node_id]

        step_template = self._update_template_ips(step_template, worker_metadata.update_rules)
        self._add_update_rules_to_template(step_template, worker_metadata.update_rules)

        step_id = self._create_step(step_template, worker_metadata.stage_id)
        step_execution_id = self._execute_step(step_id, worker_metadata.stage_execution_id)

        return step_execution_id

    async def wait_for_action_result(self, step_execution_id):
        await self._wait_for_step(step_execution_id)

        return self._get_step_report(step_execution_id)
