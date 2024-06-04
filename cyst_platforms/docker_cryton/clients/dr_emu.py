import uuid

from cyst_platforms.docker_cryton.utility import get_request, post_request


class DrEmu:
    def __init__(self, host: str, port: int):
        self._api_url = f"http://{host}:{port}/"
        self._template_id: int | None = None
        self._run_id: int | None = None

    def check_connection(self):
        print("Checking connection to Dr Emu.. ", end="")
        get_request(self._api_url)
        print("OK")

    def _create_template(self, configuration: str):
        data = {"name": "demo", "description": configuration}
        response = post_request(f"{self._api_url}templates/create/", json=data)

        if response.status_code != 201:
            raise RuntimeError(f"message: {response.text}, code: {response.status_code}")

        self._template_id = response.json()["id"]

    def _create_run(self):
        data = {"name": f"run-{uuid.uuid4()}", "template_id": self._template_id}
        response = post_request(f"{self._api_url}runs/create/", json=data)

        if response.status_code != 201:
            raise RuntimeError(f"message: {response.text}, code: {response.status_code}")

        self._run_id = response.json()["id"]

    def _start_run(self):
        response = post_request(f"{self._api_url}runs/start/{self._run_id}/")

        if response.status_code != 200:
            raise RuntimeError(f"message: {response.text}, code: {response.status_code}")

    def _stop_run(self):
        response = post_request(f"{self._api_url}runs/stop/{self._run_id}/")

        if response.status_code != 200:
            raise RuntimeError(f"message: {response.text}, code: {response.status_code}")

    def _get_infrastructure_information(self) -> tuple[dict[str, str], dict[str, str]]:
        # Only one infrastructure per run is supported
        infrastructure_id = get_request(f"{self._api_url}runs/get/{self._run_id}/").json()["infrastructure_ids"][0]
        infrastructure_info = get_request(f"{self._api_url}infrastructures/get/{infrastructure_id}/").json()
        infrastructure_networks = infrastructure_info["networks"]
        infrastructure_attackers = infrastructure_info["attackers"]  # node_id: worker_name

        ip_lookup: dict[str, str] = dict()
        for network in infrastructure_networks:
            add_network_ip = True
            for appliance in network["appliances"]:
                appliance_emulation_ip: str = appliance["ip"]
                appliance_simulation_ip: str = appliance["original_ip"]
                if appliance_simulation_ip == "None":
                    continue
                ip_lookup[appliance_emulation_ip] = appliance_simulation_ip

                if add_network_ip:
                    add_network_ip = False
                    network_emulation_ip = f'{appliance_emulation_ip.rsplit(".", 1)[0]}.0'
                    network_simulation_ip = f'{appliance_simulation_ip.rsplit(".", 1)[0]}.0'
                    ip_lookup[network_emulation_ip] = network_simulation_ip

        # parse attackers to match the cyst infrastructure
        parsed_attackers: dict[str, str] = dict()
        for attacker_node, attacker_name in infrastructure_attackers.items():
            stripped_node_id = attacker_node.split("-", 1)
            node_id = stripped_node_id[0] if len(stripped_node_id) == 1 else stripped_node_id[1]
            parsed_attackers[node_id] = attacker_name

        return ip_lookup, parsed_attackers

    def configure(self, configuration: str):
        self.check_connection()
        print("Emulation preparation (template).. ", end="")
        self._create_template(configuration)
        print("OK")
        print("Emulation preparation (run).. ", end="")
        self._create_run()
        print("OK")
        print("Starting emulation.. ", end="")
        self._start_run()
        print("OK")

        return self._get_infrastructure_information()

    def terminate(self):
        print("Stopping emulation.. ", end="")
        self._stop_run()
        print("OK")
