from typing import Optional, Any
from urllib.parse import ParseResult

from cyst.api.environment.external import ResourceImpl, ResourcePersistence
from cyst_platforms.docker_cryton.clients.cryton import Cryton


class CrytonResource(ResourceImpl):
    def __init__(self, address: str, port: int):
        self._persistence: ResourcePersistence | None = None
        self._cryton_client = Cryton(address, port)

    def init(
        self,
        path: ParseResult,
        params: Optional[dict[str, str]] = None,
        persistence: ResourcePersistence = ResourcePersistence.TRANSIENT,
    ) -> bool:
        self._persistence = persistence

        return True

    def configure(self, attackers: dict, ip_lookup: dict):
        self._cryton_client.check_connection()

        for attacker_node, attacker_name in attackers.items():
            self._cryton_client.register_worker(attacker_node, attacker_name, ip_lookup)

    def open(self) -> int:
        pass

    def close(self) -> int:
        pass

    async def send(self, data: str, params: Optional[dict[str, Any]] = None) -> int:
        return 0

    async def receive(self, params: Optional[dict[str, Any]] = None) -> Optional[str]:
        step_execution_id = self._cryton_client.execute_action(params["template"], params["node_id"])
        return await self._cryton_client.wait_for_action_result(step_execution_id)

    @property
    def path(self) -> str:
        return ""

    @property
    def persistence(self) -> ResourcePersistence:
        return self._persistence
