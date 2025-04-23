import os
import time

from datetime import datetime
from heapq import heappush, heappop

from cyst.api.configuration import SessionConfig
from cyst.api.environment.external import ResourcePersistence
from netaddr import IPAddress
from typing import Optional, Union, Any, List, Tuple, Callable

from cyst.api.environment.clock import Clock
from cyst.api.host.service import ActiveService

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.environment.configuration import (
    EnvironmentConfiguration,
    GeneralConfiguration,
    ExploitConfiguration,
    ActionConfiguration,
    PhysicalConfiguration,
)
from cyst.api.environment.infrastructure import EnvironmentInfrastructure
from cyst.api.environment.message import Request, Status, Response, Message, MessageType, Timeout
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.platform import Platform, PlatformDescription
from cyst.api.environment.platform_interface import PlatformInterface
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.logic.action import Action
from cyst.api.network.session import Session


from cyst_platforms.docker_cryton.configuration import EnvironmentConfigurationImpl, GeneralConfigurationImpl
from cyst_platforms.docker_cryton.host.service import ServiceImpl
from cyst_platforms.docker_cryton.message import RequestImpl, ResponseImpl, TimeoutImpl
from cyst_platforms.docker_cryton.cryton_resource import CrytonResource
from cyst_platforms.docker_cryton.clients.dr_emu import DrEmu


class DockerCrytonPlatform(Platform, EnvironmentMessaging, Clock):

    def collect_messages(self) -> List[Message]:
        pass

    def __init__(
        self,
        platform_interface: PlatformInterface,
        general_configuration: GeneralConfiguration,
        resources: EnvironmentResources,
        action_configuration: ActionConfiguration,
        exploit_configuration: ExploitConfiguration,
        infrastructure: EnvironmentInfrastructure,
        physical_configuration: PhysicalConfiguration,
        platform_type: PlatformType,
    ):

        self._platform_interface = platform_interface
        self._infrastructure = infrastructure
        self._resources = resources
        self._platform_type = platform_type

        self._environment_configuration = EnvironmentConfigurationImpl()
        self._environment_configuration.action = action_configuration
        self._environment_configuration.exploit = exploit_configuration
        self._environment_configuration.general = GeneralConfigurationImpl(
            self, general_configuration, self._infrastructure
        )
        self._environment_configuration.physical = physical_configuration

        self._message_queue = None
        self._messages: List[Tuple[float, int, Message]] = []

        self._terminate = False

        self._dr_emu_client = DrEmu(
            os.environ.get("CYST_PLATFORM_DR_EMU_IP", "127.0.0.1"), os.environ.get("CYST_PLATFORM_DR_EMU_PORT", 8000)
        )
        self._cryton_resource = CrytonResource(
            os.environ.get("CYST_PLATFORM_CRYTON_IP", "127.0.0.1"), os.environ.get("CYST_PLATFORM_CRYTON_PORT", 8001)
        )

    def init(self) -> bool:
        self._resources.external.register_resource("cryton", self._cryton_resource)
        self._resources.external.create_resource("cryton://", persistence=ResourcePersistence.PERSISTENT)

        return True

    def terminate(self) -> bool:
        self._dr_emu_client.terminate()

        return True

    def configure(self, *config_item: ConfigItem) -> "Platform":
        c: GeneralConfigurationImpl = GeneralConfigurationImpl.cast_from(self._environment_configuration.general)
        c.configure(*config_item)

        config = c.save_configuration(1)
        ip_lookup, attackers = self._dr_emu_client.configure(config)
        self._cryton_resource.configure(attackers, ip_lookup)

        for session in [c for c in config_item if isinstance(c, SessionConfig)]:
            self._cryton_resource.client.create_session(session.waypoints[0], session.id)

        return self

    @property
    def messaging(self) -> EnvironmentMessaging:
        return self

    # ------------------------------------------------------------------------------------------------------------------
    # Environment messaging
    def send_message(self, message: Message, delay: int = 0) -> None:
        # print("Sending message in a platform")

        # Message should already have a caller_id in it. Add run_id to it to enable correct worker selection
        run_id = self._infrastructure.runtime_configuration.run_id
        message.platform_specific["run_id"] = run_id

        # Push it to request queue, from which it will be extracted in the process loop
        heappush(self._messages, (self.current_time() + delay, message.id, message))

    def create_request(
        self,
        dst_ip: Union[str, IPAddress],
        dst_service: str = "",
        action: Optional[Action] = None,
        session: Optional[Session] = None,
        auth: Optional[Union[Authorization, AuthenticationToken]] = None,
        original_request: Optional[Request] = None,
    ) -> Request:
        # print("Creating request in a platform")
        # TODO: How to get the src ip? Src service is obtained when the message is sent and available in a
        #       Message.platform_specific property.
        if isinstance(dst_ip, str):
            dst_ip = IPAddress(dst_ip)

        # TODO: Fill in data from original_request

        request = RequestImpl(dst_ip, dst_service, action, session, auth, original_request)
        return request

    def create_response(
        self,
        request: Request,
        status: Status,
        content: Optional[Any] = None,
        session: Optional[Session] = None,
        auth: Optional[Union[Authorization, AuthenticationTarget]] = None,
        original_response: Optional[Response] = None,
    ) -> Response:
        # print("Creating response in a platform")

        response = ResponseImpl(RequestImpl.cast_from(request), status, content, session, auth, original_response)

        return response

    def open_session(self, request: Request) -> Session:
        # TODO
        pass

    # ------------------------------------------------------------------------------------------------------------------

    # ------------------------------------------------------------------------------------------------------------------
    # Clock
    @property
    def clock(self) -> Clock:
        return self

    def current_time(self) -> float:
        return time.time()

    def real_time(self) -> datetime:
        return datetime.now()

    def timeout(
        self, callback: Union[ActiveService, Callable[[Message], Tuple[bool, int]]], delay: float, parameter: Any = None
    ) -> None:
        timeout = TimeoutImpl(callback, self.current_time(), delay, parameter)
        self.send_message(timeout, int(delay))

    # ------------------------------------------------------------------------------------------------------------------
    @property
    def configuration(self) -> EnvironmentConfiguration:
        return self._environment_configuration

    async def process(self, time: int) -> bool:
        current_time = self.current_time()
        have_something_to_do = False

        requests_to_process = []
        responses_to_process = []

        if self._messages:
            have_something_to_do = True

            timeout, _, _ = self._messages[0]
            while timeout <= current_time:
                _, _, message = heappop(self._messages)

                if message.type == MessageType.REQUEST:
                    requests_to_process.append(message)
                elif message.type == MessageType.RESPONSE:
                    responses_to_process.append(message)
                elif message.type == MessageType.TIMEOUT:
                    timeout = TimeoutImpl.cast_from(message.cast_to(Timeout))
                    timeout.callback(message)

                if self._messages:
                    timeout, _, _ = self._messages[0]
                else:
                    break

        for response in responses_to_process:
            if isinstance(response, Response):  # This is here to shut up pycharm type control
                r = ResponseImpl.cast_from(response)
                s = ServiceImpl(self.configuration.general.get_object_by_id(response.platform_specific["caller_id"], ActiveService))
                self._platform_interface.execute_task(r, s)

        for request in requests_to_process:
            self._platform_interface.execute_task(request)

        return have_something_to_do


def create_platform(
    platform_interface: PlatformInterface,
    general_configuration: GeneralConfiguration,
    resources: EnvironmentResources,
    action_configuration: ActionConfiguration,
    exploit_configuration: ExploitConfiguration,
    physical_configuration: PhysicalConfiguration,
    infrastructure: EnvironmentInfrastructure,
) -> DockerCrytonPlatform:
    p = DockerCrytonPlatform(
        platform_interface,
        general_configuration,
        resources,
        action_configuration,
        exploit_configuration,
        infrastructure,
        physical_configuration,
        PlatformType.REAL_TIME,
    )
    return p


platform_description = PlatformDescription(
    specification=PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
    description="A platform using the Docker emulation for infrastructure creation and Cryton for action execution",
    creation_fn=create_platform,
)
