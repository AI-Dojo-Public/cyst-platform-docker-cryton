import os
import time

from datetime import datetime
from heapq import heappush, heappop
from netaddr import IPAddress
from typing import Optional, Union, Any, List, Tuple, Callable

from cyst.api.environment.clock import Clock
from cyst.api.host.service import ActiveService

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.environment.configuration import EnvironmentConfiguration, GeneralConfiguration, ExploitConfiguration, \
    ActionConfiguration
from cyst.api.environment.infrastructure import EnvironmentInfrastructure
from cyst.api.environment.message import Request, Status, Response, Message, MessageType
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.platform import Platform, PlatformDescription
from cyst.api.environment.platform_interface import PlatformInterface
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.logic.action import Action
from cyst.api.logic.metadata import Metadata
from cyst.api.network.session import Session
from cyst.api.utils.counter import Counter

from cyst_platforms.docker_cryton.configuration import EnvironmentConfigurationImpl, GeneralConfigurationImpl
from cyst_platforms.docker_cryton.message import RequestImpl, ResponseImpl


CRYTON_IP = "127.0.0.1"
CRYTON_PORT = 8001
CRYTON_URL = "http://" + CRYTON_IP + ":" + str(CRYTON_PORT) + "/"


class DockerCrytonPlatform(Platform, EnvironmentMessaging, Clock):

    def __init__(self, platform_interface: PlatformInterface, general_configuration: GeneralConfiguration,
                 resources: EnvironmentResources, action_configuration: ActionConfiguration,
                 exploit_configuration: ExploitConfiguration, infrastructure: EnvironmentInfrastructure):

        self._platform_interface = platform_interface
        self._infrastructure = infrastructure
        self._resources = resources

        self._environment_configuration = EnvironmentConfigurationImpl()
        self._environment_configuration.action = action_configuration
        self._environment_configuration.exploit = exploit_configuration
        self._environment_configuration.general = GeneralConfigurationImpl(self, general_configuration, self._infrastructure)

        self._message_queue = None
        self._requests: List[Tuple[float, int, Message]] = []

        self._terminate = False

        # Set environment variables
        os.environ["CYST_PLATFORM_CRYTON_IP"] = CRYTON_IP
        os.environ["CYST_PLATFORM_CRYTON_PORT"] = str(CRYTON_PORT)
        os.environ["CYST_PLATFORM_CRYTON_URL"] = CRYTON_URL

    def init(self) -> bool:
        return True

    def terminate(self) -> bool:
        return True

    def configure(self, *config_item: ConfigItem) -> 'Platform':
        c = GeneralConfigurationImpl.cast_from(self._environment_configuration.general)
        c.configure(*config_item)
        return self

    @property
    def messaging(self) -> EnvironmentMessaging:
        return self

    # ------------------------------------------------------------------------------------------------------------------
    # Environment messaging
    def send_message(self, message: Message, delay: int = 0) -> None:
        print("Sending message in a platform")

        # Message should already have a caller_id in it. Add run_id to it to enable correct worker selection
        run_id = self._infrastructure.runtime_configuration.run_id
        message.platform_specific["caller_id"] = run_id + "." + message.platform_specific["caller_id"]

        # Push it to request queue, from which it will be extracted in the process loop
        heappush(self._requests, (self.current_time() + delay, message.id, message))

    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "", action: Optional[Action] = None, session: Optional[Session] = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None, original_request: Optional[Request] = None) -> Request:
        print("Creating request in a platform")
        # TODO: How to get the src ip? Src service is obtained when the message is sent and available in a
        #       Message.platform_specific property.
        if isinstance(dst_ip, str):
            dst_ip = IPAddress(dst_ip)

        # TODO: Fill in data from original_request

        request = RequestImpl(dst_ip, dst_service, action, session, auth, original_request)
        return request

    def create_response(self, request: Request, status: Status, content: Optional[Any] = None,
                        session: Optional[Session] = None, auth: Optional[Union[Authorization, AuthenticationTarget]] = None,
                        original_response: Optional[Response] = None) -> Response:
        print("Creating response in a platform")

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

    def timeout(self, callback: Union[ActiveService, Callable[[Message], Tuple[bool, int]]], delay: float, parameter: Any = None) -> None:
        # TODO
        pass

    # ------------------------------------------------------------------------------------------------------------------
    @property
    def configuration(self) -> EnvironmentConfiguration:
        return self._environment_configuration

    async def process(self, time: int) -> bool:
        current_time = self.current_time()
        have_something_to_do = False

        # Dispatch all requests, whose time has came. Responses are managed through the behavioral models, so no big
        # deal here.
        requests_to_process = []
        if self._requests:
            have_something_to_do = True
            timeout, _, _ = self._requests[0]
            while timeout <= current_time:
                _, _, message = heappop(self._requests)
                requests_to_process.append(message)
                if self._requests:
                    timeout, _, _ = self._requests[0]
                else:
                    break

        for request in requests_to_process:
            self._platform_interface.execute_task(request)

        return have_something_to_do


def create_platform(platform_interface: PlatformInterface, general_configuration: GeneralConfiguration,
                    resources: EnvironmentResources, action_configuration: ActionConfiguration,
                    exploit_configuration: ExploitConfiguration, infrastructure: EnvironmentInfrastructure) -> DockerCrytonPlatform:
    p = DockerCrytonPlatform(platform_interface, general_configuration, resources, action_configuration,
                             exploit_configuration, infrastructure)
    return p


platform_description = PlatformDescription(
    specification=PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
    description="A platform using the Docker emulation for infrastructure creation and Cryton for action execution",
    creation_fn=create_platform
)
