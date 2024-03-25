import uuid
import time
import os

import requests
import json

from threading import Thread, Lock
from typing import Optional, Union, Any, List, Dict
from netaddr import IPAddress

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.message import Request, Status, Response, Message
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.platform import Platform, PlatformDescription
from cyst.api.environment.platform_interface import PlatformInterface
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.logic.action import Action
from cyst.api.network.session import Session


CRYTON_IP = "127.0.0.1"
CRYTON_PORT = 8001
CRYTON_URL = "http://" + CRYTON_IP + ":" + str(CRYTON_PORT) + "/"


class DockerCrytonPlatform(Platform, EnvironmentMessaging):

    def __init__(self, platform_interface: PlatformInterface, configuration: EnvironmentConfiguration, messaging: EnvironmentMessaging, resources: EnvironmentResources):
        self._platform_interface = platform_interface
        self._configuration = configuration
        self._messaging = messaging
        self._resources = resources

        self._processing_thread: Optional[Thread] = None
        self._processing_lock = Lock()
        self._message_queue = None
        self._requests: Dict[int, Message] = {}

        self._terminate = False

        # Set environment variables
        os.environ["CYST_PLATFORM_CRYTON_IP"] = CRYTON_IP
        os.environ["CYST_PLATFORM_CRYTON_PORT"] = str(CRYTON_PORT)
        os.environ["CYST_PLATFORM_CRYTON_URL"] = CRYTON_URL

    def init(self) -> bool:
        self._processing_thread = Thread(target=self._message_processor, daemon=True)
        self._processing_thread.start()
        return True

    def terminate(self) -> bool:
        self._terminate = True
        self._processing_thread.join()
        return True

    def configure(self, *config_item: ConfigItem) -> 'Platform':
        config = self._configuration.general.save_configuration(indent=1)

        data = {
            "name": "demo",
            "description": str(config)
        }

        print("Creating Template")
        template = requests.post('http://127.0.0.1:8000/templates/create/', data=json.dumps(data))
        if template.status_code != 201:
            raise RuntimeError(f"message: {template.text}, code: {template.status_code}")
        else:
            print("Template created successfully")
            template_id = template.json()["id"]

        data = {
            "name": "run-" + str(uuid.uuid4()),
            "template_id": template_id,
            "agent_ids": [
                1
            ]
        }

        print("Creating Run")
        run = requests.post('http://127.0.0.1:8000/runs/create/', data=json.dumps(data))
        if run.status_code != 201:
            raise RuntimeError(f"message: {run.text}, code: {run.status_code}")
        else:
            print("Run created successfully")
            run_id = run.json()["id"]

        print("Running the stuff")
        run_start = requests.get(f"http://127.0.0.1:8000/runs/start/{run_id}/")
        if run_start.status_code != 200:
            raise RuntimeError(f"message: {run_start.text}, code: {run_start.status_code}")
        else:
            print("Everything started successfully")
        return self

    @property
    def messaging(self) -> EnvironmentMessaging:
        return self

    @property
    def resources(self) -> EnvironmentResources:
        return self._resources

    def collect_messages(self) -> List[Message]:
        pass

    # Environment messaging
    def send_message(self, message: Message, delay: int = 0) -> None:
        print("Sending message in a platform")
        self._requests[message.id] = message
        # Sending is realized just through the action
        self._platform_interface.execute_request(message.cast_to(Request))

    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "", action: Optional[Action] = None, session: Optional[Session] = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None, original_request: Optional[Request] = None) -> Request:
        print("Creating request in a platform")
        return self._messaging.create_request(dst_ip, dst_service, action, session, auth, original_request)

    def create_response(self, request: Request, status: Status, content: Optional[Any] = None,
                        session: Optional[Session] = None, auth: Optional[Union[Authorization, AuthenticationTarget]] = None,
                        original_response: Optional[Response] = None) -> Response:
        print("Creating response in a platform")
        return self._messaging.create_response(request, status, content, session, auth, original_response)

    def open_session(self, request: Request) -> Session:
        pass

    def _message_processor(self) -> None:
        while not self._terminate:
            # Get status of all requests
            # requests_status = requests.get(CRYTON_URL + "step_executions/").json()
            # print(requests_status)
            # Convert Cryton responses to CYST responses
            # Push responses into the queue
            # with self._processing_lock:
            #     print("Locked part")
            # Let the computer rest
            time.sleep(1)


def create_platform(platform_interface: PlatformInterface, configuration: EnvironmentConfiguration,
                    messaging: EnvironmentMessaging, resources: EnvironmentResources) -> DockerCrytonPlatform:
    p = DockerCrytonPlatform(platform_interface, configuration, messaging, resources)
    return p


platform_description = PlatformDescription(
    specification=PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
    description="A platform using the Docker emulation for infrastructure creation and Cryton for action execution",
    creation_fn=create_platform
)
