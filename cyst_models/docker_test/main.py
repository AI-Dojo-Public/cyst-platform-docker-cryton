from typing import Tuple, Callable, Union, List

from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.message import Request, Response, Status, StatusOrigin, StatusValue
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.action import ActionDescription, ActionParameterType, ActionParameter, Action, ActionType
from cyst.api.logic.behavioral_model import BehavioralModel, BehavioralModelDescription
from cyst.api.logic.composite_action import CompositeActionManager
from cyst.api.network.node import Node

from cyst_platforms.docker_cryton.cryton_utils import Cryton


class DockerTestModel(BehavioralModel):
    def __init__(self, configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                 policy: EnvironmentPolicy, messaging: EnvironmentMessaging,
                 composite_action_manager: CompositeActionManager) -> None:

        self._configuration = configuration
        self._external = resources.external
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging
        self._cam = composite_action_manager

        self._action_store.add(ActionDescription(id="docker_test:action_1",
                                                 type=ActionType.DIRECT,
                                                 platform=PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
                                                 description="A testing message that returns a SERVICE|SUCCESS",
                                                 parameters=[]))

    async def action_flow(self, message: Request) -> Tuple[int, Response]:
        raise RuntimeError("Docker test namespace does not support composite actions")

    async def action_effect(self, message: Request, node: Node) -> Tuple[int, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request, Node], Tuple[int, Response]] = getattr(self, "process_" + action_name, self.process_default)
        return fn(message, node)

    def action_components(self, message: Union[Request, Response]) -> List[Action]:
        # CYST actions are component-less
        return []

    # ------------------------------------------------------------------------------------------------------------------
    def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `cyst` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(message, status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session)

    def process_action_1(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Executing message from a emulation model")

        return 1, self._messaging.create_response(message, status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                  session=message.session, auth=message.auth)


def create_docker_test_model(configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                             policy: EnvironmentPolicy, messaging: EnvironmentMessaging,
                             composite_action_manager: CompositeActionManager) -> BehavioralModel:
    model = DockerTestModel(configuration, resources, policy, messaging, composite_action_manager)
    return model


behavioral_model_description = BehavioralModelDescription(
    namespace="docker_test",
    platform=PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
    description="Testing model for platform development",
    creation_fn=create_docker_test_model
)
