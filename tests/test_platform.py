import unittest
from typing import Tuple, Callable, Union, List, Coroutine, Any

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

from netaddr import IPAddress, IPNetwork
from cyst.api.configuration import (
    AuthenticationProviderConfig,
    PassiveServiceConfig,
    AccessSchemeConfig,
    AuthorizationDomainConfig,
    AuthorizationDomainType,
    AuthorizationConfig,
    NodeConfig,
    InterfaceConfig,
    ActiveServiceConfig,
    RouterConfig,
    ConnectionConfig,
    FirewallConfig,
    FirewallChainConfig,
    ExploitConfig,
    ExploitCategory,
    ExploitLocality,
    VulnerableServiceConfig,
    DataConfig,
)  # , PortConfig

from cyst.api.host.service import ActiveService
from cyst.api.environment.configuration import ServiceParameter
from cyst.api.logic.access import (
    AccessLevel,
    AuthenticationProviderType,
    AuthenticationTokenType,
    AuthenticationTokenSecurity,
)
from cyst.api.network.firewall import FirewallPolicy, FirewallChainType, FirewallRule
from cyst.api.environment.environment import Environment
from cyst_services.scripted_actor.main import ScriptedActorControl


# ----------------------------------------------------------------------------------------------------------------------
# Model
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
        fn: Callable[[Request, Node], Coroutine[Any, Any, Tuple[int, Response]]] = getattr(self, "process_" + action_name, self.process_default)
        return await fn(message, node)

    def action_components(self, message: Union[Request, Response]) -> List[Action]:
        # CYST actions are component-less
        return []

    # ------------------------------------------------------------------------------------------------------------------
    async def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `docker_test` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(message, status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session)

    async def process_action_1(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Executing message from a emulation model")

        return 1, self._messaging.create_response(message, status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                  session=message.session, auth=message.auth)


# ----------------------------------------------------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
# Scripted attacker
# - used for scenarios 2 and 3
# - represents Cryton's scripting functionality
# -----------------------------------------------------------------------------
scripted_attacker = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            "scripted_actor",
            "scripted_attacker",
            "attacker",
            AccessLevel.LIMITED,
            id="scripted_attacker_service"
        )
    ],
    passive_services=[
        PassiveServiceConfig(
            type="jtr",
            owner="jtr",
            version="1.9.0",
            local=True,
            access_level=AccessLevel.LIMITED
        ),
        PassiveServiceConfig(
            type="empire",
            owner="empire",
            version="4.10.0",
            local=True,
            access_level=AccessLevel.LIMITED
        ),
        PassiveServiceConfig(
            type="msf",
            owner="msf",
            version="1.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.11"), IPNetwork("192.168.2.0/24"))],
    shell="",
    id="attacker_node",
)

# -----------------------------------------------------------------------------
# Local password authentication template
# -----------------------------------------------------------------------------
local_password_auth = AuthenticationProviderConfig(
    provider_type=AuthenticationProviderType.LOCAL,
    token_type=AuthenticationTokenType.PASSWORD,
    token_security=AuthenticationTokenSecurity.SEALED,
    timeout=30,
)

# -----------------------------------------------------------------------------
# Wordpress server
# - used for scenarios 2, 3, and 4
# -----------------------------------------------------------------------------
wordpress_srv = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="wordpress_app",
            owner="wordpress",
            version="6.1.1",
            local=False,
            access_level=AccessLevel.LIMITED,
            authentication_providers=[local_password_auth("wordpress_app_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["wordpress_app_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("wordpress", AccessLevel.ELEVATED)],
                    ),
                )
            ],
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.11"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="wordpress_app_node",
)

wordpress_db = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="wordpress_db",
            owner="mysql",
            version="8.0.31",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.10"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="wordpress_db_node",
)

# -----------------------------------------------------------------------------
# vFTP server
# - used for scenarios 2, 3, and 4
# -----------------------------------------------------------------------------
vsftpd_srv = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="vsftpd",
            owner="vsftpd",
            version="2.3.4",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.20"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="vsftpd_node",
)

# -----------------------------------------------------------------------------
# PostgreSQL DB server
# - used for scenarios 2, 3, and 4
# -----------------------------------------------------------------------------
postgres_srv = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="postgres",
            owner="postgres",
            version="10.5.0",
            local=False,
            private_data=[DataConfig(owner="dbuser", description="secret data for exfiltration")],
            access_level=AccessLevel.LIMITED,
            authentication_providers=[local_password_auth("postgres_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["postgres_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("dbuser", AccessLevel.ELEVATED)],
                    ),
                )
            ],
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.21"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="postgres_node",
)

# -----------------------------------------------------------------------------
# Haraka server
# -----------------------------------------------------------------------------
haraka_srv = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="haraka",
            owner="haraka",
            version="2.3.4",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.22"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="haraka_node",
)


# -----------------------------------------------------------------------------
# Chat server
# -----------------------------------------------------------------------------

chat_srv = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="tchat",
            owner="chat",
            version="2.3.4",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.3.23"), IPNetwork("192.168.3.0/24"))],
    shell="",
    id="chat_node",
)


# -----------------------------------------------------------------------------
# User PC server
# - used for scenarios 2, 3, and 4
# -----------------------------------------------------------------------------

developer = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="ssh",
            owner="ssh",
            version="5.1.4",
            local=False,
            access_level=AccessLevel.ELEVATED,
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED),
            ],
            authentication_providers=[local_password_auth("user_pc_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["user_pc_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("user", AccessLevel.ELEVATED)],
                    ),
                )
            ],
        ),
        PassiveServiceConfig(
            type="bash",
            owner="bash",
            version="8.1.0",
            local=True,
            access_level=AccessLevel.ELEVATED,
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.10"), IPNetwork("192.168.2.0/24"))],
    shell="",
    id="developer",
)


client3 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="bash",
            owner="bash",
            version="8.1.0",
            local=True,
            access_level=AccessLevel.ELEVATED
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.12"), IPNetwork("192.168.2.0/24"))],
    shell="",
    id="client3",
)

client4 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="bash",
            owner="bash",
            version="8.1.0",
            local=True,
            access_level=AccessLevel.ELEVATED
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.13"), IPNetwork("192.168.2.0/24"))],
    shell="",
    id="client4",
)

client5 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="bash",
            owner="bash",
            version="8.1.0",
            local=True,
            access_level=AccessLevel.ELEVATED
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.14"), IPNetwork("192.168.2.0/24"))],
    shell="",
    id="client5",
)

wifi_client1 = NodeConfig(
    active_services=[],
    passive_services=[],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.10"), IPNetwork("192.168.1.0/24"))],
    shell="",
    id="wifi_client1"
)

wifi_client2 = NodeConfig(
    active_services=[],
    passive_services=[],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.11"), IPNetwork("192.168.1.0/24"))],
    shell="",
    id="wifi_client2"
)

wifi_client3 = NodeConfig(
    active_services=[],
    passive_services=[],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.12"), IPNetwork("192.168.1.0/24"))],
    shell="",
    id="wifi_client3"
)


wifi_client4 = NodeConfig(
    active_services=[],
    passive_services=[],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.13"), IPNetwork("192.168.1.0/24"))],
    shell="",
    id="wifi_client4"
)

wifi_client5 = NodeConfig(
    active_services=[],
    passive_services=[],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.14"), IPNetwork("192.168.1.0/24"))],
    shell="",
    id="wifi_client5"
)


# -----------------------------------------------------------------------------
# Router between the Outside and the DMZ
# -----------------------------------------------------------------------------
perimeter_router = RouterConfig(
    interfaces=[
        # PortConfig(index=0),  # Future port or internal router (not implemented yet)
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.DENY,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.DENY,
                    # Enable free flow of packets between outside and DMZ
                    rules=[],
                )
            ],
        )
    ],
    id="perimeter_router",
)

# -----------------------------------------------------------------------------
# Internal router
# -----------------------------------------------------------------------------
internal_router = RouterConfig(
    interfaces=[
        # PortConfig(index=0),  # Future port for perimeter router (not implemented yet)
        # InterfaceConfig(IPAddress("192.168.2.1"), IPNetwork("192.168.2.0/24"), index=1),
        # InterfaceConfig(IPAddress("192.168.3.1"), IPNetwork("192.168.3.0/24"), index=2),
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.DENY,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.DENY,
                    rules=[
                        # Enable traffic flow between the three networks
                        FirewallRule(
                            src_net=IPNetwork("192.168.2.0/24"),
                            dst_net=IPNetwork("192.168.3.0/24"),
                            service="*",
                            policy=FirewallPolicy.ALLOW,
                        ),
                        FirewallRule(
                            src_net=IPNetwork("192.168.3.0/24"),
                            dst_net=IPNetwork("192.168.2.0/24"),
                            service="*",
                            policy=FirewallPolicy.ALLOW,
                        ),
                        FirewallRule(
                            src_net=IPNetwork("192.168.1.0/24"),
                            dst_net=IPNetwork("192.168.2.0/24"),
                            service="*",
                            policy=FirewallPolicy.DENY,
                        ),
                        FirewallRule(
                            src_net=IPNetwork("192.168.1.0/24"),
                            dst_net=IPNetwork("192.168.3.0/24"),
                            service="*",
                            policy=FirewallPolicy.DENY,
                        ),
                    ],
                )
            ]
        )
    ],
    id="internal_router",
)

wifi_router = RouterConfig(
    interfaces=[
        # PortConfig(index=0),  # Future port for perimeter router (not implemented yet)
        InterfaceConfig(IPAddress("192.168.1.1"), IPNetwork("192.168.1.0/24"), index=1),
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.DENY,
            chains=[FirewallChainConfig(type=FirewallChainType.FORWARD, policy=FirewallPolicy.DENY, rules=[])],
        )
    ],
    id="wifi_router",
)

inside_connections = [
    ConnectionConfig("wordpress_app_node", 0, "internal_router", -1),
    ConnectionConfig("wordpress_db_node", 0, "internal_router", -1),
    ConnectionConfig("haraka_node", 0, "internal_router", -1),
    ConnectionConfig("postgres_node", 0, "internal_router", -1),
    ConnectionConfig("chat_node", 0, "internal_router", -1),
    ConnectionConfig("developer", 0, "internal_router", -1),
    ConnectionConfig("client3", 0, "internal_router", -1),
    ConnectionConfig("client4", 0, "internal_router", -1),
    ConnectionConfig("client5", 0, "internal_router", -1),
    ConnectionConfig("wifi_client1", 0, "wifi_router", -1),
    ConnectionConfig("wifi_client2", 0, "wifi_router", -1),
    ConnectionConfig("wifi_client3", 0, "wifi_router", -1),
    ConnectionConfig("wifi_client4", 0, "wifi_router", -1),
    ConnectionConfig("wifi_client5", 0, "wifi_router", -1),
]

# router_connections = [
#     ConnectionConfig("perimeter_router", -1, "internal_router", -1),
#     ConnectionConfig("perimeter_router", -1, "wifi_router", -1),
# ]

perimeter_connections = [
    ConnectionConfig("attacker_node", 0, "perimeter_router", -1),
]

# Exploits
vsftpd_exploit = ExploitConfig(
    [VulnerableServiceConfig("vsftpd", "2.3.4")],
    ExploitLocality.REMOTE,
    ExploitCategory.CODE_EXECUTION,
)

nodes = [
    scripted_attacker,
    wordpress_srv,
    wordpress_db,
    vsftpd_srv,
    postgres_srv,
    chat_srv,
    haraka_srv,
    developer,
    client3,
    client4,
    client5,
    wifi_client1,
    wifi_client2,
    wifi_client3,
    wifi_client4,
    wifi_client5,
]
routers = [perimeter_router, internal_router, wifi_router]
connections = [*perimeter_connections, *inside_connections]
exploits = [vsftpd_exploit]
all_config_items = [*nodes, *routers, *connections, *exploits]


# ----------------------------------------------------------------------------------------------------------------------
class PlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self._env = Environment.create("docker+cryton")
        # We are bypassing private guards, but it is easier and more straightforward to do it this way for testing
        # purposes.
        self._model = self._env._behavioral_models["docker_test"] = DockerTestModel(self._env.configuration, self._env.resources,
                                                                                    None, self._env.messaging, self._env._cam)

        self._env.configure(*all_config_items)

        # TODO: Here I am getting direct access to active service and not to a service, which leaks implementation
        #       detail. Gotta fix it one day. Maybe.
        self._attacker_service = self._env.configuration.general.get_object_by_id("attacker_node.scripted_attacker", ActiveService)
        self._attacker_control = self._env.configuration.service.get_service_interface(self._attacker_service, ScriptedActorControl)

        self._env.control.add_pause_on_response("attacker_node.scripted_attacker")

        self._actions = {}
        for action in self._env.resources.action_store.get_prefixed("docker_test"):
            self._actions[action.id] = action

        self._env.control.init()

    def tearDown(self) -> None:
        self._env.control.commit()

    def test_0000(self):
        action = self._actions["docker_test:action_1"]
        self._attacker_control.execute_action("192.168.0.2", "", action)

        self._env.control.run()

        response = self._attacker_control.get_last_response()
        self.assertIsNotNone(response, "Got some response")
