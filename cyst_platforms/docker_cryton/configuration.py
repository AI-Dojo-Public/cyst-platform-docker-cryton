from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Union, Any, Type, Dict, Tuple

from cyst.api.configuration import ServiceParameter
from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.network.node import NodeConfig
from cyst.api.environment.configuration import (
    EnvironmentConfiguration,
    GeneralConfiguration,
    NodeConfiguration,
    ServiceConfiguration,
    NetworkConfiguration,
    ExploitConfiguration,
    ActionConfiguration,
    AccessConfiguration,
    ActiveServiceInterfaceType,
    ObjectType,
    ConfigurationObjectType,
    PhysicalConfiguration,
)
from cyst.api.environment.message import Message
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.infrastructure import EnvironmentInfrastructure
from cyst.api.environment.physical import PhysicalConnection, PhysicalAccess, PhysicalLocation
from cyst.api.environment.platform import Platform
from cyst.api.host.service import ActiveService, Service, PassiveService
from cyst.api.logic.access import (
    AccessScheme,
    AuthenticationProvider,
    Authorization,
    AccessLevel,
    AuthenticationToken,
    AuthenticationTarget,
    AuthenticationTokenType,
    AuthenticationTokenSecurity,
    AuthenticationProviderType,
)
from cyst.api.configuration import ExploitConfig, SessionConfig
from cyst.api.logic.data import Data
from cyst.api.network.elements import Route, Interface, Connection
from cyst.api.network.firewall import FirewallPolicy, FirewallRule
from cyst.api.network.node import Node
from cyst.api.network.session import Session
from cyst.api.utils.duration import Duration
from netaddr import IPAddress, IPNetwork


class GeneralConfigurationImpl(GeneralConfiguration):
    def __init__(
        self,
        platform: Platform,
        env_general_configuration: GeneralConfiguration,
        infrastructure: EnvironmentInfrastructure,
    ) -> None:
        self._platform = platform
        self._infrastructure = infrastructure
        self._objects = {}
        self._sessions = dict()
        self._env_general_configuration = env_general_configuration

    # ------------------------------------------------------------------------------------------------------------------
    # Proxy methods back to the environment
    def get_configuration(self) -> List[ConfigItem]:
        return self._env_general_configuration.get_configuration()

    def save_configuration(self, indent: Optional[int]) -> str:
        return self._env_general_configuration.save_configuration(indent)

    def load_configuration(self, config: str) -> List[ConfigItem]:
        return self._env_general_configuration.load_configuration(config)

    def get_configuration_by_id(
        self, id: str, configuration_type: Type[ConfigurationObjectType]
    ) -> ConfigurationObjectType:
        return self._env_general_configuration.get_configuration_by_id(id, configuration_type)

    # ------------------------------------------------------------------------------------------------------------------
    # Local methods
    def get_object_by_id(self, id: str, object_type: Type[ObjectType]) -> ObjectType:
        if object_type not in [ActiveService, SessionConfig]:
            raise RuntimeError(
                f"Docker+Cryton platform only supports getting active services as objects, not {object_type}"
            )

        if id not in self._objects:
            raise RuntimeError(f"Object with the id {id} not available in configuration.")

        return self._objects[id]

    def add_object(self, id: str, obj: Any) -> None:
        self._objects[id] = obj

    # Not fancying type removal, but it is unimportant here and only pollutes the code
    def configure(self, *config_item: ConfigItem) -> Platform:
        # Infrastructure is ready, create all active services by going through nodes
        for item in config_item:
            if isinstance(item, NodeConfig):
                if item.active_services:
                    for active_service in item.active_services:
                        # Node requirement is ignored. Waiting for a change in code that will remove it.
                        service_id = item.id + "." + active_service.name
                        conf = active_service.configuration or dict()
                        conf["__sessions"] = self._sessions
                        s = self._infrastructure.service_store.create_active_service(
                            active_service.type,
                            active_service.owner,
                            active_service.name,
                            None,
                            active_service.access_level,
                            conf,
                            item.id + "." + active_service.name,
                        )
                        if not s:
                            raise RuntimeError(f"Could not create active service with the name {active_service.name}")

                        self._objects[service_id] = s
            elif isinstance(item, ExploitConfig):
                self._objects[item.id] = item
                params = []
                if item.parameters:
                    for p in item.parameters:
                        param = self._platform.configuration.exploit.create_exploit_parameter(p.type, p.value,
                                                                                              p.immutable)
                        params.append(param)

                services = []
                for s in item.services:
                    service = self._platform.configuration.exploit.create_vulnerable_service(
                        s.name, s.min_version, s.max_version
                    )
                    services.append(service)

                e = self._platform.configuration.exploit.create_exploit(
                    item.id, services, item.locality, item.category, *params
                )
                self._platform.configuration.exploit.add_exploit(e)
            elif isinstance(item, SessionConfig):
                session = self._platform.configuration.network.create_session(
                    owner="__system",
                    waypoints=item.waypoints,
                    src_service=item.src_service,
                    dst_service=item.dst_service,
                    parent=None,
                    defer=True,
                    reverse=item.reverse,
                    id=item.id
                )
                self._objects[item.id] = session
                self._sessions[item.id] = session

        return self._platform

    @staticmethod
    def cast_from(o: GeneralConfiguration) -> "GeneralConfigurationImpl":
        if isinstance(o, GeneralConfigurationImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the GeneralConfiguration interface")


class NodeConfigurationImpl(NodeConfiguration):
    def create_node(self, id: str, ip: Union[str, IPAddress] = "", mask: str = "", shell: Service = None) -> Node:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_router(self, id: str, messaging: EnvironmentMessaging) -> Node:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_port(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0, id: str = "") -> Interface:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_interface(
        self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0, id: str = ""
    ) -> Interface:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_route(self, net: IPNetwork, port: int, metric: int, id: str = "") -> Route:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_interface(self, node: Node, interface: Interface, index: int = -1) -> int:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def set_interface(self, interface: Interface, ip: Union[str, IPAddress] = "", mask: str = "") -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_service(self, node: Node, *service: Service) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_service(self, node: Node, *service: Service) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def set_shell(self, node: Node, service: Service) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_traffic_processor(self, node: Node, processor: ActiveService) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_route(self, node: Node, *route: Route) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_routing_rule(self, node: Node, rule: FirewallRule) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def set_routing_policy(self, node: Node, policy: FirewallPolicy) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def list_routes(self, node: Node) -> List[Route]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")


class ServiceConfigurationImpl(ServiceConfiguration):
    def create_active_service(
        self,
        type: str,
        owner: str,
        name: str,
        node: Node,
        service_access_level: AccessLevel = AccessLevel.LIMITED,
        configuration: Optional[Dict[str, Any]] = None,
        id: str = "",
    ) -> Optional[Service]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_service_interface(
        self, service: ActiveService, control_interface_type: Type[ActiveServiceInterfaceType]
    ) -> ActiveServiceInterfaceType:
        if isinstance(service, control_interface_type):
            return service
        else:
            raise RuntimeError("Given active service does not provide control interface of given type.")

    def create_passive_service(
        self,
        type: str,
        owner: str,
        version: str = "0.0.0",
        local: bool = False,
        service_access_level: AccessLevel = AccessLevel.LIMITED,
        id: str = "",
    ) -> Service:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def update_service_version(self, service: PassiveService, version: str = "0.0.0") -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def set_service_parameter(self, service: PassiveService, parameter: ServiceParameter, value: Any) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_data(self, id: Optional[str], owner: str, description: str) -> Data:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def public_data(self, service: PassiveService) -> List[Data]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def private_data(self, service: PassiveService) -> List[Data]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def public_authorizations(self, service: PassiveService) -> List[Authorization]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def private_authorizations(self, service: PassiveService) -> List[Authorization]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def sessions(self, service: PassiveService) -> List[Session]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def provides_auth(self, service: Service, auth_provider: AuthenticationProvider) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def set_scheme(self, service: PassiveService, scheme: AccessScheme) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")


class SessionImpl(Session):
    def __init__(self, owner: str = None, session_id: str = None, parent: Optional["SessionImpl"] = None, path: list[str] = None):
        self._owner = owner
        self._id = session_id
        self._parent = parent
        self._path: list[str] = path

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def id(self) -> str:
        return self._id

    @property
    def parent(self) -> Optional[Session]:
        return self._parent

    @property
    def path(self) -> list[tuple[Optional[IPAddress], Optional[IPAddress]]]:
        return self._path

    @property
    def end(self) -> tuple[IPAddress, str]:
        return self._path[-1]

    @property
    def start(self) -> tuple[IPAddress, str]:
        return self._path[0]

    @property
    def enabled(self) -> bool:
        return True


class NetworkConfigurationImpl(NetworkConfiguration):
    def add_node(self, node: Node) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_connection(
        self,
        source: Node,
        target: Node,
        source_port_index: int = -1,
        target_port_index: int = -1,
        net: str = "",
        connection: Optional[Connection] = None,
    ) -> Connection:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_connections(self, node: Node, port_index: Optional[int] = None) -> List[Connection]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_session(
        self,
        owner: str,
        waypoints: List[Union[str, Node]],
        src_service: Optional[str] = None,
        dst_service: Optional[str] = None,
        parent: Optional[Session] = None,
        defer: bool = False,
        reverse: bool = False,
        id: Optional[str] = None
    ) -> Optional[Session]:
        return SessionImpl(session_id=id, path=waypoints)

    def append_session(self, original_session: Session, appended_session: Session) -> Session:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_session_from_message(self, message: Message) -> Session:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")


class AccessConfigurationImpl(AccessConfiguration):
    def create_authentication_provider(
        self,
        provider_type: AuthenticationProviderType,
        token_type: AuthenticationTokenType,
        security: AuthenticationTokenSecurity,
        ip: Optional[IPAddress],
        timeout: int,
        id: str = "",
    ) -> AuthenticationProvider:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_authentication_token(
        self, type: AuthenticationTokenType, security: AuthenticationTokenSecurity, identity: str, is_local: bool
    ) -> AuthenticationToken:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def register_authentication_token(self, provider: AuthenticationProvider, token: AuthenticationToken) -> bool:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def unregister_authentication_token(self, token_identity: str, provider: AuthenticationProvider) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_and_register_authentication_token(
        self, provider: AuthenticationProvider, identity: str
    ) -> Optional[AuthenticationToken]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_authorization(
        self,
        identity: str,
        access_level: AccessLevel,
        id: str,
        nodes: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> Authorization:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_access_scheme(self, id: str = "") -> AccessScheme:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_provider_to_scheme(self, provider: AuthenticationProvider, scheme: AccessScheme) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_authorization_to_scheme(self, auth: Authorization, scheme: AccessScheme) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_authorization_from_scheme(self, auth: Authorization, scheme: AccessScheme) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def evaluate_token_for_service(
        self, service: Service, token: AuthenticationToken, node: Node, fallback_ip: Optional[IPAddress]
    ) -> Optional[Union[Authorization, AuthenticationTarget]]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def disable_authentication_token(
        self, provider: AuthenticationProvider, token: AuthenticationToken, time: int
    ) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def enable_authentication_token(self, provider: AuthenticationProvider, token: AuthenticationToken) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_service_access(
        self, service: Service, identity: str, access_level: AccessLevel, tokens: List[AuthenticationToken] = None
    ) -> Optional[List[AuthenticationToken]]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def modify_existing_access(self, service: Service, identity: str, access_level: AccessLevel) -> bool:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")


class PhysicalConfigurationImpl(PhysicalConfiguration):

    def create_physical_location(self, location_id: str | None) -> PhysicalLocation:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_physical_location(self, location_id: str) -> PhysicalLocation | None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_physical_locations(self) -> List[PhysicalLocation]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_physical_location(self, location_id: str) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def create_physical_access(self, identity: str, time_from: datetime | None,
                               time_to: datetime | None) -> PhysicalAccess:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_physical_access(self, location_id: str, access: PhysicalAccess) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_physical_accesses(self, location_id: str) -> List[PhysicalAccess]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_physical_access(self, location_id: str, access: PhysicalAccess) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def add_physical_connection(self, origin: str, destination: str, travel_time: Duration) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_physical_connection(self, origin: str, destination: str) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_physical_connections(self, origin: str, destination: str | None) -> List[PhysicalConnection]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def place_asset(self, location_id: str, asset: str) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def remove_asset(self, location_id: str, asset: str) -> None:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def move_asset(self, origin: str, destination: str, asset: str) -> Tuple[bool, str, str]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_assets(self, location_id: str) -> List[str]:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")

    def get_location(self, asset: str) -> str:
        raise NotImplementedError("Docker+Cryton do not allow partial configuration. Use top-level configure() call.")


@dataclass
class EnvironmentConfigurationImpl(EnvironmentConfiguration):
    general: Optional[GeneralConfiguration] = None
    node: Optional[NodeConfiguration] = NodeConfigurationImpl()
    service: Optional[ServiceConfiguration] = ServiceConfigurationImpl()
    network: Optional[NetworkConfiguration] = NetworkConfigurationImpl()
    exploit: Optional[ExploitConfiguration] = None
    action: Optional[ActionConfiguration] = None
    access: Optional[AccessConfiguration] = AccessConfigurationImpl()
    physical: Optional[PhysicalConfiguration] = PhysicalConfigurationImpl()
