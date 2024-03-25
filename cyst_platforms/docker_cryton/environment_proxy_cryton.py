# Python modules to use this Proxy must be installed via pip
import cyst.api.logic.action
from importlib_metadata import entry_points
from typing import Optional, Any, Union
from netaddr import IPAddress

from cyst.api.logic.exploit import Exploit, VulnerableService, ExploitLocality, ExploitCategory, ExploitParameter, \
    ExploitParameterType
from cyst.core.logic.exploit import VulnerableServiceImpl, ExploitParameterImpl, ExploitImpl

from cyst.api.environment.environment import Environment
from cyst.api.environment.message import Request, Status, Message, Response, MessageType, StatusValue, Status, \
    StatusOrigin, StatusDetail
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources, ActionStore, ExploitStore, Clock, Statistics
from cyst.api.host.service import ActiveService
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.logic.action import Action, ActionParameter, ActionParameterType, ActionDescription
from cyst.api.network.session import Session

from cyst.core.environment.message import MessageImpl, Metadata
from cyst.core.network.elements import Endpoint, Hop
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.core.environment.stores import ActionStoreImpl, ExploitStoreImpl

CRYTON_CORE_IP = "cryton-app"
CRYTON_CORE_PORT = 8000
CRYTON = 1


class CrytonProxy(EnvironmentMessaging, EnvironmentResources):

    def __init__(self, environment: Environment):
        self._env = environment
        self._messaging = environment.messaging
        self._resources = environment.resources
        self._policy = environment.policy
        self._configuration = environment.configuration

        self._action_store = ActionStoreImpl()
        self._exploit_store = ExploitStoreImpl()

        self._interpreters = {}
        self.services = []
        self.agents = {}
        
        self.agents_counter = 0 # used for Worker name
        self.tool = None # emulation

        self._register_actions()
        self.filter_actions()

    def __getattr__(self, attr):
        return getattr(self._env, attr)

    def open_session(self, request: Request):
        pass

    def register_service(self, node_name, service_name, attacker_service):
        self.services.append({"node_name": node_name, "service_name": service_name, "attacker_service": attacker_service})

    def _register_actions(self) -> None:
        plugin_models = entry_points(group="cyst.models")
        for s in plugin_models:
            model_description = s.load()

            if model_description.namespace in self._interpreters:
                print("Behavioral model with namespace {} already registered, skipping it ...".format(
                    model_description.namespace))
            else:
                model = model_description.creation_fn(self._configuration, self._resources, self._policy,
                                                      self._messaging)
                self._interpreters[model_description.namespace] = model

    def filter_actions(self):
        all_actions = self._resources.action_store.get_prefixed('')

        for action in all_actions:
            # TODO: filter according to real description
            
            # add only actions which are possible to emulate
            if "Emulate" in action.description:
                parameters = []
                if action.parameters:
                    parameters.extend(action.parameters.values())
                self._action_store.add(ActionDescription(action.id, action.description, parameters, action.tokens))

    def send_message(self, message: Message, delay: int = 0) -> None:
        request = message.cast_to(Request)

        m = MessageImpl.cast_from(message)
        service_id = hash((m.origin.id, m.src_service))
        meta = Metadata()

        # useful for allowing multiple tools to be used
        if "Cryton" in request.action.description:
            self.tool = CRYTON
        
        # recieved action is not first agent activity -> agents worker is already up and running, and stage exists
        if self.tool == CRYTON and service_id in self.agents:
            
            meta.auxiliary["stage_id"] = self.agents[service_id]["stage_id"]
            meta.auxiliary["is_init"] = False
            request.set_metadata(meta)
        
        # received action is first agent activity -> new plan, worker, run and stage will be created
        if self.tool == CRYTON and service_id not in self.agents:
            
            self.agents_counter += 1
            worker_name = f"Worker {self.agents_counter}"

            cryton = Cryton(CRYTON_CORE_IP, CRYTON_CORE_PORT)
            worker_id = cryton.create_worker(name='attacker', description="Created from CYST")

            # stage ID is needed for adding actions - in this use case the number is equivalent to plan ID
            stage_id = cryton.init_new_agent(plan_name=f"Plan for {worker_name}", owner=worker_name,
                                             cryton_worker_id=worker_id)

            self.agents[service_id] = {"worker_id": worker_id, "stage_id": stage_id}

            # stage_id will be used for executing action in models

            meta.auxiliary["stage_id"] = stage_id
            meta.auxiliary["is_init"] = True
            request.set_metadata(meta)

        # at this point, message should have correct stage_id in metadata

        print("\n-------------------------------------------------------")
        print(f"Attacker executed action {request.action.id} on target {request.dst_ip}")
        print()

        time, response = self._interpreters[request.action.namespace].evaluate(message, None)

        for service in self.services:
            if service["service_name"] == request.src_service:
                service["attacker_service"].process_message(response)

    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "", action: Optional[Action] = None,
                       session: Optional[Session] = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None) -> Request:

        if not self.action_store.get(action.id):
            # action is not implemented
            raise RuntimeError

        return self._messaging.create_request(dst_ip, dst_service, action, session, auth)

    def create_response(self, request: Request, status: Status, content: Optional[Any] = None,
                        session: Optional[Session] = None,
                        auth: Optional[Union[Authorization, AuthenticationTarget]] = None) -> Response:

        return self._messaging.create_response(request, status, content, session, auth)

    def get_ref(self, id: str = "") -> Optional[Action]:
        return self._action_store.get_ref(id)

    def get(self, id: str = "") -> Optional[Action]:
        return self._action_store.get(id)

    def get_prefixed(self, id: str = ""):
        return self._action_store.get_prefixed(id)
    
    @property
    def action_store(self) -> ActionStore:
        return self._action_store

    @property
    def exploit_store(self) -> ExploitStore:
        return self._exploit_store

    @property
    def clock(self) -> Clock:
        return self._resources.clock

    @property
    def statistics(self) -> Statistics:
        return self._resources.statistics

