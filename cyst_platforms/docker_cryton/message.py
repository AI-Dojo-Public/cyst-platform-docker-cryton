from cyst.api.logic.action import Action
from netaddr import IPAddress
from typing import Type, Dict, Any, Optional, Union

from cyst.api.environment.message import Message, MessageType, T, Response, Request, Status
from cyst.api.logic.access import Authorization, AuthenticationToken, AuthenticationTarget
from cyst.api.logic.metadata import Metadata
from cyst.api.network.session import Session
from cyst.api.utils.counter import Counter


class MessageImpl(Message):

    def __init__(
        self,
        type: MessageType,
        src_ip: IPAddress = None,
        dst_ip: IPAddress = None,
        dst_service: str = "",
        session: Session = None,
        auth: Optional[Union[Authorization, AuthenticationToken, AuthenticationTarget]] = None,
        force_id: int = -1,
        ttl: int = 64,
    ):
        if force_id == -1:
            self._id = Counter().get("message")
        else:
            self._id = force_id

        self._type = type
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._src_service = ""
        self._dst_service = dst_service
        self._session = session
        self._auth = auth
        self._ttl = ttl

        self._metadata = None
        self._platform_specific: Dict[str, Any] = {}

    @property
    def id(self) -> int:
        return self._id

    @property
    def type(self) -> MessageType:
        return self._type

    @property
    def src_ip(self) -> Optional[IPAddress]:
        return self._src_ip

    @property
    def dst_ip(self) -> Optional[IPAddress]:
        return self._dst_ip

    @property
    def src_service(self) -> Optional[str]:
        return self._src_service

    @property
    def dst_service(self) -> str:
        return self._dst_service

    @property
    def session(self) -> Optional[Session]:
        return self._session

    @property
    def auth(self) -> Optional[Union[Authorization, AuthenticationToken, AuthenticationTarget]]:
        return self._auth

    @property
    def ttl(self) -> int:
        return self._ttl

    @property
    def metadata(self) -> Metadata:
        return self._metadata

    @property
    def platform_specific(self) -> Dict[str, Any]:
        return self._platform_specific

    def set_metadata(self, metadata: Metadata) -> None:
        self._metadata = metadata

    def cast_to(self, type: Type[T]) -> T:
        if isinstance(self, type):
            return self  # MYPY: if this works, then probably ignore
        else:
            raise ValueError("Casting to a wrong derived type")


class RequestImpl(Request, MessageImpl):

    def __init__(
        self,
        dst_ip: Union[str, IPAddress],
        dst_service: str = "",
        action: Action = None,
        session: Session = None,
        auth: Optional[Union[Authorization, AuthenticationToken, AuthenticationTarget]] = None,
        original_request: Optional[Request] = None,
    ):
        if type(dst_ip) is str:
            dst_ip = IPAddress(dst_ip)

        _session = session
        if not _session and original_request:
            _session = original_request.session

        _auth = auth
        if not _auth and original_request:
            _auth = original_request.auth

        _src_ip = None
        if original_request:
            _src_ip = original_request.src_ip

        super(RequestImpl, self).__init__(
            MessageType.REQUEST, _src_ip, dst_ip, dst_service, session=_session, auth=_auth
        )

        if original_request:
            self._src_service = original_request.src_service
            self.platform_specific["caller_id"] = original_request.platform_specific["caller_id"]

        self._action = action

    @property
    def action(self) -> Action:
        return self._action

    @staticmethod
    def cast_from(o: Request) -> "RequestImpl":
        if isinstance(o, RequestImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Request interface")


class ResponseImpl(Response, MessageImpl):
    def __init__(
        self,
        request: MessageImpl,
        status: Status = None,
        content: Any = None,
        session: Session = None,
        auth: Optional[Union[Authorization, AuthenticationToken, AuthenticationTarget]] = None,
        original_response: Optional[Response] = None,
    ) -> None:

        super(ResponseImpl, self).__init__(
            MessageType.RESPONSE, request.dst_ip, request.src_ip, session=session, auth=auth, force_id=request.id
        )

        self._status = status
        self._content = content

        # Copy platform-specific information
        self._platform_specific = request.platform_specific

        if isinstance(request, Request):
            self._action = request.action
        else:
            raise RuntimeError("Attempting to create a response from non-request Message")
        # Response switches the source and destination services
        self._src_service = request.dst_service
        self._dst_service = request.src_service

    @property
    def action(self) -> Action:
        return self._action

    @property
    def status(self) -> Status:
        return self._status

    @property
    def content(self) -> Optional[Any]:
        return self._content

    @staticmethod
    def cast_from(o: Response) -> "ResponseImpl":
        if isinstance(o, ResponseImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Response interface")
