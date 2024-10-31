from typing import Optional

from cyst.api.host.service import ActiveService, Service, PassiveService
from cyst.api.logic.access import AccessLevel


class ServiceImpl(Service):

    def __init__(self, active_service: ActiveService):
        self._active_service = active_service

    @property
    def name(self) -> str:
        return ""

    @property
    def owner(self) -> str:
        return ""

    @property
    def service_access_level(self) -> AccessLevel:
        return AccessLevel.NONE

    @property
    def passive_service(self) -> Optional['PassiveService']:
        return None

    @property
    def active_service(self) -> Optional['ActiveService']:
        return self._active_service