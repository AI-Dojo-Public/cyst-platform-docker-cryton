from tests.test_platform import all_config_itemsThe primary use case of the Docker+Cryton platform is emulation. It uses Dr-Emu to build an emulated (dockerized) infrastructure and Cryton to execute attacks on it.

## Settings
By default, the platform tries to connect to Dr-Emu at `127.0.0.1:8000` and Cryton at `127.0.0.1:8001`.

Those settings can be changed using the following environment variables:

* `CYST_PLATFORM_DR_EMU_IP`
* `CYST_PLATFORM_DR_EMU_PORT`
* `CYST_PLATFORM_CRYTON_IP`
* `CYST_PLATFORM_CRYTON_PORT`

## Prerequisites
The following applications must be started before using the platform.

* [Cryton](https://gitlab.ics.muni.cz/cryton/cryton) **v3.x.x**
* [DrEmu](https://gitlab.ics.muni.cz/ai-dojo/dr-emu) **v0.2.x**

## Usage

### Initialization and setup

1. Define your infrastructure. The nodes, services, routing, exploits, etc.  
2. Select the correct platform. We want an emulation to run in real time and use the `docker+cryton` platform.  
3. Call `configure` to build the infrastructure using Dr-Emu and register necessary details with Cryton.
4. Call `init` to make the `cryton` resource accessible to CYST models.

Example:
```python
from cyst.api.environment.environment import Environment
from cyst.api.environment.platform_specification import PlatformType, PlatformSpecification
from cyst.api.configuration.configuration import ConfigItem


config: list[ConfigItem] = ...  # You define the infrastructure configuration
platform = PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton")
environment = Environment.create(platform).configure(*config)
environment.control.init()
```

### Using Cryton resource in models
Cryton uses Workers for executing attacks. To identify the correct attacker, use the platform specific parameter `caller_id`.  
The second parameter we need is a template. The template represents one action that will be performed by the attacker.

Once we send the request to Cryton, it will do the rest and after the action has finished, it will give us the result.

Example of the Cryton resource usage in a CYST model:
```python
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.behavioral_model import BehavioralModel
from cyst.api.logic.composite_action import CompositeActionManager
from cyst.api.environment.message import Request
from typing import cast
from dataclasses import dataclass


@dataclass
class CrytonResponse:
    start_time: str
    finish_time: str
    pause_time: str
    output: str
    serialized_output: dict | list


class CrytonModel(BehavioralModel):
    def __init__(
        self,
        configuration: EnvironmentConfiguration,
        resources: EnvironmentResources,
        policy: EnvironmentPolicy,
        messaging: EnvironmentMessaging,
        composite_action_manager: CompositeActionManager,
    ) -> None:
        self._configuration = configuration
        self._external = resources.external
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging
        self._cam = composite_action_manager

    async def example_usage_of_cryton_resource(self, message: Request):
        node_id = message.platform_specific["caller_id"].split(".")[0]

        resource = self._external.create_resource("cryton://")
        result = cast(
            CrytonResponse,
            await self._external.fetch_async(
                resource,
                {
                    "template": {},
                    "node_id": node_id
                },
            )
        )
```
