import asyncio
import json
import logging
import socket
from inspect import isawaitable as _isawaitable
from typing import Any, Awaitable, Callable, ParamSpec, TypedDict, TypeVar
from xml.etree import ElementTree as ET

import wifi
import wifi.exceptions
from async_upnp_client.const import DeviceInfo, ServiceInfo
from async_upnp_client.client import UpnpRequester, UpnpStateVariable
from async_upnp_client.server import (UpnpServer, UpnpServerDevice,
                                      UpnpServerService, callable_action,
                                      create_event_var)

from async_upnp_client.utils import get_local_ip
from bless import BlessGATTCharacteristic  # type: ignore
from bless import BlessServer  # type: ignore
from bless import GATTAttributePermissions  # type: ignore
from bless import GATTCharacteristicProperties  # type: ignore

from appliances import lamp, motor

logger = logging.getLogger('homecontrol')
logger.setLevel(logging.DEBUG)
logging.basicConfig()

P = ParamSpec('P')
T = TypeVar('T')

async def maybe_coroutine(f: Callable[P, T | Awaitable[T]], *args: P.args, **kwargs: P.kwargs) -> T:
    r"""|coro|

    A helper function that will await the result of a function if it's a coroutine
    or return the result if it's not.

    This is useful for functions that may or may not be coroutines.

    Parameters
    -----------
    f: Callable[..., Any]
        The function or coroutine to call.
    \*args
        The arguments to pass to the function.
    \*\*kwargs
        The keyword arguments to pass to the function.

    Returns
    --------
    Any
        The result of the function or coroutine.
    """

    value = f(*args, **kwargs)
    if _isawaitable(value):
        return await value
    else:
        return value  # type: ignore

IP = get_local_ip()
SERVICE_UUID = 'fcb7f125-606c-57cd-924f-3482a9c10323'
NETWORK_CHARACTERISTIC_UUID = '51ff12bb-3ed8-46e5-b4f9-d64e2fec021b'
CONNECTED_CHARACTERISTIC_UUID = '28f2d950-79bd-5926-8872-648c716f231d'
LAMP_CHARACTERISTIC_UUID = 'fb63904f-5d09-5c7b-8d2c-acb56a159a8f'
MOTOR_CHARACTERISTIC_UUID = '4ce334f7-e255-5c56-a9ad-1e593f447a8c'

try:
    with open('./credentials.json', 'r') as f:
        saved_credentials: list['WiFiCredentials'] = json.load(f)
except FileNotFoundError:
    saved_credentials = []

class IoTService(UpnpServerService):
    """The main UPnP service for IoT functionality.

    This service allows to monitor and change the state of the available appliances.
    """
    SERVICE_DEFINITION = ServiceInfo(
        service_type = 'urn:schemas-upnp-org:service:IoTControl:1',
        service_id = 'urn:upnp-org:serviceId:IoTControl1',
        control_url = '/control',
        event_sub_url = '/control',
        scpd_url = '/scpd.xml',
        xml = ET.Element('xservice')
    )
    STATE_VARIABLE_DEFINITIONS = {'LampState': create_event_var('boolean', default=str(int(lamp.state))), 'MotorState': create_event_var('boolean', default=str(int(motor.state)))}

    def __init__(self, requester: UpnpRequester) -> None:
        super().__init__(requester)

        lamp.add_hook(self.sync_lamp_state)
        motor.add_hook(self.sync_motor_state)

    def sync_lamp_state(self) -> None:
        self.state_variable('LampState').value = lamp.state

    @callable_action('GetLampState', {}, {'CurrentLampState': 'LampState'})
    async def get_lamp_state(self) -> dict[str, UpnpStateVariable]:
        r"""|coro|

        Gets the current lamp state.

        Returns
        --------
        bool
            The current state of this appliance.
        """
        return {'CurrentLampState': self.state_variable('LampState')}

    @callable_action('SetLampState', {'NewLampState': 'LampState'}, {})
    async def set_lamp_state(self, NewLampState: bool):
        r"""|coro|

        Sets the lamp state to a new value.

        Parameters
        -----------
        NewLampState: bool
            The state to which the appliance will be set to.

        Returns
        --------
        Any
            The result of this action.
        """
        logger.debug(f'Setting lamp appliance state to {NewLampState}')

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lamp.set_state, NewLampState)
        self.state_variable('LampState').value = NewLampState
        return {}

    def sync_motor_state(self) -> None:
        self.state_variable('MotorState').value = motor.state

    @callable_action('GetMotorState', {}, {'CurrentMotorState': 'MotorState'})
    async def get_motor_state(self) -> dict[str, UpnpStateVariable]:
        r"""|coro|

        Gets the current motor state.

        Returns
        --------
        bool
            The current state of this appliance.
        """
        return {'CurrentMotorState': self.state_variable('MotorState')}

    @callable_action('SetMotorState', {'NewMotorState': 'MotorState'}, {})
    async def set_motor_state(self, NewMotorState: bool):
        r"""|coro|

        Sets the motor state to a new value.

        Parameters
        -----------
        NewLampState: bool
            The state to which the appliance will be set to.

        Returns
        --------
        Any
            The result of this action.
        """
        logger.debug(f'Setting motor appliance state to {NewMotorState}')

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, motor.set_state, NewMotorState)
        self.state_variable('MotorState').value = NewMotorState
        return {}

class IoTDevice(UpnpServerDevice):
    """The main UPnP device to expose the IoT device under."""

    DEVICE_DEFINITION = DeviceInfo(
        device_type = 'urn:schemas-upnp-org:device:IoTDevice:1',
        friendly_name = 'Banco de trabajo inteligente',
        manufacturer = 'Daniel & Medel Co.',
        manufacturer_url = 'http://www.utez.edu.mx/iot',
        model_description = 'Raspberry Pi Hub',
        model_name = 'rpi-iot',
        model_number = '1',
        model_url = 'http://www.utez.edu.mx/iot',
        serial_number = f'uuid:{SERVICE_UUID}',
        udn = f'uuid:{SERVICE_UUID}',
        upc = None,
        presentation_url = 'http://www.utez.edu.mx/',
        url = '/',
        icons = [

        ],
        xml = ET.Element('xdevice')
    )
    EMBEDDED_DEVICES = [

    ]
    SERVICES = [IoTService]
    ROUTES = []

class BluetoothBeacon(BlessServer):
    """Bluetooth server to enable Wi-Fi """

    def __init__(self, name: str = 'Banco de trabajo inteligente', loop: asyncio.AbstractEventLoop | None = None, *args, **kwargs):
        super().__init__(name, loop, *args, **kwargs)

        self.credentials_received = asyncio.Event()

    def sync_lamp_state(self) -> None:
        characteristic = self.get_characteristic(LAMP_CHARACTERISTIC_UUID)

        if characteristic is not None:
            characteristic.value = bytearray(lamp.state)

    def sync_motor_state(self) -> None:
        characteristic = self.get_characteristic(MOTOR_CHARACTERISTIC_UUID)

        if characteristic is not None:
            characteristic.value = bytearray(motor.state)

    async def start(self, **kwargs):
        loop = asyncio.get_event_loop()
        connected = await loop.run_in_executor(None, internet)

        await self.add_new_service(SERVICE_UUID)

        # Add a Characteristic to the service
        char_flags = (
            GATTCharacteristicProperties.read
            | GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.indicate
        )
        permissions = GATTAttributePermissions.readable | GATTAttributePermissions.writeable
        await self.add_new_characteristic(
            SERVICE_UUID, NETWORK_CHARACTERISTIC_UUID, GATTCharacteristicProperties.write, None, GATTAttributePermissions.writeable
        )
        await self.add_new_characteristic(
            SERVICE_UUID, CONNECTED_CHARACTERISTIC_UUID, GATTCharacteristicProperties.read, bytearray(connected), GATTAttributePermissions.readable
        )
        await self.add_new_characteristic(
            SERVICE_UUID, LAMP_CHARACTERISTIC_UUID, char_flags, bytearray(lamp.state), permissions
        )
        await self.add_new_characteristic(
            SERVICE_UUID, MOTOR_CHARACTERISTIC_UUID, char_flags, bytearray(motor.state), permissions
        )

        lamp.add_hook(self.sync_lamp_state)
        motor.add_hook(self.sync_motor_state)

        await super().start(**kwargs)

    async def stop(self):
        lamp.remove_hook(self.sync_lamp_state)
        motor.remove_hook(self.sync_motor_state)

        await super().stop()

    def read_request_func(self, characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
        logger.debug(f'Reading {characteristic.uuid}')

        if characteristic.uuid == MOTOR_CHARACTERISTIC_UUID:
            return bytearray(motor.state)
        elif characteristic.uuid == LAMP_CHARACTERISTIC_UUID:
            return bytearray(lamp.state)
        elif characteristic.uuid == CONNECTED_CHARACTERISTIC_UUID:
            return bytearray(internet())

        return characteristic.value

    def write_request_func(self, characteristic: BlessGATTCharacteristic, value: Any, **kwargs):
        characteristic.value = value

        logger.debug(f'{characteristic.uuid}: Char value set to {characteristic.value} type({type(characteristic.value)})')

        if characteristic.uuid == MOTOR_CHARACTERISTIC_UUID:
            motor.state = bool(value)
        elif characteristic.uuid == LAMP_CHARACTERISTIC_UUID:
            lamp.state = bool(value)
        elif characteristic.uuid == NETWORK_CHARACTERISTIC_UUID:
            asyncio.create_task(self._attempt_connection(value))

    async def _attempt_connection(self, data: bytearray) -> None:
        try:
            payload: WiFiCredentials = json.loads(data)
        except json.decoder.JSONDecodeError:
            logger.debug(f'Invalid payload received: \'{data}\'. Ignoring request.')
            return

        if await connect_to_wifi(payload):
            self.credentials_received.set()


def internet(host='8.8.8.8', port=53, timeout=3):
    """
    Host: 8.8.8.8 (google-public-dns-a.google.com)
    OpenPort: 53/tcp
    Service: domain (DNS/TCP)
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        print(ex)
        return False

class WiFiCredentials(TypedDict):
    ssid: str
    type: str
    password: str | None

def save_credentials(new_credentials: WiFiCredentials):
    with open('./credentials.json', 'r+') as f:
        saved_credentials: list[WiFiCredentials] = json.load(f)
        saved_credentials.append(new_credentials)
        json.dump(saved_credentials, f)

async def connect_to_wifi(credentials: WiFiCredentials) -> bool:
    if any(not credentials.get(x) for x in ('ssid', 'type')):
        return False

    if not credentials.get('password') and credentials['type'] != 'open':
        return False
    
    try:
        cells = wifi.Cell.where('wlan0', lambda cell: cell.ssid == credentials['ssid'])
        if len(cells) == 0:
            return False

        scheme = wifi.Scheme.for_cell('wlan0', credentials['ssid'], cells[0], credentials['password'])
        scheme.save()
        scheme.activate()
    except wifi.exceptions.ConnectionError as e:
        logger.info('Connection failed', exc_info=e)
        return False

    return True

async def run():
    loop = asyncio.get_event_loop()

    bluetooth_server = BluetoothBeacon(loop=loop)
    await bluetooth_server.start()

    if await loop.run_in_executor(None, internet) is False:
        logger.info('Connecting to Wi-Fi')
        connected = False

        if len(saved_credentials) > 0:
            logger.info('Searching saved Wi-Fi credentials')
            # prioritizes the last saved credentials
            for credentials in reversed(saved_credentials):
                logger.info(f'Trying connection to {credentials["ssid"]}')
                if await connect_to_wifi(credentials):
                    connected = True
                    break

        if connected is False:
            logger.info('Waiting for Wi-Fi credentials from Bluetooth')
            await bluetooth_server.credentials_received.wait()

    logger.info('Initializing IoT UPnP service')
    server = UpnpServer(IoTDevice, (IP, 6969), http_port=8586)

    await server.async_start()
    await asyncio.get_event_loop().create_future()

asyncio.run(run())
