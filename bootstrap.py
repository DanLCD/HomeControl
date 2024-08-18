import asyncio
import sys
import threading
from typing import Union
from async_upnp_client.server import UpnpServer, UpnpServerDevice, UpnpServerService, callable_action, create_event_var
from async_upnp_client.const import DeviceInfo, ServiceInfo
from async_upnp_client.utils import get_local_ip

from xml.etree import ElementTree as ET

from bless import (  # type: ignore
    BlessServer,
    BlessGATTCharacteristic,
    GATTCharacteristicProperties,
    GATTAttributePermissions,
)

IP = get_local_ip()
SERVICE_UUID = 'fcb7f125-606c-57cd-924f-3482a9c10323'

class IoTService(UpnpServerService):
    SERVICE_DEFINITION = ServiceInfo(
        service_type = 'urn:schemas-upnp-org:service:IoTControl:1',
        service_id = 'urn:upnp-org:serviceId:IoTControl1',
        control_url = '/control',
        event_sub_url = '/control',
        scpd_url = '/scpd.xml',
        xml = ET.Element('xservice')
    )
    STATE_VARIABLE_DEFINITIONS = {'LampState': create_event_var('boolean', default='false'), 'MotorState': create_event_var('boolean', default='false')}

    @callable_action('SetLampState', {'NewLampState': 'LampState'}, {})
    async def set_lamp_state(self, NewLampState: bool):
        self.state_variable('LampState').value = NewLampState
        # TODO: Change appliance state
        return {}

    @callable_action('SetMotorState', {'NewMotorState': 'MotorState'}, {})
    async def set_motor_state(self, NewMotorState: bool):
        self.state_variable('MotorState').value = NewMotorState
        # TODO: Change appliance state
        return {}

class IoTDevice(UpnpServerDevice):
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

# NOTE: Some systems require different synchronization methods.
trigger: Union[asyncio.Event, threading.Event]
if sys.platform in ["darwin", "win32"]:
    trigger = threading.Event()
else:
    trigger = asyncio.Event()


def read_request(characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
    print(f"Reading {characteristic.value}")
    return characteristic.value


def write_request(characteristic: BlessGATTCharacteristic, value: Any, **kwargs):
    characteristic.value = value
    print(f"Char value set to {characteristic.value}")
    if characteristic.value == b"\x0f":
        print("NICE")
        trigger.set()


async def run():
    loop = asyncio.get_event_loop()

    trigger.clear()
    # Instantiate the server
    my_service_name = "Test Service"
    server = BlessServer(name=my_service_name, loop=loop)
    server.read_request_func = read_request
    server.write_request_func = write_request

    # Add Service
    my_service_uuid = SERVICE_UUID
    await server.add_new_service(my_service_uuid)

    # Add a Characteristic to the service
    my_char_uuid = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
    char_flags = (
        GATTCharacteristicProperties.read
        | GATTCharacteristicProperties.write
        | GATTCharacteristicProperties.indicate
    )
    permissions = GATTAttributePermissions.readable | GATTAttributePermissions.writeable
    await server.add_new_characteristic(
        my_service_uuid, my_char_uuid, char_flags, None, permissions
    )

    print(server.get_characteristic(my_char_uuid))
    await server.start()
    print("Advertising")
    print(f"Write '0xF' to the advertised characteristic: {my_char_uuid}")
    if isinstance(trigger, threading.Event):
        trigger.wait()
    else:
        await trigger.wait()

    await asyncio.sleep(2)
    print("Updating")
    server.get_characteristic(my_char_uuid)
    server.update_value(my_service_uuid, "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B")
    await asyncio.sleep(5)
    await server.stop()

    server = UpnpServer(IoTDevice, (IP, 6969), http_port=8586)

    await server.async_start()
    await asyncio.get_event_loop().create_future()

asyncio.run(run())
