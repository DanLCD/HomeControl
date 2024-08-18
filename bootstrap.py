import asyncio
from typing import Any
from async_upnp_client.server import UpnpServer, UpnpServerDevice, UpnpServerService, callable_action, create_event_var
from async_upnp_client.const import DeviceInfo, ServiceInfo
from async_upnp_client.utils import get_local_ip

from xml.etree import ElementTree as ET

from bless import (
    BlessServer, # type: ignore
    BlessGATTCharacteristic, # type: ignore
    GATTCharacteristicProperties, # type: ignore
    GATTAttributePermissions, # type: ignore
)

IP = get_local_ip()
SERVICE_UUID = 'fcb7f125-606c-57cd-924f-3482a9c10323'
CHARACTERISTIC_UUID = '51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B'

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

class BluetoothBeacon(BlessServer):
    def __init__(self, name: str='Banco de trabajo inteligente', loop: asyncio.AbstractEventLoop | None = None, name_overwrite: bool = False, **kwargs):
        super().__init__(name, loop, name_overwrite, **kwargs)

        self._charbuff = bytearray()
        self._charbuff_evt = asyncio.Event()

    async def wait_read_value(self) -> bytearray:
        await self._charbuff_evt.wait()
        return self._charbuff

    async def start(self, **kwargs):
        await super().start(**kwargs)

        await self.add_new_service(SERVICE_UUID)

        # Add a Characteristic to the service
        char_flags = (
            GATTCharacteristicProperties.read
            | GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.indicate
        )
        permissions = GATTAttributePermissions.readable | GATTAttributePermissions.writeable
        await self.add_new_characteristic(
            SERVICE_UUID, CHARACTERISTIC_UUID, char_flags, None, permissions
        )

    def read_request_func(self, characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
        print(f"Reading {characteristic.value}")
        return characteristic.value

    def write_request_func(self, characteristic: BlessGATTCharacteristic, value: Any, **kwargs):
        characteristic.value = value
        print(f"Char value set to {characteristic.value}")

        if characteristic.uuid == CHARACTERISTIC_UUID:
            if self._charbuff_evt.is_set():
                self._charbuff.clear()
                self._charbuff_evt.clear()

            if characteristic.value == b"\x0f":
                self._charbuff_evt.set()
            else:
                self._charbuff.extend(characteristic.value)


async def run():
    loop = asyncio.get_event_loop()
    # Instantiate the server
    server = BluetoothBeacon(loop=loop)


    print(server.get_characteristic(CHARACTERISTIC_UUID))
    await server.start()
    print("Advertising")
    print(f"Write '0xF' to the advertised characteristic: {CHARACTERISTIC_UUID}")

    value = await server.wait_read_value()
    print(value)

    await asyncio.sleep(2)
    print("Updating")
    server.get_characteristic(CHARACTERISTIC_UUID)
    server.update_value(SERVICE_UUID, CHARACTERISTIC_UUID)
    await asyncio.sleep(5)
    await server.stop()

    server = UpnpServer(IoTDevice, (IP, 6969), http_port=8586)

    await server.async_start()
    await asyncio.get_event_loop().create_future()

asyncio.run(run())
