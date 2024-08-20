from typing import Callable, TypeAlias
from RPi import GPIO 

Hook: TypeAlias = Callable[[], None]

GPIO.setmode(GPIO.BOARD)

class Appliance:
    def __init__(self, pin: int) -> None:
        self.pin = pin
        self._hooks: list[Hook] = []
        GPIO.setup(pin, GPIO.LOW)
        self.state = False

    @property
    def state(self) -> bool:
        return self._state

    @state.setter
    def state(self, state: bool) -> None:
        self._state = state
        GPIO.output(self.pin, state)
        for hook in self._hooks:
            try:
                hook()
            except Exception:
                continue

    def set_state(self, state: bool) -> None:
        self.state = state

    def add_hook(self, callback: Hook) -> None:
        self._hooks.append(callback)

    def remove_hook(self, callback: Hook) -> None:
        self._hooks.remove(callback)

lamp = Appliance(15)
motor = Appliance(16)
