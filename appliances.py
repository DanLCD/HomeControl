from RPi import GPIO 

GPIO.setmode(GPIO.BOARD)

class Appliance:
    def __init__(self, pin: int) -> None:
        self.pin = pin
        self._state = False
        GPIO.setup(pin, GPIO.LOW)

    @property
    def state(self) -> bool:
        return self._state

    @state.setter
    def state(self, state: bool) -> None:
        self._state = state
        GPIO.output(self.pin, state)

    def set_state(self, state: bool) -> None:
        self.state = state

lamp = Appliance(15)
motor = Appliance(16)
