from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient("127.0.0.1", port=5020)
client.connect()

# Register addresses match plc.py directly: TANK_PRESSURE=0, CONVEYOR_SPEED=1, COOLING_VALVE=2
result = client.read_holding_registers(0, count=3, slave=1)
print("Initial values:", result.registers if not result.isError() else result)

# Write COOLING_VALVE (register 2) to 80.0 degrees -> scaled = 800
client.write_register(2, 800, slave=1)

# Watch it ramp up over a few seconds instead of jumping instantly
for _ in range(10):
    time.sleep(1)
    result = client.read_holding_registers(0, count=3, slave=1)
    print("Registers:", result.registers if not result.isError() else result)

client.close()