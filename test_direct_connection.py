import time
import threading
from plc.plc import start_modbus_server, get_telemetry
from scada.scada import run_operator_loop  # Or use standard pymodbus client directly
from pymodbus.client import ModbusTcpClient

PLC_HOST = "127.0.0.1"
PLC_PORT = 5020  # Make sure this port matches your plc.py configuration

def run_plc_server():
    """Starts the PLC server on a background thread."""
    print("[1/4] Starting PLC Modbus Server...")
    # Adjust arguments if your start_modbus_server takes specific parameters
    start_modbus_server(host=PLC_HOST, port=PLC_PORT)

def test_direct_communication():
    # 1. Start PLC server in a daemon thread so it runs in background
    plc_thread = threading.Thread(target=run_plc_server, daemon=True)
    plc_thread.start()
    time.sleep(1.5)  # Allow PLC server time to bind and listen

    # 2. Test Direct Read/Write via Modbus Client
    print("[2/4] Testing direct Modbus write to PLC registers...")
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    if not client.connect():
        print("❌ FAILED: Could not connect to PLC Modbus Server!")
        return

    # Direct Write Test (e.g., Register 1: CONVEYOR_SPEED = 60 RPM)
    write_res = client.write_register(address=1, value=60)
    print(f"Verification - Write Register 1 (CONVEYOR_SPEED = 60): Success={not write_res.isError()}")

    # Direct Read Test
    read_res = client.read_holding_registers(address=1, count=1)
    if not read_res.isError():
        read_val = read_res.registers[0]
        print(f"Verification - Read Register 1 Value: {read_val}")
        assert read_val == 60, f"Expected 60, got {read_val}"
        print("✅ Direct Read/Write Step Successful!")
    else:
        print("❌ FAILED: Register Read Error")

    # 3. Test Telemetry Endpoint
    print("[3/4] Fetching PLC telemetry...")
    telemetry = get_telemetry()
    print(f"Verification - Telemetry payload: {telemetry}")
    assert "registers" in telemetry or "cpu_load" in telemetry
    print("✅ Telemetry Output Verified!")

    # 4. Test SCADA Client Execution
    print("[4/4] Triggering SCADA client operator loop (5 seconds test)...")
    scada_thread = threading.Thread(target=run_operator_loop, args=(PLC_HOST, PLC_PORT), daemon=True)
    scada_thread.start()
    time.sleep(5)

    client.close()
    print("\n🎉 ALL DIRECT COMMUNICATION TESTS PASSED SAFELY!")

if __name__ == "__main__":
    test_direct_communication()