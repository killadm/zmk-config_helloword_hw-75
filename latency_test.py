import hid
import time
import threading
import argparse
import sys
import os

# Try to import protobuf generated code
try:
    import usb_comm_pb2
except ImportError:
    print("Error: usb_comm_pb2 module not found.")
    print("Please compile the protobuf file using protoc:")
    print("  protoc -I=config/proto --python_out=. config/proto/usb_comm.proto")
    sys.exit(1)

try:
    from pynput import keyboard
except ImportError:
    print("Error: pynput module not found.")
    print("Please install it: pip install pynput")
    sys.exit(1)

# Default ZMK VID/PID
VENDOR_ID = 0x1d50
PRODUCT_ID = 0x615e

# HID Report ID
REPORT_ID = 1
# Usage Page for the custom interface
USAGE_PAGE = 0xFF14

def find_device(vid, pid, usage_page):
    for device_dict in hid.enumerate():
        if device_dict['vendor_id'] == vid and device_dict['product_id'] == pid:
            if device_dict['usage_page'] == usage_page:
                return device_dict
    return None

def send_simulate_input(dev, position, pressed):
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.SIMULATE_INPUT
    msg.simulate_input.position = position
    msg.simulate_input.pressed = pressed

    data = msg.SerializeToString()
    
    # Packetize (matches usb_comm_hid.c logic)
    # Report ID (1) + Length (1) + Data (62)
    report = bytearray([REPORT_ID]) + bytearray([len(data)]) + data + bytearray(64 - len(data) - 2)
    
    dev.write(report)

class LatencyTester:
    def __init__(self):
        self.start_time = 0
        self.end_time = 0
        self.received = threading.Event()
        self.target_key = None

    def on_press(self, key):
        try:
            if key.char == self.target_key:
                self.end_time = time.perf_counter()
                self.received.set()
        except AttributeError:
            pass

    def test(self, dev, position, char):
        self.target_key = char
        self.received.clear()
        
        listener = keyboard.Listener(on_press=self.on_press)
        listener.start()
        
        # Wait a bit for listener to start
        time.sleep(0.1)
        
        print(f"Simulating press of '{char}' (pos={position})...")
        self.start_time = time.perf_counter()
        send_simulate_input(dev, position, True)
        
        if self.received.wait(timeout=1.0):
            latency_ms = (self.end_time - self.start_time) * 1000
            print(f"Success! Latency: {latency_ms:.2f} ms")
            
            # Release the key
            time.sleep(0.1)
            send_simulate_input(dev, position, False)
        else:
            print("Timeout waiting for key press.")
            # Ensure release
            send_simulate_input(dev, position, False)
            
        listener.stop()

def main():
    parser = argparse.ArgumentParser(description="Test latency of simulated key presses.")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=VENDOR_ID, help="Vendor ID (default: 0x1d50)")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=PRODUCT_ID, help="Product ID (default: 0x615e)")
    parser.add_argument("--pos", type=int, required=True, help="Matrix position of the key to simulate")
    parser.add_argument("--char", type=str, required=True, help="Expected character output (e.g. 'a')")
    
    args = parser.parse_args()

    print(f"Looking for device {hex(args.vid)}:{hex(args.pid)} with usage page {hex(USAGE_PAGE)}...")
    device_info = find_device(args.vid, args.pid, USAGE_PAGE)
    
    if not device_info:
        print("Device not found. Make sure the keyboard is connected and the firmware is updated.")
        sys.exit(1)
        
    print(f"Found device: {device_info['path']}")
    
    try:
        dev = hid.device()
        dev.open_path(device_info['path'])
        
        tester = LatencyTester()
        tester.test(dev, args.pos, args.char)
        
        dev.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
