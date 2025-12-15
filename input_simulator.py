import hid
import time
import argparse
import sys
import re

# Try to import protobuf generated code
try:
    import usb_comm_pb2
except ImportError:
    print("Error: usb_comm_pb2 module not found.")
    print("Please compile the protobuf file using protoc:")
    print("  protoc -I=config/proto --python_out=. config/proto/usb_comm.proto")
    sys.exit(1)

# Default ZMK VID/PID
VENDOR_ID = 0x1d50
PRODUCT_ID = 0x615e

# HID Report ID
REPORT_ID = 1
# Usage Page for the custom interface
USAGE_PAGE = 0xFF14

# Key Mapping (Key Name -> Position)
# Derived from hw75_keyboard.dts default_transform
KEY_MAP = {
    # Row 1
    'ESC': 0, 'F1': 1, 'F2': 2, 'F3': 3, 'F4': 4,
    'F5': 5, 'F6': 6, 'F7': 7, 'F8': 8, 'F9': 9,
    'F10': 10, 'F11': 11, 'F12': 12, 'PAUSE': 13, 'BREAK': 13,

    # Row 2
    'GRAVE': 14, '`': 14, '1': 15, '2': 16, '3': 17,
    '4': 18, '5': 19, '6': 20, '7': 21, '8': 22,
    '9': 23, '0': 24, '-': 25, '=': 26, 'BACKSPACE': 27, 'BSPC': 27,
    'INSERT': 28, 'INS': 28,

    # Row 3
    'TAB': 29, 'Q': 30, 'W': 31, 'E': 32, 'R': 33,
    'T': 34, 'Y': 35, 'U': 36, 'I': 37, 'O': 38,
    'P': 39, '[': 40, ']': 41, '\\': 42, 'DELETE': 43, 'DEL': 43,

    # Row 4
    'CAPSLOCK': 44, 'CLCK': 44, 'A': 45, 'S': 46, 'D': 47,
    'F': 48, 'G': 49, 'H': 50, 'J': 51, 'K': 52,
    'L': 53, ';': 54, '\'': 55, 'ENTER': 56, 'RET': 56,
    'PGUP': 57, 'PAGEUP': 57,

    # Row 5
    'LSHIFT': 58, 'SHIFT': 58, 'Z': 59, 'X': 60, 'C': 61,
    'V': 62, 'B': 63, 'N': 64, 'M': 65, ',': 66,
    '.': 67, '/': 68, 'RSHIFT': 69, 'UP': 70, 'PGDN': 71, 'PAGEDOWN': 71,

    # Row 6
    'LCTRL': 72, 'CTRL': 72, 'LGUI': 73, 'WIN': 73, 'CMD': 73,
    'LALT': 74, 'ALT': 74, 'SPACE': 75, 'RALT': 76,
    'FN': 77, 'RCTRL': 78, 'LEFT': 79, 'DOWN': 80, 'RIGHT': 81,
}

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
    
    # Packetize
    report = bytearray([REPORT_ID]) + bytearray([len(data)]) + data + bytearray(64 - len(data) - 2)
    dev.write(report)

def parse_combo(combo_str):
    keys = [k.strip().upper() for k in re.split(r'[+\s]+', combo_str)]
    return keys

def execute_keys(dev, keys, delay=0.05):
    # Press all keys in sequence
    active_keys = []
    for k in keys:
        if k not in KEY_MAP:
            print(f"Warning: Key '{k}' not found in map.")
            continue
        
        position = KEY_MAP[k]
        print(f"Pressing {k} (Pos {position})")
        send_simulate_input(dev, position, True)
        active_keys.append(position)
        time.sleep(0.01) # Small delay between presses

    time.sleep(delay)

    # Release all keys in reverse order
    for position in reversed(active_keys):
        print(f"Releasing (Pos {position})")
        send_simulate_input(dev, position, False)
        time.sleep(0.01)

def send_otp_set_time(dev):
    timestamp = int(time.time())
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.OTP_SET_TIME
    msg.otp_set_time.timestamp = timestamp
    
    data = msg.SerializeToString()
    report = bytearray([REPORT_ID]) + bytearray([len(data)]) + data + bytearray(64 - len(data) - 2)
    dev.write(report)
    print(f"Set time to {timestamp}")

def send_otp_set_secret(dev, secret_str):
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.OTP_SET_SECRET
    msg.otp_set_secret.secret = secret_str.encode('utf-8')
    
    data = msg.SerializeToString()
    report = bytearray([REPORT_ID]) + bytearray([len(data)]) + data + bytearray(64 - len(data) - 2)
    dev.write(report)
    print(f"Set secret to {secret_str}")

def main():
    parser = argparse.ArgumentParser(description="Simulate key presses on HW-75.")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=VENDOR_ID, help="Vendor ID")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=PRODUCT_ID, help="Product ID")
    parser.add_argument("--combo", type=str, help="Key combo (e.g. 'CTRL+C', 'A', 'SHIFT+A')")
    parser.add_argument("--text", type=str, help="Type a string of text")
    parser.add_argument("--otp-sync-time", action="store_true", help="Sync PC time to keyboard for OTP")
    parser.add_argument("--otp-secret", type=str, help="Set OTP secret string")
    
    args = parser.parse_args()

    if not any([args.combo, args.text, args.otp_sync_time, args.otp_secret]):
        parser.print_help()
        sys.exit(1)

    print(f"Looking for device {hex(args.vid)}:{hex(args.pid)}...")
    device_info = find_device(args.vid, args.pid, USAGE_PAGE)
    
    if not device_info:
        print("Device not found.")
        sys.exit(1)
        
    try:
        dev = hid.device()
        dev.open_path(device_info['path'])
        
        if args.otp_secret:
            send_otp_set_secret(dev, args.otp_secret)
            time.sleep(0.1)

        if args.otp_sync_time:
            send_otp_set_time(dev)
            time.sleep(0.1)

        if args.combo:
            keys = parse_combo(args.combo)
            execute_keys(dev, keys)
            
        if args.text:
            for char in args.text:
                key = char.upper()
                if char.isupper() or char in '!@#$%^&*()_+{}|:"<>?~':
                    execute_keys(dev, ['SHIFT', key])
                else:
                    execute_keys(dev, [key])
                time.sleep(0.05)
        
        dev.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
