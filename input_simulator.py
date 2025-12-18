import hid
import time
import argparse
import sys
import re
from google.protobuf.internal import decoder

# Try to import protobuf generated code
try:
    import usb_comm_pb2
except ImportError:
    print("Error: usb_comm_pb2 module not found.")
    print("Please compile the protobuf file using protoc.")
    sys.exit(1)

# Default ZMK VID/PID
VENDOR_ID = 0x1d50
PRODUCT_ID = 0x615e

# HID Report ID
REPORT_ID = 1
# Usage Page for the custom interface
USAGE_PAGE = 0xFF14

# Key Mapping (Key Name -> Position)
KEY_MAP = {
    'ESC': 0, 'F1': 1, 'F2': 2, 'F3': 3, 'F4': 4,
    'F5': 5, 'F6': 6, 'F7': 7, 'F8': 8, 'F9': 9,
    'F10': 10, 'F11': 11, 'F12': 12, 'PAUSE': 13, 'BREAK': 13,
    'GRAVE': 14, '`': 14, '1': 15, '2': 16, '3': 17,
    '4': 18, '5': 19, '6': 20, '7': 21, '8': 22,
    '9': 23, '0': 24, '-': 25, '=': 26, 'BACKSPACE': 27, 'BSPC': 27,
    'INSERT': 28, 'INS': 28,
    'TAB': 29, 'Q': 30, 'W': 31, 'E': 32, 'R': 33,
    'T': 34, 'Y': 35, 'U': 36, 'I': 37, 'O': 38,
    'P': 39, '[': 40, ']': 41, '\\': 42, 'DELETE': 43, 'DEL': 43,
    'CAPSLOCK': 44, 'CLCK': 44, 'A': 45, 'S': 46, 'D': 47,
    'F': 48, 'G': 49, 'H': 50, 'J': 51, 'K': 52,
    'L': 53, ';': 54, '\'': 55, 'ENTER': 56, 'RET': 56,
    'PGUP': 57, 'PAGEUP': 57,
    'LSHIFT': 58, 'SHIFT': 58, 'Z': 59, 'X': 60, 'C': 61,
    'V': 62, 'B': 63, 'N': 64, 'M': 65, ',': 66,
    '.': 67, '/': 68, 'RSHIFT': 69, 'UP': 70, 'PGDN': 71, 'PAGEDOWN': 71,
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

def encode_varint(value):
    """Encode an int as a protobuf varint."""
    if value == 0:
        return b'\x00'
    out = []
    while value > 127:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)

def send_message(dev, msg):
    data = msg.SerializeToString()
    # Prepend length as varint
    varint_len = encode_varint(len(data))
    payload = varint_len + data
    
    offset = 0
    while offset < len(payload):
        chunk_size = min(len(payload) - offset, 62)
        chunk = payload[offset : offset + chunk_size]
        
        # Report ID (1) + Len (1) + Chunk (...)
        report = bytearray([REPORT_ID])
        report.append(len(chunk))
        report.extend(chunk)
        
        # Pad to 64 bytes
        padding = 64 - len(report)
        if padding > 0:
            report.extend(bytearray(padding))
            
        dev.write(report)
        offset += chunk_size
        # print(f"Sent chunk: {chunk.hex()}")

def read_message(dev, timeout_ms=1000):
    """Read and reassemble a protobuf message."""
    # This is a simplified reader. It assumes we start reading at the beginning of a message.
    # A robust reader would maintain a buffer across calls.
    
    buffer = bytearray()
    start_time = time.time()
    
    while (time.time() - start_time) * 1000 < timeout_ms:
        try:
            # hid.read returns a list of integers
            # max length is 64 usually
            report = dev.read(64, timeout_ms=100)
            if not report:
                continue
            
            # report[0] might be Report ID if using read(), but usually hidapi returns data content.
            # On Windows/hidapi, if report ID is used, the first byte might be it.
            # However, ZMK firmware sends: [Len, Data...] inside the report.
            # Let's inspect.
            
            # If report is [1, Len, Data...], then report[0] is ID.
            # If report is [Len, Data...], then report[0] is Len.
            
            # Usually hidapi read returns the Report ID as first byte if it's non-zero.
            
            data_start = 0
            if report[0] == REPORT_ID:
                data_start = 1
            
            # Check length byte
            if len(report) > data_start:
                chunk_len = report[data_start]
                if chunk_len > 0:
                    chunk = report[data_start+1 : data_start+1+chunk_len]
                    buffer.extend(chunk)
                    
                    # Try to decode
                    # Read varint length from buffer
                    try:
                        # decode_varint returns (value, new_pos)
                        msg_len, new_pos = decoder._DecodeVarint(buffer, 0)
                        
                        if len(buffer) >= new_pos + msg_len:
                            # Full message received
                            msg_data = buffer[new_pos : new_pos + msg_len]
                            msg = usb_comm_pb2.MessageD2H()
                            msg.ParseFromString(msg_data)
                            return msg
                    except (IndexError, decoder._DecodeError):
                        # Not enough data yet
                        pass
        except Exception as e:
            # print(f"Read error: {e}")
            pass
            
    return None

def send_simulate_input(dev, position, pressed):
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.SIMULATE_INPUT
    msg.simulate_input.position = position
    msg.simulate_input.pressed = pressed
    send_message(dev, msg)

def parse_combo(combo_str):
    keys = [k.strip().upper() for k in re.split(r'[+\s]+', combo_str)]
    return keys

def execute_keys(dev, keys, delay=0.05):
    active_keys = []
    for k in keys:
        if k not in KEY_MAP:
            print(f"Warning: Key '{k}' not found in map.")
            continue
        
        position = KEY_MAP[k]
        print(f"Pressing {k} (Pos {position})")
        send_simulate_input(dev, position, True)
        active_keys.append(position)
        time.sleep(0.01)

    time.sleep(delay)

    for position in reversed(active_keys):
        print(f"Releasing (Pos {position})")
        send_simulate_input(dev, position, False)
        time.sleep(0.01)

def send_otp_set_time(dev):
    timestamp = int(time.time())
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.OTP_SET_TIME
    msg.otp_set_time.timestamp = timestamp
    
    send_message(dev, msg)
    print(f"Sent time: {timestamp}")
    
    # Wait for response
    resp = read_message(dev)
    if resp and resp.action == usb_comm_pb2.Action.OTP_SET_TIME:
        print(f"Success! Firmware confirmed time: {resp.otp_set_time.timestamp}")
    else:
        print("No confirmation received.")

def send_otp_set_secret(dev, secret_str):
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.OTP_SET_SECRET
    msg.otp_set_secret.secret = secret_str.encode('utf-8')
    
    send_message(dev, msg)
    print(f"Sent secret: {secret_str}")
    
    resp = read_message(dev)
    if resp and resp.action == usb_comm_pb2.Action.OTP_SET_SECRET:
         print("Success! Secret set confirmed.")
    else:
         print("No confirmation received.")

def get_otp_state(dev):
    msg = usb_comm_pb2.MessageH2D()
    msg.action = usb_comm_pb2.Action.OTP_GET_STATE
    
    send_message(dev, msg)
    print("Requesting OTP state...")
    
    resp = read_message(dev)
    if resp and resp.action == usb_comm_pb2.Action.OTP_GET_STATE:
        print(f"Current OTP Code: {resp.otp_state.code}")
        if resp.otp_state.HasField('remaining'):
            print(f"Remaining: {resp.otp_state.remaining}s")
    else:
        print("No response received.")

def main():
    parser = argparse.ArgumentParser(description="Simulate key presses on HW-75.")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=VENDOR_ID, help="Vendor ID")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=PRODUCT_ID, help="Product ID")
    parser.add_argument("--combo", type=str, help="Key combo (e.g. 'CTRL+C', 'A', 'SHIFT+A')")
    parser.add_argument("--text", type=str, help="Type a string of text")
    parser.add_argument("--otp-sync-time", action="store_true", help="Sync PC time to keyboard for OTP")
    parser.add_argument("--otp-secret", type=str, help="Set OTP secret string")
    parser.add_argument("--otp-get", action="store_true", help="Get current OTP code")
    
    args = parser.parse_args()

    if not any([args.combo, args.text, args.otp_sync_time, args.otp_secret, args.otp_get]):
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
            
        if args.otp_get:
            get_otp_state(dev)
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
