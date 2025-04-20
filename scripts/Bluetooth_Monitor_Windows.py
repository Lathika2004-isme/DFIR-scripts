import wmi
import time
import logging


logging.basicConfig(filename='bluetooth_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def get_bluetooth_devices():
    c = wmi.WMI()
    devices = []
    for device in c.Win32_PnPEntity( PNPClass='Bluetooth' ):
        devices.append(device.DeviceID)
    return devices

def main():
    previous_devices = set()
    while True:
        current_devices = set(get_bluetooth_devices())
        for device in current_devices - previous_devices:
            logging.info(f"Device connected: {device}")
        for device in previous_devices - current_devices:
            logging.info(f"Device disconnected: {device}")
        previous_devices = current_devices
        time.sleep(1) 

if __name__ == "__main__":
    main()