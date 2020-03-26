from .conversions import byte_mac_to_str
from .conversions import convert_timestamp


__all__ = ["Handshake"]


class Handshake:
    def __init__(self, message_1, message_2, message_3, message_4):
        self.message_1 = message_1
        self.message_2 = message_2
        self.message_3 = message_3
        self.message_4 = message_4

        self.ap_mac = message_1.ap_mac
        self.device_mac = message_1.device_mac

        self.start_time = message_1.timestamp
        self.end_time = message_4.timestamp

    def __str__(self):
        output_string = f"        AP MAC Address    : {byte_mac_to_str(self.ap_mac)}"
        output_string += f"\n        Device MAC Address: {byte_mac_to_str(self.device_mac)}"
        output_string += f"\n        Start Time        : {convert_timestamp(self.start_time)}"
        output_string += f"\n        End Time          : {convert_timestamp(self.end_time)}"

        return output_string

    def create_file(self, essid):
        output_byte_string = b"\x48\x43\x50\x58"                                 # File Signature
        output_byte_string += b"\x04\x00\x00\x00"                                # Version
        output_byte_string += b"\x00"                                            # Message Pair
        output_byte_string += chr(len(essid)).encode()                           # ESSID Length
        output_byte_string += essid.encode() + (b"\x00" * (32 - len(essid)))     # ESSID
        output_byte_string += b"\x02"                                            # Key Version
        output_byte_string += self.message_2.key_mic                             # Key MIC
        output_byte_string += self.ap_mac                                        # AP MAC Address
        output_byte_string += self.message_1.key_nonce                           # AP Nonce
        output_byte_string += self.device_mac                                    # Device MAC Address
        output_byte_string += self.message_2.key_nonce                           # Device Nonce
        output_byte_string += chr(len(self.message_2.eapol)).encode() + b"\x00"  # EAPOL Length
        output_byte_string += self.message_2.eapol                               # EAPOL
        output_byte_string += b"\x00" * (256 - len(self.message_2.eapol))        # Buffer Zeroes

        return output_byte_string
