from .conversions import byte_mac_to_str
from .conversions import convert_timestamp


__all__ = ["EAPOL"]


class EAPOL:
    def __init__(self, timestamp, buffer):
        if buffer[0] != 0x88:
            raise ValueError

        if buffer[32:34] != b"\x88\x8e":
            raise ValueError

        version = buffer[34]
        replay_counter = buffer[50]

        # Can do this differently, Each message number has a different set of data and can figure it out that way
        if version == 1 and replay_counter == 1:
            self.message_number = 2
        elif version == 1 and replay_counter == 2:
            self.message_number = 4
        elif version == 2 and replay_counter == 1:
            self.message_number = 1
        elif version == 2 and replay_counter == 2:
            self.message_number = 3

        self.timestamp = timestamp

        if self.message_number in (1, 3):
            self.ap_mac = buffer[10:16]
            self.device_mac = buffer[4:10]

        else:
            self.device_mac = buffer[10:16]
            self.ap_mac = buffer[4:10]

        self.key_nonce = buffer[51:83]
        self.key_mic = buffer[115:131]

    def __repr__(self):
        output_string = "EAPOL("
        output_string += f"timestamp={self.timestamp}, "
        output_string += f"ap_mac={self.ap_mac}, "
        output_string += f"device_mac={self.device_mac}, "
        output_string += f"key_nonce={self.key_nonce}, "
        output_string += f"key_mic={self.key_mic}, "
        output_string += f"message_number={self.message_number})"

        return output_string

    def __str__(self):
        output_string = f"        AP MAC Address    : {byte_mac_to_str(self.ap_mac)}"
        output_string += f"\n        Device MAC Address: {byte_mac_to_str(self.device_mac)}"
        output_string += f"\n        Timestamp         : {convert_timestamp(self.timestamp)}"

        return output_string
