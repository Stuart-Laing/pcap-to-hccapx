import dpkt


def pretty(data):
    output_string = ""
    for thing in data:
        if len(hex(thing)[2:]) == 1:
            output_string += "0" + hex(thing)[2:]
        else:
            output_string += hex(thing)[2:]
    return output_string


class EAPOL:
    def __init__(self, data, msg_num):

        self.src_mac = data[10:16]
        self.dst_mac = data[4:10]

        ieee_packet = dpkt.ieee80211.IEEE80211(data)

        self.key_descriptor_type = ieee_packet.data[12:13]
        self.message_number = msg_num
        self.key_mic = ieee_packet.data[89:105]
        self.key_nonce = ieee_packet.data[25:57]
        self.eapol = ieee_packet.data[8:89] + (b"\x00" * 16) + ieee_packet.data[105:]

        #if msg_num == 2:
        #    print(pretty(ieee_packet.data[8:]))
        #    print(pretty(self.eapol))
        #    print("""0103007502010a00000000000000000001d4ef6125ff9344e00e633e8db71f754a4a634ca572d9b6631f8a510179049480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000""")

    def __repr__(self):
        output_string = "EAPOL("
        output_string += f"src_mac={self.src_mac}, "
        output_string += f"dst_mac={self.dst_mac}, "
        output_string += f"key_descriptor_type={self.key_descriptor_type}, "
        output_string += f"message_number={self.message_number}, "
        output_string += f"key_mic={self.key_mic}, "
        output_string += f"key_nonce={self.key_nonce}, "
        output_string += f"eapol={self.eapol})"
        return output_string
