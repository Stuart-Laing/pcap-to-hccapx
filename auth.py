import dpkt


def __pretty(data):
    output_string = ""
    for thing in data:
        if len(hex(thing)[2:]) == 1:
            output_string += "0" + hex(thing)[2:]
        else:
            output_string += hex(thing)[2:]
    return output_string


class Handshake:
    def __init__(self):
        self.m1 = EAPOL
        self.m2 = EAPOL
        self.m3 = EAPOL
        self.m4 = EAPOL
        self.message_num = 0

    def add_eapol_packet(self, data, msg_num):
        if msg_num == 1:
            self.m1 = EAPOL(data)
            self.message_num += 1

        elif msg_num == 2:
            self.m2 = EAPOL(data)
            self.message_num += 1

        elif msg_num == 3:
            self.m3 = EAPOL(data)
            self.message_num += 1

        elif msg_num == 4:
            self.m4 = EAPOL(data)
            self.message_num += 1


class EAPOL:
    def __init__(self, data):

        self.src_mac = data[10:16]
        self.dst_mac = data[4:10]

        ieee_packet = dpkt.ieee80211.IEEE80211(data)

        self.key_descriptor_type = ieee_packet.data[12:13]
        # self.message_number = msg_num
        self.key_mic = ieee_packet.data[89:105]
        self.key_nonce = ieee_packet.data[25:57]
        self.eapol = ieee_packet.data[8:89] + (b"\x00" * 16) + ieee_packet.data[105:]

    def __repr__(self):
        output_string = "EAPOL("
        output_string += f"src_mac={self.src_mac}, "
        output_string += f"dst_mac={self.dst_mac}, "
        output_string += f"key_descriptor_type={self.key_descriptor_type}, "
        # output_string += f"message_number={self.message_number}, "
        output_string += f"key_mic={self.key_mic}, "
        output_string += f"key_nonce={self.key_nonce}, "
        output_string += f"eapol={self.eapol})"
        return output_string
