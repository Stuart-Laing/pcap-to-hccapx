import dpkt


class EAPOL:
    def __init__(self, data, msg_num):

        self.src_mac = data[10:16]
        self.dst_mac = data[4:10]

        ieee_packet = dpkt.ieee80211.IEEE80211(data)
        print(ieee_packet.data)

        self.key_descriptor_type = ieee_packet.data[12:13]
        self.message_number = msg_num
        self.key_mic = ieee_packet.data[89:105]
        self.key_nonce = ieee_packet.data[25:57]
        self.eapol = ieee_packet.data[8:89] + ieee_packet.data[105:]

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
