import dpkt

from . import Handshake
from . import EAPOL


__all__ = ["get_handshakes", "get_essids"]


def get_handshakes(file_path):
    pcap_file = open(file_path, "rb")
    contents = dpkt.pcap.Reader(pcap_file)

    eapol_messages = []

    for timestamp, buffer in contents:
        try:
            current_frame = EAPOL(timestamp, buffer)
            eapol_messages.append(current_frame)

        except dpkt.dpkt.UnpackError:
            pass

        except ValueError:
            pass

    eapol_by_mac_address = {}  # {(<AP MAC, Device MAC>): [EAPOL]}

    for eapol in eapol_messages:
        mac_address_tuple = (eapol.ap_mac, eapol.device_mac)

        if mac_address_tuple in eapol_by_mac_address:
            eapol_by_mac_address[mac_address_tuple] += [eapol]

        else:
            eapol_by_mac_address[mac_address_tuple] = [eapol]

    complete_handshakes = []
    loose_messages = []

    current_handshake_message_indexes = []
    current_handshake_message_numbers = []
    for key, item in eapol_by_mac_address.items():
        for eapol_index, eapol in enumerate(item):
            if eapol.message_number == 1:
                if not current_handshake_message_numbers:
                    # if current_handshake_message_numbers == []
                    current_handshake_message_indexes.append(eapol_index)
                    current_handshake_message_numbers.append(eapol.message_number)

                else:
                    loose_messages += [item[i] for i in current_handshake_message_indexes]

                    current_handshake_message_indexes = [eapol_index]
                    current_handshake_message_numbers = [eapol.message_number]
            elif eapol.message_number == 2:
                if current_handshake_message_numbers == [1]:
                    current_handshake_message_indexes.append(eapol_index)
                    current_handshake_message_numbers.append(eapol.message_number)

                else:
                    current_handshake_message_indexes.append(eapol_index)
                    loose_messages += [item[i] for i in current_handshake_message_indexes]

                    current_handshake_message_indexes = []
                    current_handshake_message_numbers = []
            elif eapol.message_number == 3:
                if current_handshake_message_numbers == [1, 2]:
                    current_handshake_message_indexes.append(eapol_index)
                    current_handshake_message_numbers.append(eapol.message_number)

                else:
                    current_handshake_message_indexes.append(eapol_index)
                    loose_messages += [item[i] for i in current_handshake_message_indexes]

                    current_handshake_message_indexes = []
                    current_handshake_message_numbers = []
            elif eapol.message_number == 4:
                if current_handshake_message_numbers == [1, 2, 3]:
                    complete_handshakes.append(
                        Handshake(item[current_handshake_message_indexes[0]],
                                                 item[current_handshake_message_indexes[1]],
                                                 item[current_handshake_message_indexes[2]], item[eapol_index]))

                    current_handshake_message_indexes = []
                    current_handshake_message_numbers = []

                else:
                    current_handshake_message_indexes.append(eapol_index)
                    loose_messages += [item[i] for i in current_handshake_message_indexes]

                    current_handshake_message_indexes = []
                    current_handshake_message_numbers = []

        if current_handshake_message_numbers:
            loose_messages += [item[i] for i in current_handshake_message_indexes]

    return complete_handshakes, loose_messages


def get_essids(file_path):
    pcap_file = open(file_path, "rb")
    contents = dpkt.pcap.Reader(pcap_file)

    essids = {}  # {<AP MAC>: <essid>}

    for timestamp, buffer in contents:
        if buffer[0] == 0x50:
            essid_length = buffer[37]
            essid = buffer[38:38 + essid_length].decode()

            ap_mac = buffer[10:16]

            essids[ap_mac] = essid
    return essids
