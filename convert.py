import dpkt
import sys

import auth


# TODO
# ########## Have it dynamically find the ESSID
# Proper Command Line Arguments
# ########## Have it work with files that contain more than just eapol packets
# Have it work with files with multiple 4 way handshakes
# Allow specification of different message pairs
# Allow specification of specific eapol handshakes
# Handle WPA 1
# Verify given arguments

def verify_eapol_packet(packet_buffer):
    try:
        _ = dpkt.ieee80211.IEEE80211(buffer)
    except dpkt.dpkt.UnpackError:
        return False

    if buffer[0] != 0x88:
        return False

    if buffer[32:34] != b"\x88\x8e":
        return False

    return True


def find_essid(packet_buffer):
    if packet_buffer[0] != 0x50:
        return "", 0
    ieee_packet = dpkt.ieee80211.IEEE80211(packet_buffer).data

    length = ieee_packet[1]
    name = ieee_packet[2:length + 2]

    return name, length


# pcap_path = "Demo-Files/Demo-Pcap-Clean-1.pcap"
if len(sys.argv) == 2:
    pcap_path = sys.argv[1]
else:
    pcap_path = "Demo-Files/Demo-Pcap-1.pcap"

pcap_file = open(pcap_path, "rb")
contents = dpkt.pcap.Reader(pcap_file)

msg_num = 1

eapol_packets = []

for timestamp, buffer in contents:
    if verify_eapol_packet(buffer):
        eapol_packets.append(auth.EAPOL(buffer, msg_num))
        msg_num += 1
    else:
        temp_essid, temp_essid_length = find_essid(buffer)
        if temp_essid:
            essid = temp_essid
            essid_length = temp_essid_length

try:
    essid
    essid_length
except NameError:
    print("No Essid Found")
    exit()

if len(eapol_packets) != 4:
    print("ERR")
    exit()

write_contents = {"file_signature": b"\x48\x43\x50\x58",
                  "version": b"\x04\x00\x00\x00",
                  "message_pair": b"\x00",
                  "essid_length": chr(essid_length).encode(),
                  "essid": essid + (b"\x00" * (32 - essid_length)),
                  "key_ver": b"\x02",
                  "key_mic": eapol_packets[1].key_mic,
                  "ap_mac": eapol_packets[0].src_mac,
                  "ap_nonce": eapol_packets[0].key_nonce,
                  "client_mac": eapol_packets[1].src_mac,
                  "client_nonce": eapol_packets[1].key_nonce,
                  "eapol_length": chr(len(eapol_packets[1].eapol)).encode() + b"\x00",
                  "eapol": eapol_packets[1].eapol,
                  "buffer_zeros": b"\x00" * (256 - len(eapol_packets[1].eapol))}

output_file = open("result_file.hccapx", "wb")
for value in write_contents.values():
    output_file.write(value)
output_file.close()
