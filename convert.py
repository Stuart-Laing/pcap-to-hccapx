import dpkt
import sys
import argcurse

import auth

# TODO
# ########## Have it dynamically find the ESSID
# Proper Command Line Arguments
# ########## Have it work with files that contain more than just eapol packets
# ########## Have it work with files with multiple 4 way handshakes
# Allow specification of different message pairs
# Allow specification of specific eapol handshakes
# Handle WPA 1
# Verify given arguments


HELP_MSG = """Usage: convert.py [options] -i input_zip_file

Options:
 |                 Flags              |          Description          | Required |      Default     |        
 +------------------------------------+-------------------------------+----------+------------------+
 |  -i --input-pcap <file path>       | Input pcap file path          | Yes      | None             |
 |  -o --output-file <file path>      | Output hccapx file path       | No       | ./results.hccapx |
 |  -e --essid <essid>                | ESSID of the ap               | No       | None             |
 |  -mp --message-pair <message pair> | Message pair used in the file | No       | 0                |
 |  -ap --access-mac <mac adr>        | Mac address of access point   | No       | None             |
 |  -cl --client-mac <mac adr>        | Mac address of client         | No       | None             |
 |  -h --help                         | Prints this message
 """

DEFAULT_MSG = """Usage: convert.py [options] -i input_zip_file
Try -h or --help for more info."""

arg_handler = argcurse.Handler("-h", "--help", HELP_MSG)
arg_handler.add_default(DEFAULT_MSG)

arg_handler.add_flag("-i", "--input-pcap", has_content=True, required=True)
arg_handler.add_flag("-o", "--output-file", has_content=True)
arg_handler.add_flag("-e", "--essid", has_content=True)
arg_handler.add_flag("-mp", "--message-pair", has_content=True)
arg_handler.add_flag("-ap", "--access-mac", has_content=True)
arg_handler.add_flag("-cl", "--client-mac", has_content=True)

arg_handler.compile()


def verify_eapol_packet(packet_buffer):
    try:
        _ = dpkt.ieee80211.IEEE80211(packet_buffer)
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


pcap_path = arg_handler.results["-i"]

pcap_file = open(pcap_path, "rb")
contents = dpkt.pcap.Reader(pcap_file)

handshakes = []

msg_num = 1
handshake_index = 0
for timestamp, buffer in contents:
    if verify_eapol_packet(buffer):
        if msg_num == 1:
            handshakes.append(auth.Handshake())
            handshakes[handshake_index].add_eapol_packet(buffer, msg_num)

            msg_num += 1

        elif msg_num == 2 or msg_num == 3:
            handshakes[handshake_index].add_eapol_packet(buffer, msg_num)

            msg_num += 1

        elif msg_num == 4:
            handshakes[handshake_index].add_eapol_packet(buffer, msg_num)

            msg_num = 1
            handshake_index += 1

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

if handshakes[0].message_num != 4:
    print("ERR")
    exit()

write_contents = {"file_signature": b"\x48\x43\x50\x58",
                  "version": b"\x04\x00\x00\x00",
                  "message_pair": b"\x00",
                  "essid_length": chr(essid_length).encode(),
                  "essid": essid + (b"\x00" * (32 - essid_length)),
                  "key_ver": b"\x02",
                  "key_mic": handshakes[0].m2.key_mic,
                  "ap_mac": handshakes[0].m1.src_mac,
                  "ap_nonce": handshakes[0].m1.key_nonce,
                  "client_mac": handshakes[0].m2.src_mac,
                  "client_nonce": handshakes[0].m2.key_nonce,
                  "eapol_length": chr(len(handshakes[0].m2.eapol)).encode() + b"\x00",
                  "eapol": handshakes[0].m2.eapol,
                  "buffer_zeros": b"\x00" * (256 - len(handshakes[0].m2.eapol))}

if arg_handler.results["-o"]:
    output_file_path = arg_handler.results["-o"]
else:
    output_file_path = "results.hccapx"

output_file = open(output_file_path, "wb")

for value in write_contents.values():
    output_file.write(value)
output_file.close()
