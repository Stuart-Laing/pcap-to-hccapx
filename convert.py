import dpkt
import auth

"""
trash = open("output", "wb")
trash.write(b"\x48\x43\x50\x58")
trash.close()
"""

# TODO
# Have it dynamically find the ESSID

# pcap_path = "Demo-Files/Demo-Pcap-1.pcap"
pcap_path = "Demo-Files/Demo-Pcap-Clean-1.pcap"

pcap_file = open(pcap_path, "rb")
contents = dpkt.pcap.Reader(pcap_file)

msg_num = 1

eapol_packets = []

for timestamp, buffer in contents:
    # print(repr(buffer))
    eapol_packets.append(auth.EAPOL(buffer, msg_num))
    msg_num += 1

file_signature = b"\x48\x43\x50\x58"
version = b"\x04\x00\x00\x00"
message_pair = b"\x00"
essid_length = b"\x06"
essid = b"\x57\x6f\x70\x57\x6f\x70" + (b"\x00" * 26)

key_ver = b"\x02"
key_mic = eapol_packets[1].key_mic

ap_mac = eapol_packets[0].src_mac
ap_nonce = eapol_packets[0].key_nonce

client_mac = eapol_packets[1].src_mac
client_nonce = eapol_packets[1].key_nonce

eapol = eapol_packets[1].eapol
eapol_length = chr(len(eapol)).encode() + b"\x00"

print(len(eapol))
excess_zeros = b"\x00" * (256 - len(eapol))

output_file = open("result_file.hccapx", "wb")
output_file.write(file_signature)
output_file.write(version)
output_file.write(message_pair)
output_file.write(essid_length)
output_file.write(essid)
output_file.write(key_ver)
output_file.write(key_mic)
output_file.write(ap_mac)
output_file.write(ap_nonce)
output_file.write(client_mac)
output_file.write(client_nonce)
output_file.write(eapol_length)
output_file.write(eapol)
output_file.write(excess_zeros)
output_file.close()
