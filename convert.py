import dpkt
import auth

# TODO
# Have it dynamically find the ESSID

# pcap_path = "Demo-Files/Demo-Pcap-1.pcap"
pcap_path = "Demo-Files/Demo-Pcap-Clean-1.pcap"

pcap_file = open(pcap_path, "rb")
contents = dpkt.pcap.Reader(pcap_file)

msg_num = 1

for timestamp, buffer in contents:
    # print(repr(buffer))
    wow = auth.EAPOL(buffer, msg_num)
    print(repr(wow))
    msg_num += 1
