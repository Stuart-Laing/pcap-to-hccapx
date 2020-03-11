import argcurse
import dpkt

import pcap_to_hccapx


# arg_handler = argcurse.Handler("-h", "--help", using_modes=True, args=["get-info", "demo-files/valid/2-handshakes.pcap"])
arg_handler = argcurse.Handler("-h", "--help", using_modes=True, args=["get-info", "demo-files/valid-and-invalid/3-handshakes-no-essid-missing-none-3, 4-3, 4.pcap"])

arg_handler.add_mode("get-info", "Get information about the handshakes inside of the file")
arg_handler.add_mode("make-file", "Make a hccapx file from a handshake in a file")

arg_handler.add_flag("-o", "--output-file", description="Output hccapx file path", mode="make-file",
                     content_help="<file path>", has_content=True, default="./results.hccapx")
arg_handler.add_flag("-e", "--essid", description="ESSID of the ap if it cannot be found", mode="make-file",
                     content_help="<essid>", has_content=True, default="Found Automatically")
arg_handler.add_flag("-i", "--index", description="The index of the handshake, found by using 'get-info'",
                     mode="make-file", content_help="<Index>", has_content=True)

arg_handler.add_file(file_required=True, mode="make-file")
arg_handler.add_file(file_required=True, mode="get-info")

arg_handler.generate_default_message("pcap_to_hccapx")
arg_handler.generate_help_message("pcap_to_hccapx")

arg_handler.compile()


# TODO
# What if there are no handshakes in the file


if arg_handler.results.mode_used == "get-info":
    print(f"Handshake information from: '{arg_handler.results['file'].file_list[0]}'")

    chosen_file = arg_handler.results["file"].file_list[0]

    pcap_file = open(chosen_file, "rb")
    contents = dpkt.pcap.Reader(pcap_file)

    eapol_messages = []

    for timestamp, buffer in contents:
        try:
            current_frame = pcap_to_hccapx.EAPOL(timestamp, buffer)
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
                        pcap_to_hccapx.Handshake(item[current_handshake_message_indexes[0]],
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

    if complete_handshakes:
        print("\nComplete Handshakes Found: ")
        for index, complete_handshake in enumerate(complete_handshakes):
            print(f"    Handshake Index: {index}\n{complete_handshake}\n\n")

    else:
        print("\nNo Valid Handshakes Found")

    if loose_messages:
        print(f"\nEAPOL Messages (No Associated Handshake): ")
        for incomplete_handshake in loose_messages:
            print(f"    Message Number: {incomplete_handshake.message_number}\n{incomplete_handshake}\n")

else:
    pass
