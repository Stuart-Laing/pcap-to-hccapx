import argcurse

import pcap_to_hccapx


arg_handler = argcurse.Handler("-h", "--help", using_modes=True, args=["get-info", "demo-files/valid/2-handshakes.pcap"])

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


if arg_handler.results.mode_used == "get-info":
    print(f"Handshake information from: '{arg_handler.results['file'].file_list[0]}'")

    chosen_file = arg_handler.results["file"].file_list[0]

    complete_handshakes, loose_messages = pcap_to_hccapx.get_handshakes(chosen_file)

    essids = pcap_to_hccapx.get_essids(chosen_file)

    if complete_handshakes:
        print("\nComplete Handshakes Found: ")
        for index, complete_handshake in enumerate(complete_handshakes):
            print(f"    Handshake Index: {index}\n{complete_handshake}")
            if complete_handshake.ap_mac in essids:
                print(f"        ESSID             : '{essids[complete_handshake.ap_mac]}'\n\n")
            else:
                print("        ESSID             : Not Found\n\n")

    else:
        print("\nNo Valid Handshakes Found")

    if loose_messages:
        print(f"\nEAPOL Messages (No Associated Handshake): ")
        for incomplete_handshake in loose_messages:
            print(f"    Message Number: {incomplete_handshake.message_number}\n{incomplete_handshake}\n")

else:
    pass
