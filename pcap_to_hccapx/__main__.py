import argcurse

import pcap_to_hccapx


arg_handler = argcurse.Handler("-h", "--help", using_modes=True)

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

    input_file = arg_handler.results["file"].file_list[0]

    complete_handshakes, loose_messages = pcap_to_hccapx.get_handshakes(input_file)

    essids = pcap_to_hccapx.get_essids(input_file)

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
    print(f"Generating hccapx file from: '{arg_handler.results['file'].file_list[0]}'")

    input_file = arg_handler.results["file"].file_list[0]
    if arg_handler.results["-o"].flag_used:
        output_file = arg_handler.results["-o"].flag_content
    else:
        output_file = "results.hccapx"

    essid = arg_handler.results["-e"].flag_content
    index = arg_handler.results["-i"].flag_content

    complete_handshakes, loose_messages = pcap_to_hccapx.get_handshakes(input_file)
    essids = pcap_to_hccapx.get_essids(input_file)

    if len(complete_handshakes) == 0:
        print("\nNo Valid Handshakes Found")
        exit()

    elif len(complete_handshakes) > 1:
        if arg_handler.results["-i"].flag_used:
            chosen_handshake = int(arg_handler.results["-i"].flag_content)

        else:
            print("\nMultiple Handshakes Found")
            print("Please specify index by running get-info")

            exit()

    else:
        chosen_handshake = 0

    if not arg_handler.results["-e"].flag_used:
        if complete_handshakes[int(arg_handler.results["-i"].flag_content)].ap_mac not in essids:
            print("\nNo ESSID was found")
            print("Please specify using -e")
        else:
            essid = essids[complete_handshakes[chosen_handshake].ap_mac]

    hccapx_file_content = complete_handshakes[chosen_handshake].create_file(essid)

    print(f"Writing file content to: '{output_file}'")

    print()

    with open(output_file, "wb") as hccapx_file:
        hccapx_file.write(hccapx_file_content)
