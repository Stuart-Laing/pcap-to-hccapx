import argcurse


arg_handler = argcurse.Handler("-h", "--help", using_modes=True, args=["get-info", "demo-files/valid/1-handshake.pcap"])

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

arg_handler.generate_default_message("pcap-to-hccapx")
arg_handler.generate_help_message("pcap-to-hccapx")

arg_handler.compile()

if arg_handler.results.mode_used == "get-info":
    print(f"File Chosen : '{arg_handler.results['file'].file_list[0]}'")

    chosen_file = arg_handler.results['file'].file_list[0]

    with open(chosen_file, "r") as f:
        f.read()

else:
    pass
