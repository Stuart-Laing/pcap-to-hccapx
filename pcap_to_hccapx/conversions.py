import datetime


__all__ = ["convert_timestamp", "byte_mac_to_str"]


def byte_mac_to_str(byte_mac):
    byte_str = ""
    for byte in byte_mac:
        byte_str += hex(byte)[2:]
        byte_str += ":"
    return byte_str[:-1]


def convert_timestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)
