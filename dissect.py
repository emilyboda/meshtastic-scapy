from scapy.all import rdpcap
import base64
from Crypto.Cipher import AES
from meshtastic import admin_pb2, apponly_pb2, atak_pb2, cannedmessages_pb2, channel_pb2, clientonly_pb2, config_pb2, connection_status_pb2, deviceonly_pb2, exploiteers_pager_pb2, localonly_pb2, mesh_pb2, module_config_pb2, mqtt_pb2, paxcount_pb2, portnums_pb2, remote_hardware_pb2, rtttl_pb2, storeforward_pb2, telemetry_pb2, xmodem_pb2
from google import *


# must download all the proto files from the hacker pager
# then pip install protobuf
# then sudo apt install protobuf-compiler
# then run protoc to convert each file to python
# protoc --python_out=. meshtastic/admin.proto


keys = ["AQ=="]
valid_portnums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 32, 33, 34, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 256, 257]

def loratap_raw_to_dBm(raw):
    # for rssi_max and rssi_current only
    return raw + -139

def loratap_raw_to_dBm_packet(raw, snr):
    # for rssi_packet only
    if snr >= 0:
        return raw + -139
    else:
        return raw * 0.25 + -139

def loratap_snr_to_dB(snr_byte):
    # for rssi_snr only
    # dB value is snr[two's complement]/4
    if snr_byte > 127:
        snr_signed = snr_byte - 256
    else:
        snr_signed = snr_byte
    return snr_signed / 4.0

def get_crypto_key(key_base64_str):
    # Default PSK from the Lua script
    default_psk = bytearray([
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
    ])

    user_key = base64.b64decode(key_base64_str)

    if len(user_key) == 0:
        # Encryption disabled.
        return bytearray()
    elif len(user_key) == 1:
        # Key is the default key with its last byte incremented by the user key
        key = list(default_psk)
        key[-1] = (key[-1] + (user_key[0] - 1)) % 256
        return bytearray(key)
    elif len(user_key) <= 16:
        # Pad or truncate to 16 bytes
        return user_key.ljust(16, b'\0')[:16]
    elif len(user_key) <= 32:
        # Pad or truncate to 32 bytes
        return user_key.ljust(32, b'\0')[:32]
    else:
        raise ValueError("Key is longer than 32 bytes")

def get_crypto_iv(packet_id, from_node):
    if len(packet_id) != 4 and len(from_node) != 4:
        raise ValueError('meshtastic_packet_id and mesthastic_sender_node must be 4 bytes each')
    iv = bytearray(16)
    # Packet ID (first 4 bytes)
    iv[0:4] = packet_id
    # From node (next 4 bytes)
    iv[8:12] = from_node
    return bytes(iv)

def decrypt_payload(key_base64, packet_id, from_node, encrypted_payload):
    key = get_crypto_key(key_base64)
    if not key:
        return encrypted_payload
    iv = get_crypto_iv(packet_id, from_node)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    return cipher.decrypt(encrypted_payload)

def map_portnum(num):
    from meshtastic.portnums_pb2 import DESCRIPTOR
    portnum_enum = DESCRIPTOR.enum_types_by_name['PortNum']
    for enum_value in portnum_enum.values:
        if enum_value.number == num:
            return enum_value.name
    return 'not yet defined'


def process_pcap(filename):
    packets = rdpcap(filename)
    for i, pkt in enumerate(packets, 1):
        raw = bytes(pkt)
        if not raw:
            continue
        version = raw[0]
        padding = raw[1]
        header_length = int.from_bytes(raw[2:4], byteorder='big')
        channel_frequency = int.from_bytes(raw[4:8], byteorder='big') / 1000000
        channel_bandwidth = raw[8]
        channel_spreading_factor = raw[9]
        rssi_snr = loratap_snr_to_dB(raw[13])
        rssi_packet = loratap_raw_to_dBm_packet(raw[10], rssi_snr)
        rssi_max = loratap_raw_to_dBm(raw[11])
        rssi_current = loratap_raw_to_dBm(raw[12])
        sync_word = raw[14]  # this indicates it's a Meshtastic packet
        print(f"Packet {i}:")
        print(f"    LoRaTap:")
        print(f"        Version: {version}")
        print(f"        Padding: {padding}")
        print(f"        Header Length: {header_length}")
        print(f"        Channel:")
        print(f"            Frequency: {channel_frequency} MHz")
        print(f"            Bandwidth: {channel_bandwidth}")
        print(f"            Spreading Factor: {channel_spreading_factor}")
        print(f"        RSSI:")
        print(f"            Packet: {rssi_packet}")
        print(f"            Max: {rssi_max}")
        print(f"            Current: {rssi_current}")
        print(f"            SNR: {rssi_snr}")

        if sync_word == 0x2b:
            meshtastic_destination_node = raw[15:19][::-1].hex()
            meshtastic_sender_node = raw[19:23][::-1].hex()
            meshtastic_packet_id = raw[23:27]
            meshtastic_flags = raw[27]
            meshtastic_channel_hash = raw[28]
            meshtastic_next_hop_node = raw[29]
            meshtastic_relay_node = raw[30]
            meshtastic_payload = raw[31:]

            # Decrypt the payload
            decrypted_payload = decrypt_payload(keys[0], meshtastic_packet_id, raw[19:23], meshtastic_payload)
            payload_data = decrypted_payload[0:4]
            payload_portnum = decrypted_payload[1]
            if payload_portnum in valid_portnums:

                print(f"    Meshtastic:")
                print(f"        Destination Node: {meshtastic_destination_node}")
                print(f"        Sender Node: {meshtastic_sender_node}")
                print(f"        Packet ID: {meshtastic_packet_id.hex()}")
                print(f"        Flags: {meshtastic_flags}")
                print(f"        Channel Hash: {meshtastic_channel_hash}")
                print(f"        Next Hop Node: {meshtastic_next_hop_node}")
                print(f"        Relay Node: {meshtastic_relay_node}")
                print(f"        Raw Payload: {meshtastic_payload.hex()}")
                print(f"        Decrypted Payload: {decrypted_payload.hex()}")
                print(f"        Decrypted Payload:")
                print(f"            Payload Data: {payload_data.hex()}")
                print(f"            App: {map_portnum(payload_portnum)}")
            else:
                print("Malformed packet")


        else:
            rest = raw[15:]
            print(f"    Rest of bytes (hex): {rest.hex()}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    process_pcap(sys.argv[1])