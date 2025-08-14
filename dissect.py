from scapy.all import rdpcap
import base64
from Crypto.Cipher import AES
from meshtastic import admin_pb2, apponly_pb2, atak_pb2, cannedmessages_pb2, channel_pb2, clientonly_pb2, config_pb2, connection_status_pb2, deviceonly_pb2, exploiteers_pager_pb2, localonly_pb2, mesh_pb2, module_config_pb2, mqtt_pb2, paxcount_pb2, portnums_pb2, remote_hardware_pb2, rtttl_pb2, storeforward_pb2, telemetry_pb2, xmodem_pb2
from google import *
import struct
import datetime


# must download all the proto files from the hacker pager
# then pip install protobuf
# then sudo apt install protobuf-compiler
# then run protoc to convert each file to python
# protoc --python_out=. meshtastic/admin.proto


#### TO DO

# - build database to keep track of names and map them to ids


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

def map_hardware(num):
    map = {
        0: {"name": "UNSET"},
        1: {"name": "TLORA_V2"},
        2: {"name": "TLORA_V1"},
        3: {"name": "TLORA_V2_1_1P6"},
        4: {"name": "TBEAM"},
        5: {"name": "HELTEC_V2_0"},
        6: {"name": "TBEAM_V0P7"},
        7: {"name": "T_ECHO"},
        8: {"name": "TLORA_V1_1P3"},
        9: {"name": "RAK4631"},
        10: {"name": "HELTEC_V2_1"},
        11: {"name": "HELTEC_V1"},
        12: {"name": "LILYGO_TBEAM_S3_CORE"},
        13: {"name": "RAK11200"},
        14: {"name": "NANO_G1"},
        15: {"name": "TLORA_V2_1_1P8"},
        16: {"name": "TLORA_T3_S3"},
        17: {"name": "NANO_G1_EXPLORER"},
        18: {"name": "NANO_G2_ULTRA"},
        19: {"name": "LORA_TYPE"},
        20: {"name": "WIPHONE"},
        21: {"name": "WIO_WM1110"},
        22: {"name": "RAK2560"},
        23: {"name": "HELTEC_HRU_3601"},
        24: {"name": "HELTEC_WIRELESS_BRIDGE"},
        25: {"name": "STATION_G1"},
        26: {"name": "RAK11310"},
        27: {"name": "SENSELORA_RP2040"},
        28: {"name": "SENSELORA_S3"},
        29: {"name": "CANARYONE"},
        30: {"name": "RP2040_LORA"},
        31: {"name": "STATION_G2"},
        32: {"name": "LORA_RELAY_V1"},
        33: {"name": "NRF52840DK"},
        34: {"name": "PPR"},
        35: {"name": "GENIEBLOCKS"},
        36: {"name": "NRF52_UNKNOWN"},
        37: {"name": "PORTDUINO"},
        38: {"name": "ANDROID_SIM"},
        39: {"name": "DIY_V1"},
        40: {"name": "NRF52840_PCA10059"},
        41: {"name": "DR_DEV"},
        42: {"name": "M5STACK"},
        43: {"name": "HELTEC_V3"},
        44: {"name": "HELTEC_WSL_V3"},
        45: {"name": "BETAFPV_2400_TX"},
        46: {"name": "BETAFPV_900_NANO_TX"},
        47: {"name": "RPI_PICO"},
        48: {"name": "HELTEC_WIRELESS_TRACKER"},
        49: {"name": "HELTEC_WIRELESS_PAPER"},
        50: {"name": "T_DECK"},
        51: {"name": "T_WATCH_S3"},
        52: {"name": "PICOMPUTER_S3"},
        53: {"name": "HELTEC_HT62"},
        54: {"name": "EBYTE_ESP32_S3"},
        55: {"name": "ESP32_S3_PICO"},
        56: {"name": "CHATTER_2"},
        57: {"name": "HELTEC_WIRELESS_PAPER_V1_0"},
        58: {"name": "HELTEC_WIRELESS_TRACKER_V1_0"},
        59: {"name": "UNPHONE"},
        60: {"name": "TD_LORAC"},
        61: {"name": "CDEBYTE_EORA_S3"},
        62: {"name": "TWC_MESH_V4"},
        63: {"name": "NRF52_PROMICRO_DIY"},
        64: {"name": "RADIOMASTER_900_BANDIT_NANO"},
        65: {"name": "HELTEC_CAPSULE_SENSOR_V3"},
        66: {"name": "HELTEC_VISION_MASTER_T190"},
        67: {"name": "HELTEC_VISION_MASTER_E213"},
        68: {"name": "HELTEC_VISION_MASTER_E290"},
        69: {"name": "HELTEC_MESH_NODE_T114"},
        70: {"name": "SENSECAP_INDICATOR"},
        71: {"name": "TRACKER_T1000_E"},
        72: {"name": "RAK3172"},
        73: {"name": "WIO_E5"},
        74: {"name": "RADIOMASTER_900_BANDIT"},
        75: {"name": "ME25LS01_4Y10TD"},
        76: {"name": "RP2040_FEATHER_RFM95"},
        77: {"name": "M5STACK_COREBASIC"},
        78: {"name": "M5STACK_CORE2"},
        79: {"name": "RPI_PICO2"},
        80: {"name": "M5STACK_CORES3"},
        81: {"name": "SEEED_XIAO_S3"},
        82: {"name": "MS24SF1"},
        83: {"name": "TLORA_C6"},
        84: {"name": "WISMESH_TAP"},
        85: {"name": "ROUTASTIC"},
        86: {"name": "MESH_TAB"},
        87: {"name": "MESHLINK"},
        88: {"name": "XIAO_NRF52_KIT"},
        89: {"name": "THINKNODE_M1"},
        90: {"name": "THINKNODE_M2"},
        91: {"name": "T_ETH_ELITE"},
        92: {"name": "HELTEC_SENSOR_HUB"},
        93: {"name": "RESERVED_FRIED_CHICKEN"},
        94: {"name": "HELTEC_MESH_POCKET"},
        95: {"name": "SEEED_SOLAR_NODE"},
        96: {"name": "NOMADSTAR_METEOR_PRO"},
        97: {"name": "CROWPANEL"},
        98: {"name": "LINK_32"},
        99: {"name": "SEEED_WIO_TRACKER_L1"},
        100: {"name": "SEEED_WIO_TRACKER_L1_EINK"},
        101: {"name": "QWANTZ_TINY_ARMS"},
        102: {"name": "T_DECK_PRO"},
        103: {"name": "T_LORA_PAGER"},
        104: {"name": "GAT562_MESH_TRIAL_TRACKER"},
        255: {"name": "PRIVATE_HW"}
        }
    try:
        return map[num]["name"]
    except:
        return "Unknown"
    
def map_role(num):
    map = {
        0: {"name": "CLIENT"},
        1: {"name": "CLIENT_MUTE"},
        2: {"name": "ROUTER"},
        3: {"name": "ROUTER_CLIENT"},
        4: {"name": "REPEATER"},
        5: {"name": "TRACKER"},
        6: {"name": "SENSOR"},
        7: {"name": "TAK"},
        8: {"name": "CLIENT_HIDDEN"},
        9: {"name": "LOST_AND_FOUND"},
        10: {"name": "TAK_TRACKER"},
        11: {"name": "ROUTER_LATE"}
        }
    try:
        return map[num]["name"]
    except:
        return "Unknown"
    
def map_loc_source(num):
    map = {
        0: {"name": "LOC_UNSET"},
        1: {"name": "LOC_MANUAL"},
        2: {"name": "LOC_INTERNAL"},
        3: {"name": "LOC_EXTERNAL"},
        }
    try:
        return map[num]["name"]
    except:
        return "Unknown"

def decode_textmessage(payload):
    results = {}
    results["text_message_text"] = {"name": "Message", "data": payload[4:-2].decode('utf-8', errors='replace')}
    results["text_message_end"] = {"name": "End", "data": payload[-2:]}
    return results

def decode_pos_sections(payload, start_num):
    if payload[start_num] == 13: #0x0d
        pos_lat_b = payload[start_num+1:start_num+5]
        pos_lat_raw = struct.unpack('<i', pos_lat_b)[0]
        pos_lat = pos_lat_raw / 1e7
        section_json = {"name": "Latitude", "data": pos_lat}
        next_byte = start_num + 5
        name = "lat"
    elif payload[start_num] == 21: #0x15
        pos_lon_b = payload[start_num+1:start_num+5]
        pos_lon_raw = struct.unpack('<i', pos_lon_b)[0]
        pos_lon = pos_lon_raw / 1e7
        section_json = {"name": "Longitude", "data": pos_lon}
        next_byte = start_num + 5
        name = "lon"
    elif payload[start_num] == 24: #0x18
        if payload[start_num+2] == 1: #0x01
            alt = payload[start_num+1]
            next_byte = start_num + 3
        elif payload[start_num+2] == 255: #0xff
            alt = payload[start_num+1] - 256
            next_byte = start_num + 11
        else:
            alt = payload[start_num+1]
            next_byte = start_num + 2
        section_json = {"name": "Altitude", "data": alt}
        name = "alt"
    elif payload[start_num] == 37: #0x25
        time_b = payload[start_num+1:start_num+5]
        time = int.from_bytes(time_b, 'little')
        section_json = {"name": "Time", "data": time}
        next_byte = start_num + 5
        name = "time"
    elif payload[start_num] == 40: #0x28
        source = payload[start_num+1]
        source_name = map_loc_source(source)
        section_json = {"name": "Location Source", "data": f"{source_name} [{source}]"}
        next_byte = start_num + 2
        name = "loc_source"
    elif payload[start_num] == 88: #0x58
        pdop = payload[start_num+1:start_num+3] # TODO: Figure out how this is translated to a number
        section_json = {"name": "PDOP", "data": f"{pdop}"}
        next_byte = start_num + 3
        name = "pdop"
    elif payload[start_num] == 120: #0x78
        ground_speed = payload[start_num+1]
        section_json = {"name": "Ground Speed", "data": f"{ground_speed}"}
        next_byte = start_num + 2
        name = "g_speed"
    elif payload[start_num] == 128: #0x80 (actually 0x80 0x01)
        ground_track = payload[start_num+2]
        ground_track = payload[start_num+2:start_num+6] # some it's just one byte and some it's lots of bytes and I can't figure out where the length is
    else:
        print(f"nothing for startbyte {payload[start_num]} was found")
    return name, section_json, next_byte

def decode_position(payload):

    results = {}
    start_num = 4
    try:
        while True:
            section = decode_pos_sections(payload, start_num)
            name = section[0]
            results[name] = section[1]
            start_num = section[2]
    except Exception as e:
        print(f"Malformed packet: {e}")
    
    return results

def decode_nodeinfo(payload):
    results = {}
    nodeinfo_id = payload[6:15].decode('utf-8', errors='replace')
    nodeinfo_longname_firstbyte = payload[15] # this is always 18
    nodeinfo_longname_len = payload[16]
    nodeinfo_longname_end = 17+nodeinfo_longname_len
    nodeinfo_longname = payload[17:nodeinfo_longname_end].decode('utf-8', errors='replace')
    results["longname"] = {"name": "Long Name", "data": nodeinfo_longname}
    
    nodeinfo_shortname_start = nodeinfo_longname_end
    nodeinfo_shortname_firstbyte = payload[nodeinfo_shortname_start]   # this is always 26
    nodeinfo_shortname_len = payload[nodeinfo_shortname_start+1]
    nodeinfo_shortname_end = nodeinfo_shortname_start+2+nodeinfo_shortname_len
    nodeinfo_shortname = payload[nodeinfo_shortname_start+2:nodeinfo_shortname_end].decode('utf-8', errors='replace')
    results["shortname"] = {"name": "Short Name", "data": nodeinfo_shortname}

    nodeinfo_mac_start = nodeinfo_shortname_end
    nodeinfo_mac_firstbyte = payload[nodeinfo_mac_start] # this is always 34
    nodeinfo_mac_len = payload[nodeinfo_mac_start+1]
    nodeinfo_mac_end = nodeinfo_mac_start+2+nodeinfo_mac_len
    nodeinfo_mac = payload[nodeinfo_mac_start+2:nodeinfo_mac_end].hex()
    results["mac"] = {"name": "MAC Address", "data": nodeinfo_mac}

    nodeinfo_hw_start = nodeinfo_mac_end
    nodeinfo_hw_firstbyte = payload[nodeinfo_hw_start] # this is always 40
    nodeinfo_hw = payload[nodeinfo_hw_start+1]
    nodeinfo_hw_name = map_hardware(nodeinfo_hw)
    results["hw"] = {"name": "Hardware", "data": f"{nodeinfo_hw_name} [{nodeinfo_hw}]"}

    nodeinfo_role_start = nodeinfo_hw_start+3
    nodeinfo_role_firstbyte = payload[nodeinfo_role_start] # this is different, not sure what it is
    nodeinfo_role = payload[nodeinfo_role_start+1]
    nodeinfo_role_name = map_role(nodeinfo_role)
    results["role"] = {"name": "Device Role", "data": f"{nodeinfo_role_name} [{nodeinfo_role}]"}

    # #nodeinfo_lentoskip = decrypted_payload[nodeinfo_role_start+4]
    # # TODO keep working on this so that it prints "want_response"

    return results

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
        print("")
        # print(f"Packet {i}:")
        # print(f"    LoRaTap:")
        # print(f"        Version: {version}")
        # print(f"        Padding: {padding}")
        # print(f"        Header Length: {header_length}")
        # print(f"        Channel:")
        # print(f"            Frequency: {channel_frequency} MHz")
        # print(f"            Bandwidth: {channel_bandwidth}")
        # print(f"            Spreading Factor: {channel_spreading_factor}")
        # print(f"        RSSI:")
        # print(f"            Packet: {rssi_packet}")
        # print(f"            Max: {rssi_max}")
        # print(f"            Current: {rssi_current}")
        # print(f"            SNR: {rssi_snr}")

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
            payload_start = decrypted_payload[0:4]
            payload_portnum = decrypted_payload[1]
            if payload_portnum in valid_portnums:
                print(f"    Meshtastic:")
                print(f"        Destination Node: {meshtastic_destination_node}")
                print(f"        Sender Node: {meshtastic_sender_node}")
                # print(f"        Packet ID: {meshtastic_packet_id.hex()}")
                # print(f"        Flags: {meshtastic_flags}")
                # print(f"        Channel Hash: {meshtastic_channel_hash}")
                # print(f"        Next Hop Node: {meshtastic_next_hop_node}")
                # print(f"        Relay Node: {meshtastic_relay_node}")
                # print(f"        Raw Payload: {meshtastic_payload.hex()}")
                print(f"        Decrypted Payload: {decrypted_payload.hex()}")
                # print(f"        Payload:")
                # print(f"            App: {map_portnum(payload_portnum)} [{payload_portnum}]")
                # print(f"            Start: {payload_start.hex()}")
                try:
                    if payload_portnum == 1: # text message
                        results = decode_textmessage(decrypted_payload)
                        print(f"        TEXT_MESSAGE_APP:")
                        for i in results:
                            print(f"            {results[i]["name"]}: {results[i]["data"]}")
                    
                    elif payload_portnum == 3: # position
                        results = decode_position(decrypted_payload)
                        print(f"        POSITION_APP:")
                        for i in results:
                            print(f"            {results[i]["name"]}: {results[i]["data"]}")
                        
                    # elif payload_portnum == 4: # nodeinfo
                    #     results = decode_nodeinfo(decrypted_payload)
                    #     print(f"        NODEINFO_APP:")
                    #     for i in results:
                    #         print(f"            {results[i]["name"]}: {results[i]["data"]}")
                    elif payload_portnum == 67: # telemetry
                        telemetry = telemetry_pb2.Telemetry()
                        telemetry.ParseFromString(decrypted_payload)
                        print("time:", telemetry.time)
                        print("  battery_level:", telemetry.device_metrics.battery_level)
                except Exception as e:
                    print(f"Malformed packet: {e}")
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