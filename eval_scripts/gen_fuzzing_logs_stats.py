from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket

from eval_scripts.utils import convert_friendly_time


def pcap_pkt_reader(path: str):
    # Return a generator to yield EnhancedPacket and its index in the capture: (index, EnhancedPacket)
    with open(path, "rb") as f:
        scanner = FileScanner(f)
        pkt_index = 0  # this is the packet number in Wireshark
        try:
            for block in scanner:
                if not isinstance(block, EnhancedPacket):
                    continue
                pkt_index += 1
                yield pkt_index, block
        except:
            pass


def fuzzing_log_stats(device, capture_path):
    num_mut = 0
    num_replay = 0
    num_crash = 0

    mut_replay_happen = False
    for idx, pkt in pcap_pkt_reader(capture_path):
        if idx == 1:
            start_time = pkt.timestamp
        pkt_comment = pkt.options.get("opt_comment")
        if pkt_comment == "Fuzzed from previous":
            num_mut += 1
            mut_replay_happen = True
        elif pkt_comment is not None and "Duplicated" in pkt_comment:
            num_replay += 1
            mut_replay_happen = True
        elif (
            mut_replay_happen
            and (b"[Crash]" in pkt.packet_data or b"[Timeout]" in pkt.packet_data)
            and b"Original [Timeout]" not in pkt.packet_data
        ):
            if device == "simcom" and b"[Timeout]" in pkt.packet_data:
                # SIMCom fuzzing log is bit weird, timeout log may not be actually timeout
                continue
            num_crash += 1
            mut_replay_happen = False

    time_taken = pkt.timestamp - start_time
    return f"{num_mut} mutations, {num_replay} replays, {num_crash} crashes, {convert_friendly_time(time_taken)}"


for device, pcap_path in zip(
    ["esp32_bt", "cypress_bt", "oneplus_5g", "simcom_5g", "esp32_wifi"],
    [
        "captures/esp32_bt/capture_bluetooth.pcapng",
        "captures/cypress_bt/capture_bluetooth_cypress_fuzzing.pcapng",
        "captures/oneplus_5g/capture_nr5g_gnb.pcapng",
        "captures/simcom_5g/capture_nr5g_gnb.pcapng",
        "captures/esp32_wifi/capture_wifi.pcapng",
    ],
):
    print(f"{device} fuzzing log statistics: {fuzzing_log_stats(device, pcap_path)}")
