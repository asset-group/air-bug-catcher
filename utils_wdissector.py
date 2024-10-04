import re

from wdissector import WD_DIR_TX

from fuzzlog.fuzzlog import Crash, FuzzedPkt
from utils import WDissectorTool, ae_logger, pcap_pkt_reader


def assign_crash_ids_wdissector(crashes: list[Crash]):
    # Default crash identifier assignment for WDissector
    # TODO: add logic for [Timeout]
    for crash in crashes:
        if crash.type == "normal":
            find_res = re.findall(
                rb"\[Crash\] (Crash detected at state|Device Removed at state) (.*)",
                crash.raw,
            )
            if len(find_res) > 0:
                identifier = find_res[0][1].decode()
                identifier = identifier.replace('"', "")
                crash.identifier = identifier
            else:
                # TODO: fallback to last fuzzed packet state
                crash.identifier = "timeout_" + crash.fuzzed_pkts[-1].state
        elif crash.type == "timeout":
            crash.identifier = "timeout_" + crash.fuzzed_pkts[-1].state
        else:
            ae_logger.error(f"Invalid crash type: {crash.type}")


def discover_crashes_wdissector(protocol, capture_path, decoding_offset: int):
    """
    Find all crashes inside the capture file which is generated by WDissector

    ***************************
    Capture file packet layout:
    pkt
    pkt
    pkt
    Iteration 1
    pkt
    pkt
    Iteration 2
    ***************************

    """
    wd_tool = WDissectorTool(protocol)
    # logger.info("Start capture crashes discovery...")
    # Cache logic, hack method, see comments above
    crashes: list[Crash] = []
    fuzzed_pkts: list[FuzzedPkt] = []
    prev_pkt_bytes: bytes
    crash_idx = 0
    current_iteration = 1  # iteration starts from 1
    for pkt_index, pkt in pcap_pkt_reader(capture_path):
        pkt_comment = pkt.options.get("opt_comment")
        # mutated packet
        if pkt_comment == "Fuzzed from previous":
            # field_name = packet_mutated_field(prev_packet_bytes, packet.packet_data) # KEEP
            fuzzed_pkts.append(
                FuzzedPkt(
                    pkt_bytes=pkt.packet_data,
                    loc=pkt_index,
                    iteration=current_iteration,
                    state=wd_tool.pkt_state(prev_pkt_bytes, decoding_offset),
                    filter=wd_tool.label_pkt(prev_pkt_bytes, WD_DIR_TX, decoding_offset),
                    type="mutation",
                    fuzz_info=None,
                    prev_pkt_bytes=prev_pkt_bytes,
                )
            )
        # duplicated packet
        elif pkt_comment is not None and "Duplicated" in pkt_comment:
            fuzzed_pkts.append(
                FuzzedPkt(
                    pkt_bytes=pkt.packet_data,
                    loc=pkt_index,
                    iteration=current_iteration,
                    state=wd_tool.pkt_state(pkt.packet_data, decoding_offset),
                    filter=wd_tool.label_pkt(pkt.packet_data, WD_DIR_TX, decoding_offset),
                    type="duplication",
                    fuzz_info=None,
                    prev_pkt_bytes=prev_pkt_bytes,
                )
            )
        elif b"[Crash]" in pkt.packet_data or b"[Timeout]" in pkt.packet_data:
            if len(fuzzed_pkts) == 0:
                # sometimes two crashes are too close, no fuzzed packets for the second crash
                # skip this crash
                pass
            else:
                if b"[Crash]" in pkt.packet_data:
                    crash_type = "normal"
                else:
                    crash_type = "timeout"
                crashes.append(
                    Crash(
                        fuzzed_pkts=fuzzed_pkts[:],
                        loc=pkt_index,
                        iteration=current_iteration,
                        identifier=None,
                        crash_type=crash_type,
                        raw=pkt.packet_data,
                        timestamp=pkt.timestamp,
                    )
                )
                crash_idx += 1

            fuzzed_pkts = []
        elif b"Iteration" in pkt.packet_data:
            current_iteration += 1

        prev_pkt_bytes = pkt.packet_data

    return crashes
