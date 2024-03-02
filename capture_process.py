import os
import pickle
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations
from typing import Literal

from utils import (
    calc_bytes_sha256,
    calc_file_sha256,
    is_same_crash,
    label_packets,
    logger,
    packet_mutated_field,
    packet_state,
    pcap_packet_reader,
)
from wdissector import WD_DIR_TX

# TODO: wording
# TODO: change pkt to packet
# TODO: change reason to identifier

BoardType = Literal["esp32", "cypress"]
ProtocolType = Literal["5g", "bt"]


class Crash:
    def __init__(
        self,
        fuzzed_pkts: list["FuzzedPacket"],
        pkt_loc,
        iteration,
        reason: str | None,
        raw: bytes,
        timestamp: int,
    ) -> None:
        self.fuzzed_pkts = (
            fuzzed_pkts  # this should be in ascending order by "pkt_loc" key
        )
        self.pkt_loc = pkt_loc
        self.iteration = iteration
        self.reason = reason
        self.raw = raw
        self.timestamp = timestamp

    @lru_cache(maxsize=32)
    def gen_histogram(
        self, max_iterations, sort_by_occurrence=False, sort_ascending=True
    ):
        """
        Generate histogram statistics for the crash

        max_iterations: control how far the histogram should trace back and include
        """
        pkt_histogram = {}
        for pkt in self.fuzzed_pkts:
            if self.iteration - pkt.iter < max_iterations:
                pkt_histogram[pkt.state] = pkt_histogram.get(pkt.state, 0) + 1

        if sort_by_occurrence:
            pkt_histogram = {
                k: v
                for k, v in sorted(
                    pkt_histogram.items(),
                    key=lambda item: item[1],
                    reverse=not sort_ascending,
                )
            }

        return pkt_histogram


@dataclass
class FuzzedPacket:
    packet_bytes: bytes
    loc: int
    iter: int
    state: str
    filter: str | None
    type: Literal["mutation", "duplication"]
    mutated_fields: list[str] | None
    prev_packet_bytes: bytes


class Capture:
    def __init__(
        self,
        path: str,
        protocol: ProtocolType,
        board: BoardType,
        packet_decoding_offset: int,
        use_cache=True,
    ):
        self.path = path
        self.protocol = protocol
        self.packet_decoding_offset = packet_decoding_offset
        self.board = board
        self.use_cache = use_cache

        self.crashes: list[Crash]  # To be filled in `discover_capture_crashes`
        # self.crashes = self.discover_capture_crashes()

    def auto_exploit(self):
        pass

    def assign_identifier_to_crashes(self):
        # Default to use state information in the capture as crash identifier
        for crash in self.crashes:
            if self.protocol == "bt":
                # crash.raw example: 00 00 00 00 0a fa [Crash] Crash detected at state TX / Baseband / FHS
                crash.reason = crash.raw[6:].decode()
            elif self.protocol == "5g":
                # TODO
                pass
            else:
                print("No gen_crash_identifier function implemented for", self.protocol)

    def discover_capture_crashes(self) -> None:
        """
        Find all crashes inside the capture file and one cache file for crashes is generated and stored.

        Cache is stored in the filesystem with file name being the sha256 hash of capture file.
        For reference, loading and finding crashes from a 997 MB capture file containing 5.7 million
        packets takes about 2 minutes without cache.

        The cache content might be outdated after the function which generates it is changed so that
        the format of cache content is altered. In this case, the cache should always be regenerated.
        A hacky way to determine if a function is changed in Python is to leverage func.__code__ object.
        More information can be found at: https://rushter.com/blog/python-bytecode-patch/. Note that this
        __code__.co_code might differ when running using different versions of Python or on different machines.

        Cache file is a pickled Python dictionary:
        {
            "cache_version":
            "crashes":
        }
        """
        logger.info("Start capture crashes discovery...")
        # Cache logic, hack method, see comments above
        cache_version = calc_bytes_sha256(
            self.discover_capture_crashes.__code__.co_code
        )
        capture_sha256 = calc_file_sha256(self.path)
        self.capture_crash_cache_path = f"/home/user/wdissector/modules/auto-exploiter/cache/{capture_sha256}.pickle"
        if self.use_cache:
            if not os.path.exists(self.capture_crash_cache_path):
                logger.info("No capture cache is found, regenerating...")
            else:
                with open(self.capture_crash_cache_path, "rb") as f:
                    try:
                        _crashes = pickle.load(f)
                        if _crashes["cache_version"] != cache_version:
                            logger.info("Outdated capture cache, regenerating...")
                        else:
                            self.crashes = _crashes["crashes"]
                            return
                    except:
                        logger.info("Invalid capture cache file, regenerating...")

        crashes = []
        fuzzed_pkts = []
        prev_packet_bytes: bytes
        crash_idx = 0
        current_iteration = 0
        for packet_index, packet in pcap_packet_reader(self.path):
            pkt_comment = packet.options.get("opt_comment")
            if pkt_comment == "Fuzzed from previous":  # mutated packet
                # field_name = packet_mutated_field(prev_packet_bytes, packet.packet_data) # KEEP
                fuzzed_pkts.append(
                    FuzzedPacket(
                        packet_bytes=packet.packet_data,
                        loc=packet_index,
                        iter=current_iteration,
                        state=packet_state(
                            prev_packet_bytes, self.packet_decoding_offset
                        ),
                        filter=label_packets(
                            prev_packet_bytes, WD_DIR_TX, self.packet_decoding_offset
                        ),
                        type="mutation",
                        mutated_fields=None,
                        prev_packet_bytes=prev_packet_bytes,
                    )
                )
            # duplicated packet
            elif pkt_comment is not None and "Duplicated" in pkt_comment:
                fuzzed_pkts.append(
                    FuzzedPacket(
                        packet_bytes=packet.packet_data,
                        loc=packet_index,
                        iter=current_iteration,
                        state=packet_state(
                            packet.packet_data, self.packet_decoding_offset
                        ),
                        filter=label_packets(
                            packet.packet_data, WD_DIR_TX, self.packet_decoding_offset
                        ),
                        type="duplication",
                        mutated_fields=None,
                        prev_packet_bytes=prev_packet_bytes,
                    )
                )
            # TODO: which crashes should be ignored and why?
            elif (
                packet.packet_data[4:13] == b"\n\xfa[Crash]"
                and b"TX / LMP / LMP_detach" not in packet.packet_data
            ):
                # generate packet states histogram
                # pkt_histogram = {}
                # for pkt in changed_pkts:
                #     if current_iteration - pkt["iteration"] < max_iterations:
                #         pkt_histogram[pkt["state"]] = (
                #             pkt_histogram.get(pkt["state"], 0) + 1
                #         )

                # # sort by occurrence
                # pkt_histogram = {
                #     k: v
                #     for k, v in sorted(
                #         pkt_histogram.items(),
                #         key=lambda item: item[1],
                #         reverse=True,
                #     )
                # }

                # Sometimes there is no corresponding crash reason from monitor.txt for some crashes, need
                # to check the timestamp to see if the reason is pointing to the correct crash
                # The timestamp in the log can be in GMT+8 or GMT or GMT-8 zone
                # TODO: Optimize this
                # reason = "not_found"
                # for trial in range(3):
                #     if crash_reason_idx + trial >= len(crash_reasons):
                #         break
                #     if (
                #         abs(
                #             block.timestamp
                #             - crash_reasons[crash_reason_idx + trial][1]
                #         )
                #         < 2
                #         or abs(
                #             abs(
                #                 block.timestamp
                #                 - crash_reasons[crash_reason_idx + trial][1]
                #             )
                #             - 8 * 60 * 60
                #         )
                #         < 2
                #     ):
                #         reason = crash_reasons[crash_reason_idx + trial][0]
                #         crash_reason_idx = crash_reason_idx + trial + 1
                #         break

                crashes.append(
                    Crash(
                        fuzzed_pkts=fuzzed_pkts[:],
                        pkt_loc=packet_index,
                        iteration=current_iteration,
                        reason=None,
                        raw=packet.packet_data,
                        timestamp=packet.timestamp,
                    )
                )

                crash_idx += 1
                fuzzed_pkts = []

            elif self.protocol == "bt" and b"BT Process Started" in packet.packet_data:
                current_iteration += 1
            # TODO: complete logic for 5g
            # elif self.protocol == "5g" and :

            prev_packet_bytes = packet.packet_data

        self.crashes = crashes
        self.assign_identifier_to_crashes()

        with open(self.capture_crash_cache_path, "wb") as f:
            pickle.dump({"crashes": self.crashes, "cache_version": cache_version}, f)

    @staticmethod
    def is_same_crash_identifier(id1, id2, thresh: int | None = None) -> bool:
        # Here provides a fallback and most basic way to compare identifiers. This is more like
        # an interface for different kinds of captures to actually implement, if necessary.
        return id1 == id2

    @staticmethod
    def find_crash_identifier_from_run_log(run_log_path) -> str | None:
        # Default way to get crash identifier, which is actually from WDissector output
        if not os.path.exists(run_log_path):
            logger.error(
                f"Run log {run_log_path} does not exist, unable to find crash identifier."
            )

        with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                m = re.search(r"\[31m(\[Crash\] .*?)\[00m", line)
                if m:
                    return m.groups()[0]

        return None

    def group_crashes(self, same_crash_threshold):
        # First find the indexes of same crashes from the capture
        # E.g. [[2,4,7] , [3,10,61]], each list element inside same_crash_indexes represents
        # one crash which happens multiple times.
        # Note to me that `itertools.groupby` is not a feasible solution
        # same_crash_indexes: list[list[int]] = []
        grouped_crashes: list[list[Crash]] = []
        # Helper variable to indicate if a crash is already visited
        visited = [0] * len(self.crashes)
        for idx1, crash1 in enumerate(self.crashes):
            if visited[idx1] == 1:
                continue

            visited[idx1] = 1
            same_crashes = [crash1]
            # same_crash_index = [idx1]

            # if idx1 == len(self.crashes) - 1:
            #     # no next crash, this is the last one
            #     grouped_crashes.append(same_crashes)
            #     break

            for idx2, crash2 in enumerate(self.crashes):
                if idx1 >= idx2:
                    # no need to revisit
                    continue

                if self.is_same_crash_identifier(
                    crash1.reason, crash2.reason, same_crash_threshold
                ):
                    same_crashes.append(crash2)
                    visited[idx2] = 1

                # # TODO: optimize
                # if self.board == "cypress":
                #     if is_same_crash(
                #         str(crash1.raw), str(crash2.raw), same_crash_threshold
                #     ):
                #         same_crash_index.append(idx2)
                #         shown[idx2] = 1
                # else:
                #     if is_same_crash(
                #         crash1.reason, crash2.reason, same_crash_threshold
                #     ):
                #         same_crash_index.append(idx2)
                #         shown[idx2] = 1

            # same_crash_indexes.append(same_crash_index)
            grouped_crashes.append(same_crashes)

        return grouped_crashes

    def gen_histogram(
        self,
        max_iterations: int,
        sort_by_occurrence=False,
        sort_ascending=True,
        same_crash_threshold: int = 2000,
        common_states_only: bool = True,
    ):
        """
        Generate histogram statistics for the capture by combining same crash statistics from
        the capture. There are many crashes inside a capture file, and some of them are the same
        or can be considered as the same.
        Return [
            same_crash_1_diagram,
            same_crash_2_diagram, ...
        ]
        same_crash_1_diagram format: {
            "reasons": {"reason_1": occurrence, "reason_2": occurrence},
            "histogram": {"state_1": occurrence, "state_2": occurrence},
            "num_crashes":,
        }
        """
        same_crash_indexes = self.group_crashes(same_crash_threshold)
        combined_histogram = []
        for same_crash_index in same_crash_indexes:
            reasons = {}
            same_crash_histogram = {}
            states_occurrence = {}
            for idx in same_crash_index:
                reasons[self.crashes[idx].reason] = (
                    reasons.get(self.crashes[idx].reason, 0) + 1
                )
                crash_histogram = self.crashes[idx].gen_histogram(max_iterations)
                for state in crash_histogram:
                    states_occurrence[state] = states_occurrence.get(state, 0) + 1

            for idx in same_crash_index:
                crash_histogram = self.crashes[idx].gen_histogram(max_iterations)
                for state in states_occurrence:
                    if common_states_only:
                        if states_occurrence[state] < len(same_crash_index):
                            # not all crash has this state
                            continue

                    same_crash_histogram[state] = same_crash_histogram.get(state, 0) + 1

            if sort_by_occurrence:
                same_crash_histogram = {
                    k: v
                    for k, v in sorted(
                        same_crash_histogram.items(),
                        key=lambda item: item[1],
                        reverse=not sort_ascending,
                    )
                }

            combined_histogram.append(
                {
                    # "pkt_locs": [self.crashes[i]["pkt_loc"] for i in same_crash_index],
                    "reasons": reasons,
                    "histogram": same_crash_histogram,
                    "num_crashes": len(same_crash_index),
                }
            )

        return combined_histogram

        # include all states in the result
        if not common_states_only:
            for same_crash_index in same_crash_indexes:
                for i in same_crash_index:
                    reasons[self.crashes[i]["reason"]] = (
                        reasons.get(self.crashes[i]["reason"], 0) + 1
                    )

                    for j in self.crashes[i]["histogram"]:
                        same_crash_histogram[j] = (
                            same_crash_histogram.get(j, 0)
                            + self.crashes[i]["histogram"][j]
                        )

                combined_histogram.append(
                    {
                        "pkt_locs": [
                            self.crashes[i]["pkt_loc"] for i in same_crash_index
                        ],
                        "reasons": reasons,
                        "histogram": same_crash_histogram,
                        "num_crashes": len(same_crash_index),
                    }
                )
            return combined_histogram
        else:
            for same_crash_index in same_crash_indexes:
                # only include the same keys in the result histogram
                common_keys = self.crashes[same_crash_index[0]].histogram.keys()
                for crash_index in same_crash_index[1:]:
                    common_keys = (
                        common_keys & self.crashes[crash_index].histogram.keys()
                    )

                same_crash_histogram = {}
                for crash_index in same_crash_index:
                    for k in common_keys:
                        same_crash_histogram[k] = (
                            same_crash_histogram.get(k, 0)
                            + self.crashes[crash_index].histogram[k]
                        )

                # sort
                same_crash_histogram = {
                    k: v
                    for k, v in sorted(
                        same_crash_histogram.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )
                }
                # common_histogram = dict(
                #     sorted(common_histogram.items(), key=lambda i: i[1], reverse=True)
                # )
                reasons = {}
                for i in same_crash_index:
                    reasons[self.crashes[i].reason] = (
                        reasons.get(self.crashes[i].reason, 0) + 1
                    )

                combined_histogram.append(
                    {
                        "pkt_locs": [self.crashes[i].pkt_loc for i in same_crash_index],
                        "reasons": reasons,
                        "histogram": same_crash_histogram,
                        "num_crashes": len(same_crash_index),
                    }
                )

        return combined_histogram


class ESP32Capture(Capture):
    def __init__(self, path: str, log_path: str, use_cache: bool = True):
        super().__init__(path, "bt", "esp32", 4, use_cache=use_cache)
        self.log_path = log_path

    def assign_identifier_to_crashes(self):
        # crash identifier: Backtrace||Backtrace TODO: update existing format which is using single | as separator
        if not os.path.exists(self.log_path):
            # super().gen_crash_identifier()
            return
        crash_identifiers = extract_crash_reason_bt(self.log_path)
        crash_identifiers_index = 0

        for crash in self.crashes:
            reason = "not_found"
            # TODO: trial should be replaced with try until log's timestamp bigger than crash's
            for trial in range(3):
                # Possible that the log is using UTC+8 while the timestamps in capture file are using UTC+0
                if crash_identifiers_index + trial >= len(crash_identifiers):
                    break
                diff = abs(
                    crash.timestamp
                    - crash_identifiers[crash_identifiers_index + trial][1]
                )
                if diff % (8 * 60 * 60) < 2:
                    reason = crash_identifiers[crash_identifiers_index + trial][0]
                    crash_identifiers_index = crash_identifiers_index + trial + 1
                    break
                # if (
                #     abs(
                #         crash.timestamp
                #         - crash_identifiers_ts[crash_identifiers_index + trial][1]
                #     )
                #     < 2
                #     or abs(
                #         abs(
                #             crash.timestamp
                #             - crash_identifiers_ts[crash_identifiers_index + trial][1]
                #         )
                #         - 8 * 60 * 60
                #     )
                #     < 2
                # ):
                #     reason = crash_identifiers_ts[crash_identifiers_index + trial][0]
                #     crash_identifiers_index = crash_identifiers_index + trial + 1
                #     break

            crash.reason = reason

    @staticmethod
    def is_same_crash_identifier(id1, id2, thresh: int) -> bool:
        # TODO
        return is_same_crash(id1, id2, thresh)

    @staticmethod
    def find_crash_identifier_from_run_log(run_log_path) -> str | None:
        # TODO: optimize
        crash_id = extract_crash_reason_bt(run_log_path)
        if crash_id == []:
            return None
        return crash_id[0][0]


class CypressCapture(Capture):
    def __init__(self, path: str, use_cache=True):
        super().__init__(path, "bt", "cypress", use_cache)


# run_exploit should return
# 1. execution result
# 2. crash identifier, if any


# class PicklableEnhancedPacket:
#     # EnhancedPacket object from `python-pcapng` module somehow cannot be saved using `pickle` or `dill` module.
#     def __init__(self, pcapng_packet: EnhancedPacket) -> None:
#         self.packet_data = pcapng_packet.packet_data


# Reason for issue "Can't get attribute 'XX' on <module '__main__' from 'YY'":
# https://stackoverflow.com/a/27733727 Workaround: https://stackoverflow.com/a/27733727
# class CustomUnpickler(pickle.Unpickler):
#     # usage: _crashes = CustomUnpickler(f).load()
#     def find_class(self, module, name):
#         if name == "PicklableEnhancedPacket":
#             return PicklableEnhancedPacket
#         return super().find_class(module, name)


# TODO: bad function, should remove
# def extract_crash_reason(log_path, capture_type):
#     # log_path can be pcap file path or actual log file path
#     if log_path.endswith(".pcap") or log_path.endswith(".pcapng"):
#         # log with be in the directory as capture file with name `monitor.1.txt`
#         actual_log_path = os.path.join(os.path.dirname(log_path), "monitor.1.txt")
#     else:
#         actual_log_path = log_path

#     if capture_type == "bt":
#         return extract_crash_reason_bt(actual_log_path)


def extract_crash_reason_bt(log_path):
    """
    For ESP32, some error logs will be printed out when crash happens. Guru Meditation Error and Backtrace line
    will remain the same when the same crash happens.
    Example log file is shown below, note that timestamp [2022-06-22 22:54:46.827969] may or may not be present.
    [2022-06-22 22:54:46.827969] Guru Meditation Error: Core  0 panic'ed (LoadProhibited). Exception was unhandled.
    [2022-06-22 22:54:46.838065] Core  0 register dump:
    ......
    [2022-06-22 22:54:46.838066] Backtrace:0x40028dcc:0x3ffcc150 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
    ......
    [2022-06-22 22:54:46.838065] Core  1 register dump:
    ......
    [2022-06-22 22:54:46.838066] Backtrace:0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
    ......
    [2022-06-22 22:54:46.827969] Guru Meditation Error:
    """
    if not os.path.exists(log_path):
        # TODO:
        return [[None, 0]]

    # Some invalid characters can be present, just ignore
    reason_txt = open(log_path, "r", encoding="utf8", errors="ignore")
    reasons = []
    reason = ""
    timestamp_re = re.compile(r"^\[.*?\]")
    # TODO: store ELF file hash somewhere
    timestamp = ""
    for line in reason_txt:
        """
        Version 1
        The log might be missing some part, e.g. "Guru Meditation Error" line may not be there
        when crash happens, but "Backtrace" line is there.

        if "Guru Meditation Error" in line:
            if reason != "":
                reasons.append([reason, timestamp])
            reason = timestamp_re.sub("", line).strip()
            if len(timestamp_re.findall(line)) == 0:
                continue
            timestamp = timestamp_re.findall(line)[0]
            # The timestamp in the log file is in UTC+8
            timestamp = (
                time.mktime(time.strptime(timestamp, "[%Y-%m-%d %H:%M:%S.%f]"))
                - 8 * 60 * 60
            )
        elif "Backtrace:" in line:
            reason = reason + "|" + timestamp_re.sub("", line).strip()
        """

        # find all "Guru Meditation Error" and "Backtrace" lines, then group the lines with timestamp
        # falling within 10 seconds into one crash reason
        if ("Guru Meditation Error" in line) or ("Backtrace:" in line):
            reason = timestamp_re.sub("", line).strip()
            if len(timestamp_re.findall(line)) == 0:
                timestamp = 0
            else:
                # The timestamp in the log file is in UTC+8 or UTC, TODO
                timestamp = (
                    time.mktime(
                        time.strptime(
                            timestamp_re.findall(line)[0], "[%Y-%m-%d %H:%M:%S.%f]"
                        )
                    )
                    - 8 * 60 * 60
                )

            # append reason if they are very close in terms of time
            if len(reasons) > 0 and abs(timestamp - reasons[-1][1]) < 10:
                reasons[-1][0] = reasons[-1][0] + "|" + reason
            else:
                reasons.append([reason, timestamp])

    # Remember to append the last reason
    # reasons.append([reason, timestamp]) # Version 1 need
    return reasons


if __name__ == "__main__":
    mut_capture_path = "/home/user/wdissector/bindings/python/captures/bluetooth_esp32/mut/capture_bluetooth.pcapng"
    mut_capture = Capture(mut_capture_path, "bt", use_cache=True)
    # combine_histogram(mut_capture, 2000)
    print(mut_capture.gen_histogram(2000, 1))
