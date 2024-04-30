import os
import pickle
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from utils import (
    calc_bytes_sha256,
    calc_file_sha256,
    is_same_crash,
    label_packets,
    logger,
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
        identifier: str | None,
        raw: bytes,
        timestamp: int,
    ) -> None:
        self.fuzzed_pkts = (
            fuzzed_pkts  # this should be in ascending order by "pkt_loc" key
        )
        self.pkt_loc = pkt_loc
        self.iteration = iteration
        self.identifier = identifier
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

    @staticmethod
    def is_same_crash_id(id1, id2, thresh: int | None = None) -> bool:
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

    def assign_identifier_to_crashes(self):
        # Default to use state information in the capture as crash identifier
        for crash in self.crashes:
            if self.protocol == "bt":
                # crash.raw example: 00 00 00 00 0a fa [Crash] Crash detected at state TX / Baseband / FHS
                crash.identifier = crash.raw[6:].decode()
            elif self.protocol == "5g":
                # TODO Implement for 5g
                pass
            else:
                logger.error(
                    "No assign_identifier_to_crashes function implemented for",
                    self.protocol,
                )

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
            # mutated packet
            if pkt_comment == "Fuzzed from previous":
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
                crashes.append(
                    Crash(
                        fuzzed_pkts=fuzzed_pkts[:],
                        pkt_loc=packet_index,
                        iteration=current_iteration,
                        identifier=None,
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

    def group_crashes(self, same_crash_threshold: int):
        # Group the same kind of crashes based on their identifiers.
        # Developer note: `itertools.groupby` is not a feasible solution here.
        grouped_crashes: list[list[Crash]] = []

        # Helper variable to indicate if a crash is already visited
        same_crash_indexes_map: dict[int, list] = {}
        for idx1, crash1 in enumerate(self.crashes):
            same_crash_indexes_map[idx1] = []
            for idx2, crash2 in enumerate(self.crashes):
                if self.is_same_crash_id(
                    crash1.identifier, crash2.identifier, same_crash_threshold
                ):
                    same_crash_indexes_map[idx1].append(idx2)

        visited = set()
        for k, v in same_crash_indexes_map.items():
            if k in visited:
                continue
            visited.add(k)
            temp = set([k])
            for i in v:
                temp.add(i)
                visited.add(i)
                for j in same_crash_indexes_map[i]:
                    temp.add(j)
                    visited.add(j)

            grouped_crashes.append([self.crashes[i] for i in temp])

        return grouped_crashes


class ESP32Capture(Capture):
    def __init__(self, path: str, log_path: str, use_cache: bool = True):
        super().__init__(path, "bt", "esp32", 4, use_cache=use_cache)
        self.log_path = log_path

    def assign_identifier_to_crashes(self):
        # More crash information can be retrieved on ESP32 board from fuzzing log.
        # Some backtrace lines are present in logs when crash happens on ESP32 board.
        # crash identifier: Backtrace||Backtrace
        # TODO: update existing format which is using single | as separator
        if not os.path.exists(self.log_path):
            super().assign_identifier_to_crashes()
            return
        crash_ids = extract_crash_reason_bt(self.log_path)
        crash_ids_index = 0
        max_window = 2

        for crash in self.crashes:
            identifier = "not_found"
            # TODO: trial should be replaced with try until log's timestamp bigger than crash's
            # Possible that the log is using UTC+8 while the timestamps in capture file are using UTC+0, or reversely
            for trial in range(3):
                if crash_ids_index + trial >= len(crash_ids):
                    break
                diff = abs(crash.timestamp - crash_ids[crash_ids_index + trial][1])
                # consider diff = 8 * 60 * 60 + 1 or 8 * 60 * 60 - 1
                diff_remainder = diff % (8 * 60 * 60)
                if (
                    diff_remainder < max_window
                    or abs(diff_remainder - 8 * 60 * 60) < max_window
                ):
                    identifier = crash_ids[crash_ids_index + trial][0]
                    crash_ids_index = crash_ids_index + trial + 1
                    break

            crash.identifier = identifier

    @staticmethod
    def is_same_crash_id(id1, id2, thresh: int) -> bool:
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
        # find all "Guru Meditation Error" and "Backtrace" lines, then group the lines with timestamp
        # falling within 1 seconds slot into one crash identifier
        if ("Guru Meditation Error" in line) or ("Backtrace:" in line):
            reason = timestamp_re.sub("", line).strip()
            if len(timestamp_re.findall(line)) == 0:
                timestamp = 0
            else:
                timestamp = time.mktime(
                    time.strptime(
                        timestamp_re.findall(line)[0], "[%Y-%m-%d %H:%M:%S.%f]"
                    )
                )

            # append reason if they are very close in terms of time
            if len(reasons) > 0 and abs(timestamp - reasons[-1][1]) < 1:
                reasons[-1][0] = reasons[-1][0] + "|" + reason
            else:
                reasons.append([reason, timestamp])

    # Remember to append the last reason
    # reasons.append([reason, timestamp]) # Version 1 need
    return reasons
