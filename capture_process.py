import os
import pickle
import re
from dataclasses import dataclass
from typing import Literal

from constants import CAPTURE_CACHE_PATH
from utils import (
    ae_logger,
    calc_bytes_sha256,
    calc_file_sha256,
    extract_ts,
    is_same_crash,
    pcap_pkt_reader,
)
from wdissector import WD_DIR_TX



class Capture:
    def __init__(
        self,
        path: str,
        protocol: ProtocolType,
        board: BoardType,
        pkt_decoding_offset: int,
        use_cache=True,
    ):
        self.path = path
        self.protocol = protocol
        self.pkt_decoding_offset = pkt_decoding_offset
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
            ae_logger.error(
                f"Run log {run_log_path} does not exist, unable to find crash identifier."
            )

        with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                m = re.search(r"\[31m(\[Crash\] .*?)\[00m", line)
                if m:
                    return m.groups()[0]

        return None

    def _assign_identifier_to_crashes(self):
        # Default to use state information in the capture as crash identifier
        for crash in self.crashes:
            if self.protocol == "bt":
                # crash.raw example: 00 00 00 00 0a fa [Crash] Crash detected at state TX / Baseband / FHS
                crash.identifier = crash.raw[6:].decode()
            elif self.protocol == "5g":
                # TODO Implement for 5g
                pass
            else:
                ae_logger.error(
                    "No assign_identifier_to_crashes function implemented for",
                    self.protocol,
                )

    def assign_identifier_to_crashes(self) -> None:
        self._assign_identifier_to_crashes()

    # def is_duplicated_pkt():
    #     pass

    # def is_mutated_pkt():
    #     pass

    # def is_crash_pkt():

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
        ae_logger.info("Start capture crashes discovery...")
        # Cache logic, hack method, see comments above
        cache_version = calc_bytes_sha256(self.discover_capture_crashes.__code__.co_code)
        capture_sha256 = calc_file_sha256(self.path)
        self.capture_crash_cache_path = os.path.join(
            CAPTURE_CACHE_PATH, f"{capture_sha256}.pickle"
        )
        if self.use_cache:
            if os.path.exists(self.capture_crash_cache_path):
                with open(self.capture_crash_cache_path, "rb") as f:
                    try:
                        _crashes = pickle.load(f)
                        if _crashes["cache_version"] == cache_version:
                            self.crashes = _crashes["crashes"]
                            return
                        else:
                            ae_logger.info("Outdated capture cache, regenerating...")
                    except:
                        ae_logger.info("Invalid capture cache file, regenerating...")
            else:
                ae_logger.info("No capture cache is found, regenerating...")

        crashes: list[Crash] = []
        fuzzed_pkts: list[FuzzedPkt] = []
        prev_pkt_bytes: bytes
        crash_idx = 0
        current_iteration = 0
        for pkt_index, pkt in pcap_pkt_reader(self.path):
            pkt_comment = pkt.options.get("opt_comment")
            # mutated packet
            if pkt_comment == "Fuzzed from previous":
                # field_name = packet_mutated_field(prev_packet_bytes, packet.packet_data) # KEEP
                fuzzed_pkts.append(
                    FuzzedPkt(
                        pkt_bytes=pkt.packet_data,
                        loc=pkt_index,
                        iteration=current_iteration,
                        state=pkt_state(prev_pkt_bytes, self.pkt_decoding_offset),
                        filter=label_pkt(
                            prev_pkt_bytes, WD_DIR_TX, self.pkt_decoding_offset
                        ),
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
                        state=pkt_state(pkt.packet_data, self.pkt_decoding_offset),
                        filter=label_pkt(
                            pkt.packet_data, WD_DIR_TX, self.pkt_decoding_offset
                        ),
                        type="duplication",
                        fuzz_info=None,
                        prev_pkt_bytes=prev_pkt_bytes,
                    )
                )
            # TODO: which crashes should be ignored and why?
            elif pkt.packet_data[4:13] == b"\n\xfa[Crash]":
                if 0 and b"TX / LMP / LMP_detach" in pkt.packet_data:
                    pass
                elif len(fuzzed_pkts) == 0:
                    # sometimes two crashes are too close, no fuzzed packets for the second crash
                    # skip this crash
                    pass
                else:
                    crashes.append(
                        Crash(
                            fuzzed_pkts=fuzzed_pkts[:],
                            loc=pkt_index,
                            iteration=current_iteration,
                            identifier=None,
                            raw=pkt.packet_data,
                            timestamp=pkt.timestamp,
                        )
                    )
                    crash_idx += 1

                fuzzed_pkts = []

            elif self.protocol == "bt" and b"BT Process Started" in pkt.packet_data:
                current_iteration += 1
            # TODO: complete logic for 5g
            # elif self.protocol == "5g" and :

            prev_pkt_bytes = pkt.packet_data

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
        crash_ids = extract_crash_ids_bt(self.log_path)
        crash_ids_index = 0
        max_window = 2

        for crash in self.crashes:
            identifier = "not_found"
            # TODO: trial should be replaced with try until log's timestamp bigger than crash's
            # Possible that the log is using UTC+8 while the timestamps in capture file are using UTC+0, or reversely.
            # Thus judging two timestamps by comparing minutes and seconds only is a simple and naive approach. Then
            # consider hour:59:59 and hour+9:00:04 which makes judging more difficult. Another way is to calculate the
            # difference first which can be written as d=D or D+8*60*60 where D is the real difference. Second step is
            # calculate the remainder: r=d%(8*60*60).
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
        if id1 is None or id2 is None:
            return False
        return is_same_crash(id1, id2, thresh)

    @staticmethod
    def find_crash_identifier_from_run_log(run_log_path) -> str | None:
        # TODO: optimize, how?
        crash_id = extract_crash_ids_bt(run_log_path)
        if crash_id == []:
            return None
        return crash_id[0][0]


class CypressCapture(Capture):
    def __init__(self, path: str, use_cache=True):
        super().__init__(path, "bt", "cypress", 4, use_cache)


class NordicCapture(Capture):
    pass


# run_exploit should return
# 1. execution result
# 2. crash identifier, if any


def extract_crash_ids_bt(log_path):
    """
    For ESP32, some error logs will be printed out when crash happens. ASSERT information, Guru Meditation Error and Backtrace line
    will remain the same when the same crash happens.
    Example log file is shown below, note that timestamp [2022-06-22 22:54:46.827969] may or may not be present.

    [2023-11-23 13:17:40.464918] ASSERT_WARN(5 42), in lc_task.c at line 6708ASSERT_WARN(5 0), in lc_task.c at line 405
    [2022-06-22 22:54:46.827429] ASSERT_PARAM(-218959118 0), in arch_main.c at line 327
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
        ae_logger.warn(f"Log {log_path} does not exist.")
        return [[None, 0]]

    # Some invalid characters can be present, just ignore
    identifiers = []
    identifier = ""
    timestamp_re = re.compile(r"^\[.*?\]")
    assert_re = re.compile(r".*(ASSERT.*?line \d+).*?\n")

    # TODO: store ELF file hash somewhere
    guru_seen_count = 0
    assert_line: tuple[int, str] | None = None

    # flooding log: Sending flooding packet now, or empty line, after ASSERT line
    meaningless_line_count = 0

    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        for line_idx, line in enumerate(f):
            # find all "Guru Meditation Error" and "Backtrace" lines, then group the lines with timestamp
            # falling within 1 seconds slot into one crash identifier
            if "ASSERT" in line:
                assert_line = (line_idx, line)
                meaningless_line_count = 0
            elif line == "\n" or "Send flooding packet now" in line:
                meaningless_line_count += 1
            elif ("Guru Meditation Error" in line) or ("Backtrace:" in line):
                if "Guru Meditation Error" in line:
                    guru_seen_count += 1
                identifier = timestamp_re.sub("", line).strip()
                timestamp = extract_ts(line)

                # append lines if they are very close in terms of time, one identifier can consist of multiple lines
                if (
                    guru_seen_count <= 1
                    and len(identifiers) > 0
                    and abs(timestamp - identifiers[-1][1]) < 1
                ):
                    identifiers[-1][0] = identifiers[-1][0] + "|" + identifier
                else:
                    if assert_line is None:
                        identifiers.append(["|" + identifier, timestamp])
                    else:
                        is_assert_line_close = (
                            line_idx - assert_line[0] - meaningless_line_count < 15
                        )
                        is_assert_line_close = is_assert_line_close and (
                            extract_ts(line) - extract_ts(assert_line[1]) < 2
                        )
                        if is_assert_line_close:
                            identifiers.append(
                                [
                                    assert_re.findall(assert_line[1])[0] + "|" + identifier,
                                    timestamp,
                                ]
                            )
                            assert_line = None
                        else:
                            identifiers.append(["|" + identifier, timestamp])

                    guru_seen_count = 1

    return identifiers
