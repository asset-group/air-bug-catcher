import os
import re

from constants import CAPTURE_CACHE_PATH
from utils import ae_logger, calc_file_sha256, extract_ts, is_same_crash
from utils_wdissector import assign_crash_ids_wdissector, discover_crashes_wdissector

from .fuzzlog import Crash, FuzzLog, FuzzLogCache


class ESP32BtFuzzLog(FuzzLog):
    def __init__(
        self,
        *,
        use_cache: bool,
        enable_group_crashes: bool,
        capture_path: str,
        log_path: str,
        same_crash_thresh: int,
    ) -> None:
        """
        Empty log_path means no detailed log available
        """
        super().__init__(
            protocol="bt",
            board="esp32",
            use_cache=use_cache,
            has_trace_log=log_path != "",
            enable_group_crashes=enable_group_crashes,
        )
        self.capture_path = capture_path
        self.log_path = log_path
        self.same_crash_thresh = same_crash_thresh

        self.crashes: list[Crash]

        # Initialize cache
        if self.use_cache:
            capture_sha256 = calc_file_sha256(self.capture_path)
            cache_path = os.path.join(CAPTURE_CACHE_PATH, f"{capture_sha256}.pickle")
            self.fuzzlog_cache = FuzzLogCache(
                cache_path, [self.discover_crashes, self.assign_crash_identifiers]
            )

        self.discover_crashes()
        self.group_crashes()

    def is_same_crash_id(self, id1, id2):
        if id1 is None or id2 is None:
            return False
        # TODO
        return is_same_crash(id1, id2, self.same_crash_thresh)

    def get_crash_id(self, trace_log_path: str, run_log_path: str, target_crash_type: str):
        """
        Get crash id from exploit running
        """
        # Normal crash:
        #      trace_log enabled: get from trace_log
        #      trace_log disabled: get from exploit run log
        # Timeout crash: always get from run log, last fuzzed packet state
        crash_id = "not_found"
        if target_crash_type == "timeout":
            # get the state of last fuzzed packet as identifier
            with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
                for line in f:
                    res = re.findall(r"Send .*? packet now!.*? State: (.*)", line)
                    if len(res) > 0:
                        crash_id = "timeout_" + res[0]
        elif target_crash_type == "normal":
            if not self.has_trace_log:
                # Get from run log
                with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
                    for line in f:
                        res = re.findall(r"\[Crash\] Crash detected at state (.*)", line)
                        if len(res) > 0:
                            crash_id = res[0].replace("", "").replace("[00m", "")
            else:
                # Get from trace log
                crash_ids = self.crash_ids_from_trace_log(trace_log_path)
                if len(crash_ids) > 0:
                    crash_id = crash_ids[0][0]
        else:
            ae_logger.error(f"Invalid crash type: {target_crash_type}.")

        return crash_id

    def crash_ids_from_trace_log(self, log_path: str):
        # TODO: what if no identifier found?

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
            return []

        # Some invalid characters can be present, just ignore
        identifiers = []
        identifier = ""
        timestamp_re = re.compile(r"^\[.*?\]")
        assert_re = re.compile(r".*((ASSERT|assert failed).*?(line |:)\d+).*?\n")

        # TODO: store ELF file hash somewhere
        guru_seen_count = 0
        assert_line: tuple[int, str] | None = None

        # flooding log: Send flooding packet now, or empty line, after ASSERT line
        meaningless_line_count = 0

        with open(log_path, "r", encoding="utf8", errors="ignore") as f:
            for line_idx, line in enumerate(f):
                # find all "Guru Meditation Error" and "Backtrace" lines, then group the lines with timestamp
                # falling within 1 seconds slot into one crash identifier
                if "ASSERT" in line or "assert failed" in line:
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
                                re_res = assert_re.findall(assert_line[1])
                                if len(re_res) > 0:
                                    identifiers.append(
                                        [
                                            re_res[0][0] + "|" + identifier,
                                            timestamp,
                                        ]
                                    )
                                else:
                                    identifiers.append(["|" + identifier, timestamp])
                                assert_line = None
                            else:
                                identifiers.append(["|" + identifier, timestamp])

                        guru_seen_count = 1

        return identifiers

    def assign_crash_identifiers(self):
        assign_crash_ids_wdissector(self.crashes)
        if not self.has_trace_log:
            return

        crash_ids = self.crash_ids_from_trace_log(self.log_path)
        if crash_ids is None:
            return

        crash_ids_pointer = 0
        max_window = 2

        for crash in self.crashes:
            if crash.type == "timeout":
                continue
            identifier = "not_found"
            # TODO: trial should be replaced with try until log's timestamp bigger than crash's
            # Possible that the log is using UTC+8 while the timestamps in capture file are using UTC+0, or reversely.
            # Thus judging two timestamps by comparing minutes and seconds only is a simple and naive approach. Then
            # consider hour:59:59 and hour+9:00:04 which makes judging more difficult. Another way is to calculate the
            # difference first which can be written as d=D or D+8*60*60 where D is the real difference. Second step is
            # calculate the remainder: r=d%(8*60*60).
            for trial in range(3):
                if crash_ids_pointer + trial >= len(crash_ids):
                    break
                diff = abs(crash.timestamp - crash_ids[crash_ids_pointer + trial][1])
                # consider diff = 8 * 60 * 60 + 1 or 8 * 60 * 60 - 1
                diff_remainder = diff % (8 * 60 * 60)
                if (
                    diff_remainder < max_window
                    or abs(diff_remainder - 8 * 60 * 60) < max_window
                ):
                    identifier = crash_ids[crash_ids_pointer + trial][0]
                    crash_ids_pointer = crash_ids_pointer + trial + 1
                    break

            crash.identifier = identifier

    def discover_crashes(self):
        ae_logger.info("Discovering crashes...")
        # Load from cache if possible
        if self.use_cache and self.fuzzlog_cache is not None:
            crashes = self.fuzzlog_cache.load()
            if crashes is not None:
                self.crashes = crashes
                return

        self.crashes = discover_crashes_wdissector("bt", self.capture_path, 4)
        self.assign_crash_identifiers()

        # Save cache of possible
        if self.use_cache and self.fuzzlog_cache is not None:
            self.fuzzlog_cache.save(self.crashes)
