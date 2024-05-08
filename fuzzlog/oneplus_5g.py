import os
import re

from constants import CAPTURE_CACHE_PATH
from utils import ae_logger, calc_file_sha256, extract_ts
from utils_wdissector import assign_crash_ids_wdissector, discover_crashes_wdissector

from .fuzzlog import Crash, FuzzLog, FuzzLogCache


class OnePlus5GFuzzLog(FuzzLog):
    def __init__(
        self,
        *,
        use_cache: bool,
        enable_group_crashes: bool,
        capture_path: str,
        log_path: str,
    ) -> None:
        super().__init__(
            protocol="5g",
            board="oneplus",
            use_cache=use_cache,
            has_trace_log=log_path != "",
            enable_group_crashes=enable_group_crashes,
        )
        self.capture_path = capture_path
        self.log_path = log_path

        self.crashes: list[Crash]

        # Initialize cache
        if self.use_cache:
            capture_sha256 = calc_file_sha256(self.capture_path)
            cache_path = os.path.join(CAPTURE_CACHE_PATH, f"{capture_sha256}.pickle")
            self.fuzzlog_cache = FuzzLogCache(
                cache_path,
                refs=[self.discover_crashes, self.assign_crash_identifiers],
            )

        self.discover_crashes()
        self.group_crashes()

    def is_same_crash_id(self, id1, id2):
        return id1 == id2

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
                        res = re.findall(
                            r"\[Crash\] (Crash detected at state|Device Removed at state) (.*)",
                            line,
                        )
                        if len(res) > 0:
                            crash_id = (
                                res[0][1]
                                .replace("", "")
                                .replace("[00m", "")
                                .replace('"', "")
                            )
            else:
                # Get from trace log
                crash_ids = self.crash_ids_from_trace_log(trace_log_path)
                if len(crash_ids) > 0:
                    crash_id = crash_ids[0][0]
        else:
            ae_logger.error(f"Invalid crash type: {target_crash_type}.")

        return crash_id

    def crash_ids_from_trace_log(self, log_path: str) -> list[tuple[str, float]]:
        # TODO: possible that no ID is found
        identifiers = []
        with open(log_path, "r", encoding="utf8") as f:
            for line in f:
                if "sModemReason" in line:
                    ts = extract_ts(line)
                    identifier = re.findall(r"cause:(.*)", line)[0]
                    identifiers.append((identifier, ts))

        return identifiers

    def assign_crash_identifiers(self):
        assign_crash_ids_wdissector(self.crashes)
        if not self.has_trace_log:
            return

        crash_ids = self.crash_ids_from_trace_log(self.log_path)
        if crash_ids is None:
            return

        crash_ids_pointer = 0
        max_window = 3

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

        self.crashes = discover_crashes_wdissector("5g", self.capture_path, 0)
        self.assign_crash_identifiers()

        # Save cache of possible
        if self.use_cache and self.fuzzlog_cache is not None:
            self.fuzzlog_cache.save(self.crashes)
