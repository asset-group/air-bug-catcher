from fuzzlog.esp32_bt import ESP32BtFuzzLog
from utils import ae_logger
from utils_wdissector import discover_crashes_wdissector


class ESP32WifiFuzzLog(ESP32BtFuzzLog):
    def __init__(
        self,
        *,
        use_cache: bool,
        enable_group_crashes: bool,
        capture_path: str,
        log_path: str,
        same_crash_thresh: int
    ) -> None:
        super().__init__(
            use_cache=use_cache,
            enable_group_crashes=enable_group_crashes,
            capture_path=capture_path,
            log_path=log_path,
            same_crash_thresh=same_crash_thresh,
        )
        self.protocol = "wifi"

    def discover_crashes(self):
        ae_logger.info("Discovering crashes...")
        # Load from cache if possible
        if self.use_cache and self.fuzzlog_cache is not None:
            crashes = self.fuzzlog_cache.load()
            if crashes is not None:
                self.crashes = crashes
                return

        self.crashes = discover_crashes_wdissector("wifi", self.capture_path, 0)
        self.assign_crash_identifiers()

        # Save cache of possible
        if self.use_cache and self.fuzzlog_cache is not None:
            self.fuzzlog_cache.save(self.crashes)
