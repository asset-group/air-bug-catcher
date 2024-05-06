from .esp32_bt import ESP32BtFuzzLog


class CypressBtFuzzlog(ESP32BtFuzzLog):
    def __init__(
        self,
        *,
        use_cache: bool,
        enable_group_crashes: bool,
        capture_path: str,
    ) -> None:
        super().__init__(
            use_cache=use_cache,
            enable_group_crashes=enable_group_crashes,
            capture_path=capture_path,
            log_path="",
            same_crash_thresh=0,
        )

        self.board = "cypress"
