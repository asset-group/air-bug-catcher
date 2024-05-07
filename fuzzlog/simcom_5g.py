from .oneplus_5g import OnePlus5GFuzzLog


class SIMCom5GFuzzLog(OnePlus5GFuzzLog):
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
        )
        self.board = "simcom"
