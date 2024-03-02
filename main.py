from auto_exploiter import AutoExploiter

capture_path = "/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/capture_bluetooth.pcapng"
capture_log_path = (
    "/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/monitor.1.txt"
)

esp32_auto_exploiter = AutoExploiter(
    capture_path, "bt", "esp32", esp32_log_path=capture_log_path
)

esp32_auto_exploiter.auto_exploit(2000, 4, 5, 1, 60 * 60, 60, 50)
