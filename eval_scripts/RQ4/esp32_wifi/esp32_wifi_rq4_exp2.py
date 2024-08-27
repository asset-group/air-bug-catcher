from auto_exploiter import AutoExploiter
from exploiter.esp32_wifi import ESP32WifiExploiter
from fuzzlog.esp32_wifi import ESP32WifiFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

fuzzlog = ESP32WifiFuzzLog(
    use_cache=False,
    enable_group_crashes=True,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/esp32_wifi/capture_wifi.pcapng",
    log_path="/home/user/wdissector/modules/airbugcatcher/captures/esp32_wifi/monitor.1.txt",
    same_crash_thresh=50000,
)

exploiter = ESP32WifiExploiter(
    fuzzlog=fuzzlog,
    session_id=session_id,
    run_dir="/home/user/wdissector",
    target_port="/dev/ttyWiFi",
    target_hub_port=3,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)


auto_exploiter = AutoExploiter(
    fuzzlog=fuzzlog,
    exploiter=exploiter,
    session_id=session_id,
    max_fuzzed_pkts=3,
    min_trial_pkts=6,
    min_trial_iter=1,
    max_trial_time=60 * 20,
    enable_flooding=True,
    enable_duplication=True,
    enable_mutation=True,
)

auto_exploiter.run()
