from auto_exploiter import AutoExploiter
from exploiter.esp32_bt import ESP32BtExploiter
from fuzzlog.esp32_bt import ESP32BtFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

fuzzlog = ESP32BtFuzzLog(
    use_cache=False,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/esp32_bt/capture_bluetooth.pcapng",
    log_path="",
    same_crash_thresh=2000,
    enable_group_crashes=True,
)
esp32_bt_exploiter = ESP32BtExploiter(
    fuzzlog=fuzzlog,
    session_id=session_id,
    run_dir="/home/user/wdissector",
    host_port="/dev/ttyBTHost",
    target="fc:f5:c4:26:fa:b6",
    target_port="/dev/ttyESP32-fc",
    target_hub_port=1,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)
auto_exploiter = AutoExploiter(
    fuzzlog=fuzzlog,
    exploiter=esp32_bt_exploiter,
    session_id=session_id,
    max_fuzzed_pkts=3,
    min_trial_pkts=6,
    min_trial_iter=3,
    max_trial_time=60 * 60,
    enable_flooding=False,
    enable_duplication=False,
    enable_mutation=True,
)

auto_exploiter.run()
