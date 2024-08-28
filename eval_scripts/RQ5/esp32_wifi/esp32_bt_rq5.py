import os

from exploiter.esp32_wifi import ESP32WifiExploiter
from fuzzlog.esp32_wifi import ESP32WifiFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

exploits = []
for root, dirs, files in os.walk(
    "/home/user/wdissector/modules/airbugcatcher/captures/esp32_wifi/baseline_data"
):
    for file in files:
        pref = file.replace("baseline_data_", "").replace(".bin", "")
        exploit = f"esp32_wifi_bl_{pref}"
        exploits.append(exploit)


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
    target_hub_port=4,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)

for exploit in exploits:
    target_crash_type = "timeout" if "timeout" in exploit else "normal"
    crash_triggered, crash_ids = exploiter.run_exploit_once(exploit, "", target_crash_type)
    ae_logger.info(f"Baseline exploit {exploit}: crash_ids: {crash_ids}")
