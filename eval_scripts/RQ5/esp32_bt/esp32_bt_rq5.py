import os

from exploiter.esp32_bt import ESP32BtExploiter
from fuzzlog.esp32_bt import ESP32BtFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start baseline exploiter")

exploits = []
for root, dirs, files in os.walk(
    "/home/user/wdissector/modules/airbugcatcher/captures/esp32_bt/baseline_data"
):
    for file in files:
        pref = file.replace("baseline_data_", "").replace(".bin", "")
        exploit = f"baseline_exp_{pref}"
        exploits.append(exploit)

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


for exploit in exploits:
    target_crash_type = "timeout" if "timeout" in exploit else "normal"
    crash_triggered, crash_ids = esp32_bt_exploiter.run_exploit_once(
        exploit, "", target_crash_type
    )
    ae_logger.info(f"Baseline exploit {exploit}: crash_ids: {crash_ids}")
