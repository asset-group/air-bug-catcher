import os

from exploiter.simcom_5g import SIMCom5GExploiter
from fuzzlog.simcom_5g import SIMCom5GFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start baseline exploiter for simcom")

exploits = []
for root, dirs, files in os.walk(
    "/home/user/wdissector/modules/airbugcatcher/captures/simcom_5g"
):
    for file in files:
        pref = file.replace("baseline_data_", "").replace(".bin", "")
        exploit = f"mac_sch_bl_exp_simcom_{pref}"
        exploits.append(exploit)


fuzzlog = SIMCom5GFuzzLog(
    use_cache=False,
    enable_group_crashes=True,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/simcom_5g/capture_nr5g_gnb.pcapng",
)

exploiter = SIMCom5GExploiter(
    session_id=session_id,
    run_dir="/home/user/wdissector4",
    fuzzlog=fuzzlog,
    target_hub_port=4,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)


for exploit in exploits:
    target_crash_type = "timeout" if "timeout" in exploit else "normal"
    crash_triggered, crash_ids = exploiter.run_exploit_once(exploit, "", target_crash_type)
    ae_logger.info(f"Baseline exploit {exploit}: crash_ids: {crash_ids}")
