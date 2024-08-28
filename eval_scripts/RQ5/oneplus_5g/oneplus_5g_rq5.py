import os

from exploiter.oneplus_5g import OnePlus5GExploiter
from fuzzlog.oneplus_5g import OnePlus5GFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start baseline exploiter for oneplus")

exploits = []
for root, dirs, files in os.walk(
    "/home/user/wdissector/modules/airbugcatcher/captures/oneplus_5g/"
):
    for file in files:
        pref = file.replace("baseline_data_", "").replace(".bin", "")
        exploit = f"mac_sch_bl_exp_oneplus_{pref}"
        exploits.append(exploit)

oneplus_fuzzlog = OnePlus5GFuzzLog(
    use_cache=False,
    enable_group_crashes=True,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/oneplus_5g/capture_nr5g_gnb.pcapng",
    log_path="/home/user/wdissector/modules/airbugcatcher/captures/oneplus_5g/monitor.combined.txt",
)
oneplus_exploiter = OnePlus5GExploiter(
    session_id=session_id,
    run_dir="/home/user/wdissector",
    fuzzlog=oneplus_fuzzlog,
    modem_timeout=60,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)

for exploit in exploits:
    target_crash_type = "timeout" if "timeout" in exploit else "normal"
    crash_triggered, crash_ids = oneplus_exploiter.run_exploit_once(
        exploit, "", target_crash_type
    )
    ae_logger.info(f"Baseline exploit {exploit}: crash_ids: {crash_ids}")
