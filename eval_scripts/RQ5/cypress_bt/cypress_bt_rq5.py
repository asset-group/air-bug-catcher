import os

from exploiter.cypress_bt import CypressExploiter
from fuzzlog.cypress_bt import CypressBtFuzzlog
from utils import ae_logger, session_id

ae_logger.info("Start baseline exploiter for cypress")


exploits = []
for root, dirs, files in os.walk(
    "/home/user/wdissector/modules/airbugcatcher/captures/cypress_bt/baseline_data"
):
    for file in files:
        pref = file.replace("baseline_data_", "").replace(".bin", "")
        exploit = f"cypress_bt_bl_{pref}"
        exploits.append(exploit)

fuzzlog = CypressBtFuzzlog(
    use_cache=False,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/cypress_bt/capture_bluetooth_cypress_fuzzing.pcapng",
    enable_group_crashes=True,
)

exploiter = CypressExploiter(
    fuzzlog=fuzzlog,
    session_id=session_id,
    run_dir="/home/user/wdissector",
    host_port="/dev/ttyBTHost",
    target="20:73:5b:18:6c:f2",
    target_port="/dev/ttyCypress",
    target_hub_port=2,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)


for exploit in exploits:
    target_crash_type = "timeout" if "timeout" in exploit else "normal"
    crash_triggered, crash_ids = exploiter.run_exploit_once(exploit, "", target_crash_type)
    ae_logger.info(f"Baseline exploit {exploit}: crash_ids: {crash_ids}")
