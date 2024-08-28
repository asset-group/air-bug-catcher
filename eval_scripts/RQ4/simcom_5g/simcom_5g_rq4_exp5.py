from auto_exploiter import AutoExploiter
from exploiter.simcom_5g import SIMCom5GExploiter
from fuzzlog.simcom_5g import SIMCom5GFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

fuzzlog = SIMCom5GFuzzLog(
    use_cache=False,
    enable_group_crashes=True,
    capture_path="/home/user/wdissector/modules/airbugcatcher/captures/simcom_5g/capture_nr5g_gnb.pcapng",
)

exploiter = SIMCom5GExploiter(
    session_id=session_id,
    run_dir="/home/user/wdissector",
    fuzzlog=fuzzlog,
    target_hub_port=4,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)

auto_exploiter = AutoExploiter(
    fuzzlog=fuzzlog,
    exploiter=exploiter,
    session_id=session_id,
    max_fuzzed_pkts=2,
    min_trial_pkts=6,
    min_trial_iter=3,
    max_trial_time=60 * 60,
    enable_flooding=True,
    enable_duplication=True,
    enable_mutation=True,
)

auto_exploiter.run()
