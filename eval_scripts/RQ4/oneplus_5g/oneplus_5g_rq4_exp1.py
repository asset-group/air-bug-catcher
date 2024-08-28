from auto_exploiter import AutoExploiter
from exploiter.oneplus_5g import OnePlus5GExploiter
from fuzzlog.oneplus_5g import OnePlus5GFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

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

auto_exploiter = AutoExploiter(
    fuzzlog=oneplus_fuzzlog,
    exploiter=oneplus_exploiter,
    session_id=session_id,
    max_fuzzed_pkts=3,
    min_trial_pkts=6,
    min_trial_iter=3,
    max_trial_time=60 * 10,
    enable_flooding=True,
    enable_duplication=True,
    enable_mutation=True,
)

auto_exploiter.run()
