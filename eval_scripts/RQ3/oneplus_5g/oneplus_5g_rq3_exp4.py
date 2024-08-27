from auto_exploiter import AutoExploiter
from exploiter.oneplus_5g import OnePlus5GExploiter
from fuzzlog.oneplus_5g import OnePlus5GFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start auto exploiter")

oneplus_fuzzlog = OnePlus5GFuzzLog(
    use_cache=True,
    enable_group_crashes=True,
    capture_path="/home/user/wdissector/modules/auto-exploiter/captures/nordce2_eval_evo_nb/capture_nr5g_gnb_processed.pcapng",
    log_path="/home/user/wdissector/modules/auto-exploiter/captures/nordce2_eval_evo_nb/monitor.combined.txt",
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
    max_trial_time=60 * 60,
    enable_flooding=False,
    enable_duplication=False,
    enable_mutation=True,
)

auto_exploiter.run()