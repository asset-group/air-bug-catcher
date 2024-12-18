from auto_exploiter import AutoExploiter
from exploiter.cypress_bt import CypressExploiter
from fuzzlog.cypress_bt import CypressBtFuzzlog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher for Cypress")

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
auto_exploiter = AutoExploiter(
    fuzzlog=fuzzlog,
    exploiter=exploiter,
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
