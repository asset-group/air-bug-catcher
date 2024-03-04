from auto_exploiter import AutoExploiter

capture_path = "/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/capture_bluetooth.pcapng"
capture_log_path = (
    "/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/monitor.1.txt"
)

esp32_auto_exploiter = AutoExploiter(
    capture_path, "bt", "esp32", esp32_log_path=capture_log_path
)

esp32_auto_exploiter.auto_exploit(
    same_crash_thresh=2000,
    exploit_max_fuzzed_pkts=3,
    min_trial_pkts=6,
    max_trial_iter=1,
    max_trial_time=60 * 60,
    modem_timeout=60,
    exploit_timeout=50,
    exploit_running_dir="/home/user/wdissector2",
    host_port="/dev/ttyUSB1",
    target="fc:f5:c4:26:fa:b6",
    target_port="/dev/ttyUSB4",
    target_hub_port=2,
)

# esp32_auto_exploiter.auto_exploit(
#     same_crash_thresh=2000,
#     exploit_max_fuzzed_pkts=3,
#     min_trial_pkts=6,
#     max_trial_iter=1,
#     max_trial_time=60 * 60,
#     modem_timeout=60,
#     exploit_timeout=50,
#     exploit_running_dir="/home/user/wdissector",
#     host_port="/dev/ttyUSB3",
#     target="24:0a:c4:61:1c:1a",
#     target_port="/dev/ttyUSB5",
#     target_hub_port=4,
# )
