import os
import re
import sys

from .utils import convert_friendly_time, count_total_exp_time

if len(sys.argv) < 2:
    print("Need to specify the RQ1 results folder.")


results_folder = sys.argv[1]


def count_rq1(device):
    raw_log_path = os.path.join(results_folder, f"{device}/{device}_rq1.log")
    with open(raw_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "log is saved in" in line:
                abc_log_name = re.findall(r"/[^/]*?\.log", line)[0]
                abc_log_path = os.path.join(results_folder, f"{device}{abc_log_name}")
                break

    # Unique bugs
    num_unique_crash = 0
    num_unique_hang = 0
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "Auto exploit for" in line:
                if "timeout_" in line:
                    num_unique_hang += 1
                else:
                    num_unique_crash += 1
    num_unique = num_unique_crash + num_unique_hang

    # Reproduced & Not reproduced
    num_reproduced_crash = 0
    num_reproduced_hang = 0
    num_not_reproduced_crash = 0
    num_not_reproduced_hang = 0
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        in_exploit = False
        exploit_type = ""
        for line in f:
            if "Auto exploit for" in line:
                in_exploit = True
                if "timeout_" in line:
                    exploit_type = "hang"
                else:
                    exploit_type = "crash"
            elif in_exploit and ("triggers crash" in line or "Same crash found" in line):
                if exploit_type == "hang":
                    num_reproduced_hang += 1
                else:
                    num_reproduced_crash += 1
                in_exploit = False
            elif "No crash ever" in line:
                if exploit_type == "hang":
                    num_not_reproduced_hang += 1
                else:
                    num_not_reproduced_crash += 1
    num_reproduced = num_reproduced_crash + num_reproduced_hang
    num_not_reproduced = num_not_reproduced_crash + num_not_reproduced_hang

    # Expected & Unexpected
    num_expected_crash = 0
    num_expected_hang = 0
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        in_exploit = False
        exploit_type = ""
        for line in f:
            if "Auto exploit for" in line:
                in_exploit = True
                if "timeout_" in line:
                    exploit_type = "hang"
                else:
                    exploit_type = "crash"
            elif in_exploit and "Same crash found for" in line:
                if exploit_type == "hang":
                    num_expected_hang += 1
                else:
                    num_expected_crash += 1
                in_exploit = False
    num_unexpected_crash = num_reproduced_crash - num_expected_crash
    num_unexpected_hang = num_reproduced_hang - num_expected_hang
    num_expected = num_expected_crash + num_expected_hang
    num_unexpected = num_unexpected_crash + num_unexpected_hang

    # Max # Mut & Max # Replay
    mut_max = 0
    replay_max = 0
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "mut_max" in line:
                m = re.search(r"mut_max: (\d+)", line)
                mut_max = int(m.group(1))
            elif "dup_max" in line:
                m = re.search(r"dup_max: (\d+)", line)
                replay_max = int(m.group(1))

    # # Test Case
    num_test_case = 0
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "Run exploit" in line:
                num_test_case += 1

    time_taken = count_total_exp_time(abc_log_path)

    return (
        num_unique,
        num_unique_crash,
        num_unique_hang,
        num_reproduced,
        num_reproduced_crash,
        num_reproduced_hang,
        num_not_reproduced,
        num_not_reproduced_crash,
        num_not_reproduced_hang,
        num_expected,
        num_expected_crash,
        num_expected_hang,
        num_unexpected,
        num_unexpected_crash,
        num_unexpected_hang,
        mut_max,
        replay_max,
        num_test_case,
        time_taken,
    )


def rq1_display_helper(device, stats):
    (
        num_unique,
        num_unique_crash,
        num_unique_hang,
        num_reproduced,
        num_reproduced_crash,
        num_reproduced_hang,
        num_not_reproduced,
        num_not_reproduced_crash,
        num_not_reproduced_hang,
        num_expected,
        num_expected_crash,
        num_expected_hang,
        num_unexpected,
        num_unexpected_crash,
        num_unexpected_hang,
        mut_max,
        replay_max,
        num_test_case,
        time_taken,
    ) = stats
    print(
        f"{device}:\tunique bugs: {num_unique} ({num_unique_crash} + {num_unique_hang}), reproduced: {num_reproduced} ({num_reproduced_crash} + {num_reproduced_hang}), not reproduced: {num_not_reproduced} ({num_not_reproduced_crash} + {num_not_reproduced_hang})"
    )
    print(
        f"\t\texpected: {num_expected} ({num_expected_crash} + {num_expected_hang}), unexpected: {num_unexpected} ({num_unexpected_crash} + {num_unexpected_hang})"
    )
    print(
        f"\t\tmax # mutation: {mut_max}, max # replay: {replay_max}, # test case: {num_test_case}, time: {convert_friendly_time(time_taken)}"
    )
    print()


esp32_bt_stats = count_rq1("esp32_bt")
cypress_bt_stats = count_rq1("cypress_bt")
oneplus_5g_stats = count_rq1("oneplus_5g")
simcom_5g_stats = count_rq1("simcom_5g")
esp32_wifi_stats = count_rq1("esp32_wifi")
total_stats = []
for i, j, k, m, n in zip(
    esp32_bt_stats, cypress_bt_stats, oneplus_5g_stats, simcom_5g_stats, esp32_wifi_stats
):
    total_stats.append(i + j + k + m + n)

print("===== RQ1 Statistics =====")
print("Format INT (INT + INT) means <total number> (<number of crash> + <number of hang>)")
rq1_display_helper("esp32_bt", esp32_bt_stats)
rq1_display_helper("cypress_bt", cypress_bt_stats)
rq1_display_helper("oneplus_5g", oneplus_5g_stats)
rq1_display_helper("simcom_5g", simcom_5g_stats)
rq1_display_helper("esp32_wifi", esp32_wifi_stats)
rq1_display_helper("Total (All Devices)", total_stats)
