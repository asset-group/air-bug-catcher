import os
import sys

from .utils import (
    convert_friendly_time,
    count_expected_unexpected,
    count_total_exp_time,
    count_total_unique_bugs,
)

if len(sys.argv) < 2:
    print("Need to specify the RQ3 results folder.")


results_folder = sys.argv[1]


def count_rq3_expected_unexpected(device, exp_index):
    raw_log_path = os.path.join(results_folder, f"{device}/{device}_rq3_exp{exp_index}.log")
    num_expected, num_unexpected = count_expected_unexpected(raw_log_path)

    return f"{num_expected} / {num_unexpected}"


def count_rq3_exps_max_time(device, exp_indexes: list[int]):
    exp_times = []
    for exp_index in exp_indexes:
        raw_log_path = os.path.join(
            results_folder, f"{device}/{device}_rq3_exp{exp_index}.log"
        )
        exp_times.append(count_total_exp_time(raw_log_path))

    return convert_friendly_time(max(exp_times))


print("===== RQ3 Statistics =====\n")
raw_log_path = os.path.join(results_folder, f"esp32_bt/esp32_bt_rq3_exp1.log")
print(f"esp32_bt w/o log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"esp32_bt experiments w/o log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('esp32_bt', [1,2,3])}"
)
print(
    "esp32_bt w/o log, mutation only triggers\t",
    count_rq3_expected_unexpected("esp32_bt", 1),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_bt w/o log, mutation + replay triggers\t",
    count_rq3_expected_unexpected("esp32_bt", 2),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_bt w/o log, all triggers\t\t\t",
    count_rq3_expected_unexpected("esp32_bt", 3),
    "(Expected / Unexpected) bugs",
)
raw_log_path = os.path.join(results_folder, f"esp32_bt/esp32_bt_rq3_exp4.log")
print(f"esp32_bt with log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"esp32_bt experiments with log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('esp32_bt', [4,5,6])}"
)
print(
    "esp32_bt with log, mutation only triggers\t",
    count_rq3_expected_unexpected("esp32_bt", 4),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_bt with log, mutation + replay triggers\t",
    count_rq3_expected_unexpected("esp32_bt", 5),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_bt with log, all triggers\t\t\t",
    count_rq3_expected_unexpected("esp32_bt", 6),
    "(Expected / Unexpected) bugs",
)
print()

raw_log_path = os.path.join(results_folder, f"cypress_bt/cypress_bt_rq3_exp1.log")
print(f"cypress_bt w/o log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"cypress_bt experiments w/o log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('cypress_bt', [1,2,3])}"
)
print(
    "cypress_bt w/o log, mutation only triggers\t",
    count_rq3_expected_unexpected("cypress_bt", 1),
    "(Expected / Unexpected) bugs",
)
print(
    "cypress_bt w/o log, mutation + replay triggers\t",
    count_rq3_expected_unexpected("cypress_bt", 2),
    "(Expected / Unexpected) bugs",
)
print(
    "cypress_bt w/o log, all triggers\t\t",
    count_rq3_expected_unexpected("cypress_bt", 3),
    "(Expected / Unexpected) bugs",
)
print()

raw_log_path = os.path.join(results_folder, f"oneplus_5g/oneplus_5g_rq3_exp1.log")
print(f"oneplus_5g w/o log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"oneplus_5g experiments w/o log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('oneplus_5g', [1])}"
)
print(
    "oneplus_5g w/o log, mutation only triggers\t",
    count_rq3_expected_unexpected("oneplus_5g", 1),
    "(Expected / Unexpected) bugs",
)
raw_log_path = os.path.join(results_folder, f"oneplus_5g/oneplus_5g_rq3_exp4.log")
print(f"oneplus_5g with log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"oneplus_5g experiments with log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('oneplus_5g', [4])}"
)
print(
    "oneplus_5g with log, mutation only triggers\t",
    count_rq3_expected_unexpected("oneplus_5g", 4),
    "(Expected / Unexpected) bugs",
)
print()

raw_log_path = os.path.join(results_folder, f"simcom_5g/simcom_5g_rq3_exp1.log")
print(f"simcom_5g w/o log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"simcom_5g experiments w/o log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('simcom_5g', [1])}"
)
print(
    "simcom_5g w/o log, mutation only triggers\t",
    count_rq3_expected_unexpected("simcom_5g", 1),
    "(Expected / Unexpected) bugs",
)
print()

raw_log_path = os.path.join(results_folder, f"esp32_wifi/esp32_wifi_rq3_exp1.log")
print(f"esp32_wifi w/o log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"esp32_wifi experiments w/o log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('esp32_wifi', [1,2,3])}"
)
print(
    "esp32_wifi w/o log, mutation only triggers\t",
    count_rq3_expected_unexpected("esp32_wifi", 1),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_wifi w/o log, mutation + replay triggers\t",
    count_rq3_expected_unexpected("esp32_wifi", 2),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_wifi w/o log, all triggers\t\t",
    count_rq3_expected_unexpected("esp32_wifi", 3),
    "(Expected / Unexpected) bugs",
)
raw_log_path = os.path.join(results_folder, f"esp32_wifi/esp32_wifi_rq3_exp4.log")
print(f"esp32_wifi with log has {count_total_unique_bugs(raw_log_path)[1]} unique bugs")
print(
    f"esp32_wifi experiments with log in RQ3 takes a Max. Time of {count_rq3_exps_max_time('esp32_wifi', [4,5,6])}"
)
print(
    "esp32_wifi with log, mutation only triggers\t",
    count_rq3_expected_unexpected("esp32_wifi", 4),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_wifi with log, mutation + replay triggers\t",
    count_rq3_expected_unexpected("esp32_wifi", 5),
    "(Expected / Unexpected) bugs",
)
print(
    "esp32_wifi with log, all triggers\t\t",
    count_rq3_expected_unexpected("esp32_wifi", 6),
    "(Expected / Unexpected) bugs",
)
