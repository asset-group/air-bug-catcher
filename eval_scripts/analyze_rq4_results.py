import os
import sys

from .utils import count_expected_unexpected

if len(sys.argv) < 2:
    print("Need to specify the RQ4 results folder.")


results_folder = sys.argv[1]


def count_rq4_expected_unexpected(device, exp_index):
    raw_log_path = os.path.join(results_folder, f"{device}/{device}_rq4_exp{exp_index}.log")
    num_expected, num_unexpected = count_expected_unexpected(raw_log_path)

    return f"\t{num_expected} expected bugs and\t{num_unexpected} unexpected bugs."


print("===== RQ4 Statistics =====\n")
print(
    "esp32_bt with Max_fpg=3 and Max_tt=10min triggers",
    count_rq4_expected_unexpected("esp32_bt", 1),
)
print(
    "esp32_bt with Max_fpg=3 and Max_tt=20min triggers",
    count_rq4_expected_unexpected("esp32_bt", 2),
)
print(
    "esp32_bt with Max_fpg=3 and Max_tt=40min triggers",
    count_rq4_expected_unexpected("esp32_bt", 3),
)
print(
    "esp32_bt with Max_fpg=1 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_bt", 4),
)
print(
    "esp32_bt with Max_fpg=2 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_bt", 5),
)
print(
    "esp32_bt with Max_fpg=3 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_bt", 6),
)
print()
print(
    "cypress_bt with Max_fpg=3 and Max_tt=10min triggers",
    count_rq4_expected_unexpected("cypress_bt", 1),
)
print(
    "cypress_bt with Max_fpg=3 and Max_tt=20min triggers",
    count_rq4_expected_unexpected("cypress_bt", 2),
)
print(
    "cypress_bt with Max_fpg=3 and Max_tt=40min triggers",
    count_rq4_expected_unexpected("cypress_bt", 3),
)
print(
    "cypress_bt with Max_fpg=1 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("cypress_bt", 4),
)
print(
    "cypress_bt with Max_fpg=2 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("cypress_bt", 5),
)
print(
    "cypress_bt with Max_fpg=3 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("cypress_bt", 6),
)
print()
print(
    "oneplus_5g with Max_fpg=3 and Max_tt=10min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 1),
)
print(
    "oneplus_5g with Max_fpg=3 and Max_tt=20min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 2),
)
print(
    "oneplus_5g with Max_fpg=3 and Max_tt=40min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 3),
)
print(
    "oneplus_5g with Max_fpg=1 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 4),
)
print(
    "oneplus_5g with Max_fpg=2 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 5),
)
print(
    "oneplus_5g with Max_fpg=3 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("oneplus_5g", 6),
)
print()
print(
    "simcom_5g with Max_fpg=3 and Max_tt=10min triggers",
    count_rq4_expected_unexpected("simcom_5g", 1),
)
print(
    "simcom_5g with Max_fpg=3 and Max_tt=20min triggers",
    count_rq4_expected_unexpected("simcom_5g", 2),
)
print(
    "simcom_5g with Max_fpg=3 and Max_tt=40min triggers",
    count_rq4_expected_unexpected("simcom_5g", 3),
)
print(
    "simcom_5g with Max_fpg=1 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("simcom_5g", 4),
)
print(
    "simcom_5g with Max_fpg=2 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("simcom_5g", 5),
)
print(
    "simcom_5g with Max_fpg=3 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("simcom_5g", 6),
)
print()
print(
    "esp32_wifi with Max_fpg=3 and Max_tt=10min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 1),
)
print(
    "esp32_wifi with Max_fpg=3 and Max_tt=20min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 2),
)
print(
    "esp32_wifi with Max_fpg=3 and Max_tt=40min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 3),
)
print(
    "esp32_wifi with Max_fpg=1 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 4),
)
print(
    "esp32_wifi with Max_fpg=2 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 5),
)
print(
    "esp32_wifi with Max_fpg=3 and Max_tt=60min triggers",
    count_rq4_expected_unexpected("esp32_wifi", 6),
)
print()
