import os
import sys

if len(sys.argv) < 2:
    print("Need to specify the RQ5 results folder.")


results_folder = sys.argv[1]

print("===== RQ5 Statistics =====\n")
for device in ["esp32_bt", "cypress_bt", "oneplus_5g", "simcom_5g", "esp32_wifi"]:
    for trial in range(1, 6):
        raw_log_path = os.path.join(
            results_folder, f"{device}/{device}_bl_trial_{trial}.log"
        )
        num_crash = 0
        with open(raw_log_path, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                if "Comment: [Crash]" in line:
                    num_crash += 1

        print(f"Device {device} triggers {num_crash} bugs in RQ5 trial {trial}.")

    print("")
