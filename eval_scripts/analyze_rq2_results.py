import datetime
import os
import re
import sys

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

if len(sys.argv) < 2:
    print(
        "Need to specify the RQ2 results folder. Note that RQ2 statistics can be derived from RQ1 results, so the folder can be RQ1 results folder."
    )


results_folder = sys.argv[1]


def count_expected_bug_trigger_times(device):
    raw_log_path = os.path.join(results_folder, f"{device}/{device}_rq1.log")
    with open(raw_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "log is saved in" in line:
                abc_log_name = re.findall(r"/[^/]*?\.log", line)[0]
                abc_log_path = os.path.join(results_folder, f"{device}{abc_log_name}")
                break

    trigger_times = []
    with open(abc_log_path, "r", encoding="utf8", errors="ignore") as f:
        exp_start_time = 0
        for line in f:
            if "Auto exploit for" in line:
                exp_start_time = datetime.datetime.strptime(
                    line[:23], "%Y-%m-%d %H:%M:%S,%f"
                ).timestamp()
            elif "Same crash found for" in line:
                current_time = datetime.datetime.strptime(
                    line[:23], "%Y-%m-%d %H:%M:%S,%f"
                ).timestamp()
                trigger_times.append(current_time - exp_start_time)

    return trigger_times


plot_data = []
for device in ["esp32_bt", "cypress_bt", "oneplus_5g", "simcom_5g", "esp32_wifi"]:
    temp = [
        [0, device, 1],
        [0, device, 2],
        [0, device, 3],
        [0, device, 4],
    ]
    device_times = count_expected_bug_trigger_times(device)
    for t in device_times:
        if t < 120:
            temp[0][0] += 1
        elif t < 240:
            temp[1][0] += 1
        elif t < 1800:
            temp[2][0] += 1
        else:
            temp[3][0] += 1

    plot_data += temp
df = pd.DataFrame(plot_data)

plt.rcParams.update({"font.size": 10})
plt.rc("pdf", fonttype=42)

df.columns = ["count", "Device", "index"]
ax = sns.barplot(
    df,
    x="index",
    y="count",
    hue="Device",
    linewidth=1.2,
    saturation=1.0,
)
ax.set_xticks([0, 1, 2, 3])
ax.set_xticklabels(["0-2", "2-4", "4-30", "30-60"])
ax.set_xlabel("Reproduction Time of Expected Bugs (minutes)")
ax.set_ylabel("Bug Count")
ax.bar_label(ax.containers[0], fmt=lambda x: str(int(x)) if x > 0 else "")
ax.bar_label(ax.containers[1], fmt=lambda x: str(int(x)) if x > 0 else "")
ax.bar_label(ax.containers[2], fmt=lambda x: str(int(x)) if x > 0 else "")
ax.bar_label(ax.containers[3], fmt=lambda x: str(int(x)) if x > 0 else "")
ax.bar_label(ax.containers[4], fmt=lambda x: str(int(x)) if x > 0 else "")

rq2_figure_path = os.path.join(results_folder, "rq2_figure.pdf")
plt.savefig(rq2_figure_path)

print("===== RQ2 Statistics =====")
print(f"The figure for RQ2 is saved in {rq2_figure_path}, you can download via SFTP.\n")
