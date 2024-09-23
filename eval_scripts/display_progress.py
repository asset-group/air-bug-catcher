import os
import re
import time

from alive_progress import alive_bar

base_folder = os.getcwd()


def get_running_rq() -> int:
    for root, dirs, files in os.walk(base_folder):
        for file in files:
            if file.endswith(".running"):
                if (s := re.search(r"\d+", file)) is not None:
                    return int(s[0])
                else:
                    return 0
        break

    return 0


current_rq = get_running_rq()
if current_rq == 0:
    print("Currently there is no RQ experiment running.")
    exit()

current_rq_logs_dir = f"{base_folder}/eval_results/RQ{current_rq}"

log_paths = {
    "RQ1": [
        "esp32_bt/esp32_bt_rq1.log",
        "cypress_bt/cypress_bt_rq1.log",
        "oneplus_5g/oneplus_5g_rq1.log",
        "simcom_5g/simcom_5g_rq1.log",
        "esp32_wifi/esp32_wifi_rq1.log",
    ],
    "RQ2": [],
    "RQ3": [
        "esp32_bt/esp32_bt_rq3_exp1.log",
        "esp32_bt/esp32_bt_rq3_exp2.log",
        "esp32_bt/esp32_bt_rq3_exp3.log",
        "esp32_bt/esp32_bt_rq3_exp4.log",
        "esp32_bt/esp32_bt_rq3_exp5.log",
        "esp32_bt/esp32_bt_rq3_exp6.log",
        "cypress_bt/cypress_bt_rq3_exp1.log",
        "cypress_bt/cypress_bt_rq3_exp2.log",
        "cypress_bt/cypress_bt_rq3_exp3.log",
        "oneplus_5g/oneplus_5g_rq3_exp1.log",
        "oneplus_5g/oneplus_5g_rq3_exp4.log",
        "simcom_5g/simcom_5g_rq3_exp1.log",
        "esp32_wifi/esp32_wifi_rq3_exp1.log",
        "esp32_wifi/esp32_wifi_rq3_exp2.log",
        "esp32_wifi/esp32_wifi_rq3_exp3.log",
        "esp32_wifi/esp32_wifi_rq3_exp4.log",
        "esp32_wifi/esp32_wifi_rq3_exp5.log",
        "esp32_wifi/esp32_wifi_rq3_exp6.log",
    ],
    "RQ4": [
        "esp32_bt/esp32_bt_rq4_exp1.log",
        "esp32_bt/esp32_bt_rq4_exp2.log",
        "esp32_bt/esp32_bt_rq4_exp3.log",
        "esp32_bt/esp32_bt_rq4_exp4.log",
        "esp32_bt/esp32_bt_rq4_exp5.log",
        "esp32_bt/esp32_bt_rq4_exp6.log",
        "cypress_bt/cypress_bt_rq4_exp1.log",
        "cypress_bt/cypress_bt_rq4_exp2.log",
        "cypress_bt/cypress_bt_rq4_exp3.log",
        "cypress_bt/cypress_bt_rq4_exp4.log",
        "cypress_bt/cypress_bt_rq4_exp5.log",
        "cypress_bt/cypress_bt_rq4_exp6.log",
        "oneplus_5g/oneplus_5g_rq4_exp1.log",
        "oneplus_5g/oneplus_5g_rq4_exp2.log",
        "oneplus_5g/oneplus_5g_rq4_exp3.log",
        "oneplus_5g/oneplus_5g_rq4_exp4.log",
        "oneplus_5g/oneplus_5g_rq4_exp5.log",
        "oneplus_5g/oneplus_5g_rq4_exp6.log",
        "simcom_5g/simcom_5g_rq4_exp1.log",
        "simcom_5g/simcom_5g_rq4_exp2.log",
        "simcom_5g/simcom_5g_rq4_exp3.log",
        "simcom_5g/simcom_5g_rq4_exp4.log",
        "simcom_5g/simcom_5g_rq4_exp5.log",
        "simcom_5g/simcom_5g_rq4_exp6.log",
        "esp32_wifi/esp32_wifi_rq4_exp1.log",
        "esp32_wifi/esp32_wifi_rq4_exp2.log",
        "esp32_wifi/esp32_wifi_rq4_exp3.log",
        "esp32_wifi/esp32_wifi_rq4_exp4.log",
        "esp32_wifi/esp32_wifi_rq4_exp5.log",
        "esp32_wifi/esp32_wifi_rq4_exp6.log",
    ],
    "RQ5": [
        "esp32_bt/esp32_bt_bl_trial_1.log",
        "esp32_bt/esp32_bt_bl_trial_2.log",
        "esp32_bt/esp32_bt_bl_trial_3.log",
        "esp32_bt/esp32_bt_bl_trial_4.log",
        "esp32_bt/esp32_bt_bl_trial_5.log",
        "cypress_bt/cypress_bt_bl_trial_1.log",
        "cypress_bt/cypress_bt_bl_trial_2.log",
        "cypress_bt/cypress_bt_bl_trial_3.log",
        "cypress_bt/cypress_bt_bl_trial_4.log",
        "cypress_bt/cypress_bt_bl_trial_5.log",
        "oneplus_5g/oneplus_5g_bl_trial_1.log",
        "oneplus_5g/oneplus_5g_bl_trial_2.log",
        "oneplus_5g/oneplus_5g_bl_trial_3.log",
        "oneplus_5g/oneplus_5g_bl_trial_4.log",
        "oneplus_5g/oneplus_5g_bl_trial_5.log",
        "simcom_5g/simcom_5g_bl_trial_1.log",
        "simcom_5g/simcom_5g_bl_trial_2.log",
        "simcom_5g/simcom_5g_bl_trial_3.log",
        "simcom_5g/simcom_5g_bl_trial_4.log",
        "simcom_5g/simcom_5g_bl_trial_5.log",
        "esp32_wifi/esp32_wifi_bl_trial_1.log",
        "esp32_wifi/esp32_wifi_bl_trial_2.log",
        "esp32_wifi/esp32_wifi_bl_trial_3.log",
        "esp32_wifi/esp32_wifi_bl_trial_4.log",
        "esp32_wifi/esp32_wifi_bl_trial_5.log",
    ],
}

bl_num_exploits = {
    "esp32_bt": 190,
    "cypress_bt": 12,
    "oneplus_5g": 30,
    "simcom_5g": 5,
    "esp32_wifi": 5,
}


def log_reader(log_path):
    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        while True:
            line = f.readline()
            if line == "":
                time.sleep(0.5)
                continue

            yield line


def read_log_progress_rq1_rq4(log_path):
    num_unique = 0
    running_bug_index = -1
    bug_start_time = 0

    progress = 0
    for line in log_reader(log_path):
        if num_unique == 0 and "are unique" in line:
            m = re.findall(r"\d+", line)
            num_unique = int(m[1])
        elif num_unique == 0:
            yield 0
            continue

        if "Auto exploit for" in line:
            running_bug_index += 1
            bug_start_time = time.time()
        elif "Total time" in line:
            yield 1
            return

        if running_bug_index >= 0:
            progress = (
                running_bug_index
                + (time.time() - bug_start_time) / 60 * 60  # TODO: change back to 60*60
            ) / num_unique
            progress = min(1, progress)

        yield progress


def read_log_progress_rq5(log_path):
    device = "_".join(os.path.split(log_path)[1].split("_")[:2])
    total_exploits = bl_num_exploits[device]
    executed_exploits = set()
    for line in log_reader(log_path):
        if "Running command:" in line:
            executed_exploits.add(re.findall(r'--exploit=(.*?)"', line)[0])

        if len(executed_exploits) == total_exploits:
            yield 1
            return

        yield len(executed_exploits) / total_exploits


def read_log_progress(log_path):
    if "RQ5" in log_path:
        g = read_log_progress_rq5(log_path)
    else:
        g = read_log_progress_rq1_rq4(log_path)
    for p in g:
        yield p


with alive_bar(
    manual=True,
    stats="  End in {eta}",
    dual_line=True,
    title=f"RQ{current_rq} experiment progress",
) as bar:
    num_logs = len(log_paths[f"RQ{current_rq}"])
    for idx, log_rel_path in enumerate(log_paths[f"RQ{current_rq}"]):
        log_path = os.path.join(current_rq_logs_dir, log_rel_path)
        bar.text = f"Current running sub-experiment: {os.path.split(log_rel_path)[1].replace('.log', '')}, progress {idx+1}/{num_logs}"
        for p in read_log_progress(log_path):
            bar((idx + p) / num_logs)
