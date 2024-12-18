import os
import re


def convert_friendly_time(t) -> str:
    if t >= 3600:
        return f"{t//3600:.0f} hr {t%3600/60:>02.0f} min"
    return f"{t/60} min"


def count_expected_unexpected(log_path):
    # The raw log from running the script, not the dedicated log for AirBugCatcher
    num_expected = 0
    num_not_reproduced = 0
    num_total = 0

    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "Auto exploit for" in line:
                num_total += 1
            elif "Same crash found for" in line:
                num_expected += 1
            elif "No crash ever" in line:
                num_not_reproduced += 1

    return num_expected, num_total - num_expected - num_not_reproduced


def count_total_unique_bugs(log_path) -> tuple[int, int]:
    # Return the number of total and unique bugs
    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if line.startswith("Total"):
                m = re.findall(r"\d+", line)
                return int(m[0]), int(m[1])

    return 0, 0


def count_total_exp_time(log_path) -> int:
    # Return time in seconds
    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "Total time" in line:
                m = re.findall(r"\d+\.\d+", line)
                return int(float(m[0]))
    return 0


def count_total_exp_time_friendly(log_path) -> str:
    t = count_total_exp_time(log_path)
    return convert_friendly_time(t)


def get_abc_log_path(raw_log_path) -> str:
    base_path = os.path.dirname(raw_log_path)
    with open(raw_log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            if "log is saved in" in line:
                abc_log_name = re.findall(r"/[^/]*?\.log", line)[0].replace(os.sep, "")
                abc_log_path = os.path.join(base_path, abc_log_name)
                if os.path.exists(abc_log_path):
                    return abc_log_path

                abc_log_path = re.findall(r"/.*\.log", line)[0]
                return abc_log_path
