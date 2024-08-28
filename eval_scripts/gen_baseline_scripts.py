import os


def gen(baseline_data_dir, protocol, device):
    tp_path = ""
    script_name_prefix = ""
    script_folder = ""
    if protocol == "bt":
        tp_path = "/home/user/wdissector/modules/airbugcatcher/exploit_templates/baseline_bt.template"
        script_name_prefix = f"bl_exp_{device}"
        script_folder = "/home/user/wdissector/modules/exploits/bluetooth/"
    elif protocol == "5g":
        tp_path = "/home/user/wdissector/modules/airbugcatcher/exploit_templates/baseline_5g.template"
        script_name_prefix = f"mac_sch_bl_exp_{device}"
        script_folder = "/home/user/wdissector/modules/exploits/5gnr_gnb/"
    elif protocol == "wifi":
        tp_path = "/home/user/wdissector/modules/airbugcatcher/exploit_templates/baseline_wifi.template"
        script_name_prefix = f"bl_exp_{device}"
        script_folder = "/home/user/wdissector/modules/exploits/wifi_ap/"
    else:
        print(f"Unsupported protocol: {protocol}.")
        exit(-1)
    baseline_exploit_script = open(tp_path, "r", encoding="utf8").read()

    for root, dirs, files in os.walk(baseline_data_dir):
        for file in files:
            pref = file.replace("baseline_data_", "").replace(".bin", "")
            path = os.path.join(root, file)

        with open(
            os.path.join(script_folder, f"{script_name_prefix}_{pref}.cpp"),
            "w",
            encoding="utf8",
        ) as f:
            f.write(baseline_exploit_script.replace("<baseline_data_path>", path))


if __name__ == "__main__":
    gen(
        "/home/user/wdissector/modules/airbugcatcher/captures/esp32_bt/baseline_data/",
        "bt",
        "esp32_bt",
    )
    gen(
        "/home/user/wdissector/modules/airbugcatcher/captures/cypress_bt/baseline_data/",
        "bt",
        "cypress_bt",
    )
    gen(
        "/home/user/wdissector/modules/airbugcatcher/captures/oneplus_5g/baseline_data/",
        "5g",
        "oneplus_5g",
    )
    gen(
        "/home/user/wdissector/modules/airbugcatcher/captures/simcom_5g/baseline_data/",
        "5g",
        "simcom_5g",
    )
    gen(
        "/home/user/wdissector/modules/airbugcatcher/captures/esp32_wifi/baseline_data/",
        "wifi",
        "esp32_wifi",
    )
