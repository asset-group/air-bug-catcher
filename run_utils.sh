function cp_esp32_bt_config() {
    cp eval_scripts/wdissector_configs/esp32_bt/global_config.json /home/user/wdissector/configs/global_config.json
    cp eval_scripts/wdissector_configs/esp32_bt/bt_config.json /home/user/wdissector/configs/bt_config.json
}

function cp_cypress_bt_config() {
    cp eval_scripts/wdissector_configs/cypress_bt/global_config.json /home/user/wdissector/configs/global_config.json
    cp eval_scripts/wdissector_configs/cypress_bt/bt_config.json /home/user/wdissector/configs/bt_config.json
}

function cp_oneplus_5g_config() {
    cp eval_scripts/wdissector_configs/oneplus_5g/global_config.json /home/user/wdissector/configs/global_config.json
    cp eval_scripts/wdissector_configs/oneplus_5g/5gnr_gnb_config.json /home/user/wdissector/configs/5gnr_gnb_config.json
}

function cp_simcom_5g_config() {
    cp eval_scripts/wdissector_configs/simcom_5g/global_config.json /home/user/wdissector/configs/global_config.json
    cp eval_scripts/wdissector_configs/simcom_5g/5gnr_gnb_config.json /home/user/wdissector/configs/5gnr_gnb_config.json
}

function cp_esp32_wifi_config() {
    cp eval_scripts/wdissector_configs/esp32_wifi/global_config.json /home/user/wdissector/configs/global_config.json
    cp eval_scripts/wdissector_configs/esp32_wifi/wifi_ap_config.json /home/user/wdissector/configs/wifi_ap_config.json
}
