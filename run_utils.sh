# The functions inside this file shall only be executed inside `/home/user/wdissector/modules/airbugcatcher`
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

function clean_running_files() {
    rm -f run_rq1.running
    rm -f run_rq2.running
    rm -f run_rq3.running
    rm -f run_rq4.running
    rm -f run_rq5.running
}

function create_running_file() {
    touch "run_rq$1.running"
}
