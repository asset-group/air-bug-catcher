echo "Running RQ5"

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

source .venv/bin/activate

cp_esp32_bt_config
mkdir -p eval_results/RQ5/esp32_bt/
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_5.log 2>&1

cp_cypress_bt_config
mkdir -p eval_results/RQ5/cypress_bt/
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_5.log 2>&1

cp_oneplus_5g_config
mkdir -p eval_results/RQ5/oneplus_5g/
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_5.log 2>&1

cp_simcom_5g_config
mkdir -p eval_results/RQ5/simcom_5g/
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_5.log 2>&1

cp_esp32_wifi_config
mkdir -p eval_results/RQ5/esp32_wifi/
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_5.log 2>&1
