. run_utils.sh

echo "Running RQ5"
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

python -m eval_scripts.analyze_rq5_results eval_results/RQ5
