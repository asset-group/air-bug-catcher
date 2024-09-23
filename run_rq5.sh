. run_utils.sh

clean_running_files
trap clean_running_files EXIT
create_running_file 5

echo "Running RQ5"
source .venv/bin/activate

echo "Running RQ5 on esp32_bt"
cp_esp32_bt_config
mkdir -p eval_results/RQ5/esp32_bt/
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.esp32_bt.esp32_bt_rq5 >eval_results/RQ5/esp32_bt/esp32_bt_bl_trial_5.log 2>&1

echo "Running RQ5 on cypress_bt"
cp_cypress_bt_config
mkdir -p eval_results/RQ5/cypress_bt/
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.cypress_bt.cypress_bt_rq5 >eval_results/RQ5/cypress_bt/cypress_bt_bl_trial_5.log 2>&1

echo "Running RQ5 on oneplus_5g"
cp_oneplus_5g_config
mkdir -p eval_results/RQ5/oneplus_5g/
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.oneplus_5g.oneplus_5g_rq5 >eval_results/RQ5/oneplus_5g/oneplus_5g_bl_trial_5.log 2>&1

echo "Running RQ5 on simcom_5g"
cp_simcom_5g_config
mkdir -p eval_results/RQ5/simcom_5g/
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.simcom_5g.simcom_5g_rq5 >eval_results/RQ5/simcom_5g/simcom_5g_bl_trial_5.log 2>&1

echo "Running RQ5 on esp32_wifi"
cp_esp32_wifi_config
mkdir -p eval_results/RQ5/esp32_wifi/
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_1.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_2.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_3.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_4.log 2>&1
python -m eval_scripts.RQ5.esp32_wifi.esp32_wifi_rq5 >eval_results/RQ5/esp32_wifi/esp32_wifi_bl_trial_5.log 2>&1

echo "Generating RQ5 statistics"
python -m eval_scripts.analyze_rq5_results eval_results/RQ5
