. run_utils.sh

clean_running_files
trap clean_running_files EXIT
create_running_file 4

echo "Running RQ4"
source .venv/bin/activate

echo "Running RQ4 on esp32_bt"
cp_esp32_bt_config
mkdir -p eval_results/RQ4/esp32_bt/
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp1 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp1.log 2>&1
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp2 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp2.log 2>&1
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp3 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp3.log 2>&1
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp4 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp4.log 2>&1
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp5 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp5.log 2>&1
python -m eval_scripts.RQ4.esp32_bt.esp32_bt_rq4_exp6 >eval_results/RQ4/esp32_bt/esp32_bt_rq4_exp6.log 2>&1

echo "Running RQ4 on cypress_bt"
cp_cypress_bt_config
mkdir -p eval_results/RQ4/cypress_bt/
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp1 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp1.log 2>&1
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp2 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp2.log 2>&1
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp3 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp3.log 2>&1
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp4 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp4.log 2>&1
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp5 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp5.log 2>&1
python -m eval_scripts.RQ4.cypress_bt.cypress_bt_rq4_exp6 >eval_results/RQ4/cypress_bt/cypress_bt_rq4_exp6.log 2>&1

echo "Running RQ4 on oneplus_5g"
cp_oneplus_5g_config
mkdir -p eval_results/RQ4/oneplus_5g/
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp1 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp1.log 2>&1
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp2 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp2.log 2>&1
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp3 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp3.log 2>&1
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp4 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp4.log 2>&1
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp5 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp5.log 2>&1
python -m eval_scripts.RQ4.oneplus_5g.oneplus_5g_rq4_exp6 >eval_results/RQ4/oneplus_5g/oneplus_5g_rq4_exp6.log 2>&1

echo "Running RQ4 on simcom_5g"
cp_simcom_5g_config
mkdir -p eval_results/RQ4/simcom_5g/
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp1 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp1.log 2>&1
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp2 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp2.log 2>&1
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp3 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp3.log 2>&1
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp4 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp4.log 2>&1
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp5 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp5.log 2>&1
python -m eval_scripts.RQ4.simcom_5g.simcom_5g_rq4_exp6 >eval_results/RQ4/simcom_5g/simcom_5g_rq4_exp6.log 2>&1

echo "Running RQ4 on esp32_wifi"
cp_esp32_wifi_config
mkdir -p eval_results/RQ4/esp32_wifi/
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp1 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp1.log 2>&1
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp2 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp2.log 2>&1
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp3 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp3.log 2>&1
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp4 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp4.log 2>&1
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp5 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp5.log 2>&1
python -m eval_scripts.RQ4.esp32_wifi.esp32_wifi_rq4_exp6 >eval_results/RQ4/esp32_wifi/esp32_wifi_rq4_exp6.log 2>&1

echo "Generating RQ4 statistics"
python -m eval_scripts.analyze_rq4_results eval_results/RQ4
