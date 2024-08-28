. run_utils.sh

echo "Running RQ1"
source .venv/bin/activate

echo "Running RQ1 on esp32_bt"
cp_esp32_bt_config
mkdir -p eval_results/RQ1/esp32_bt/
python -m eval_scripts.RQ1.esp32_bt.esp32_bt_rq1 >eval_results/RQ1/esp32_bt/esp32_bt_rq1.log 2>&1

echo "Running RQ1 on cypress_bt"
cp_cypress_bt_config
mkdir -p eval_results/RQ1/cypress_bt/
python -m eval_scripts.RQ1.cypress_bt.cypress_bt_rq1 >eval_results/RQ1/cypress_bt/cypress_bt_rq1.log 2>&1

echo "Running RQ1 on oneplus_5g"
cp_oneplus_5g_config
mkdir -p eval_results/RQ1/oneplus_5g/
python -m eval_scripts.RQ1.oneplus_5g.oneplus_5g_rq1 >eval_results/RQ1/oneplus_5g/oneplus_5g_rq1.log 2>&1

echo "Running RQ1 on simcom_5g"
cp_simcom_5g_config
mkdir -p eval_results/RQ1/simcom_5g/
python -m eval_scripts.RQ1.simcom_5g.simcom_5g_rq1 >eval_results/RQ1/simcom_5g/simcom_5g_rq1.log 2>&1

echo "Running RQ1 on esp32_wifi"
cp_esp32_wifi_config
mkdir -p eval_results/RQ1/esp32_wifi/
python -m eval_scripts.RQ1.esp32_wifi.esp32_wifi_rq1 >eval_results/RQ1/esp32_wifi/esp32_wifi_rq1.log 2>&1

echo "Generating RQ1 statistics"
python -m eval_scripts.analyze_rq1_results eval_results/RQ1
