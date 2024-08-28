. run_utils.sh

echo "Running RQ3"
source .venv/bin/activate

cp_esp32_bt_config
mkdir -p eval_results/RQ3/esp32_bt/
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp1 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp1.log 2>&1
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp2 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp2.log 2>&1
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp3 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp3.log 2>&1
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp4 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp4.log 2>&1
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp5 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp5.log 2>&1
python -m eval_scripts.RQ3.esp32_bt.esp32_bt_rq3_exp6 >eval_results/RQ3/esp32_bt/esp32_bt_rq3_exp6.log 2>&1

cp_cypress_bt_config
mkdir -p eval_results/RQ3/cypress_bt/
python -m eval_scripts.RQ3.cypress_bt.cypress_bt_rq3_exp1 >eval_results/RQ3/cypress_bt/cypress_bt_rq3_exp1.log 2>&1
python -m eval_scripts.RQ3.cypress_bt.cypress_bt_rq3_exp2 >eval_results/RQ3/cypress_bt/cypress_bt_rq3_exp2.log 2>&1
python -m eval_scripts.RQ3.cypress_bt.cypress_bt_rq3_exp3 >eval_results/RQ3/cypress_bt/cypress_bt_rq3_exp3.log 2>&1

cp_oneplus_5g_config
mkdir -p eval_results/RQ3/oneplus_5g/
python -m eval_scripts.RQ3.oneplus_5g.oneplus_5g_rq3_exp1 >eval_results/RQ3/oneplus_5g/oneplus_5g_rq3_exp1.log 2>&1
python -m eval_scripts.RQ3.oneplus_5g.oneplus_5g_rq3_exp4 >eval_results/RQ3/oneplus_5g/oneplus_5g_rq3_exp4.log 2>&1

cp_simcom_5g_config
mkdir -p eval_results/RQ3/simcom_5g/
python -m eval_scripts.RQ3.simcom_5g.simcom_5g_rq3_exp1 >eval_results/RQ3/simcom_5g/simcom_5g_rq3_exp1.log 2>&1

cp_esp32_wifi_config
mkdir -p eval_results/RQ3/esp32_wifi/
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp1 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp1.log 2>&1
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp2 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp2.log 2>&1
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp3 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp3.log 2>&1
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp4 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp4.log 2>&1
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp5 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp5.log 2>&1
python -m eval_scripts.RQ3.esp32_wifi.esp32_wifi_rq3_exp6 >eval_results/RQ3/esp32_wifi/esp32_wifi_rq3_exp6.log 2>&1

python -m eval_scripts.analyze_rq3_results eval_results/RQ3
