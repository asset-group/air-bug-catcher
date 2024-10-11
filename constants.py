import os

CAPTURE_CACHE_PATH = "/home/user/wdissector/modules/airbugcatcher/cache"
RUN_LOG_PATH = "/home/user/wdissector/modules/airbugcatcher/logs"
UHUBCTL_PATH = "/home/user/wdissector/3rd-party/uhubctl/uhubctls"

# WDissector configurations path
BT_WD_SM_CONFIG = "/home/user/wdissector/configs/bt_config.json"
BT_WD_MODEL_CONFIG = "/home/user/wdissector/configs/models/bt/sdp_rfcomm_query.json"
FIVEG_WD_SM_CONFIG = "/home/user/wdissector/configs/5gnr_gnb_config.json"
FIVEG_WD_MODEL_CONFIG = "/home/user/wdissector/configs/models/5gnr_gnb/nr-softmodem.json"
WIFI_WD_SM_CONFIG = "/home/user/wdissector/configs/wifi_ap_config.json"
WIFI_WD_MODEL_CONFIG = "/home/user/wdissector/configs/models/wifi_ap/wpa2_eap.json"

os.makedirs(CAPTURE_CACHE_PATH, exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/5gnr_gnb", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/bt", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/wifi", exist_ok=True)
