import os

CAPTURE_CACHE_PATH = "/home/user/wdissector/modules/airbugcatcher/cache"
RUN_LOG_PATH = "/home/user/wdissector/modules/airbugcatcher/logs"


os.makedirs(CAPTURE_CACHE_PATH, exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/5gnr_gnb", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/bt", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/wifi", exist_ok=True)
