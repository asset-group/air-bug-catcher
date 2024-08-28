# AirBugCatcher

AirBugCatcher is a useful tool to automatically and reliably reproduce wireless protocol vulnerabilities, which complements the security testing pipeline. AirBugCatcher is tested on wireless protocols such as Bluetooth Classic, 5G NR and Wi-Fi, and achieves satisfactory results.

# Setup

AirBugCatcher is purely written in Python. While AirBugCatcher is developed using Python 3.12.3 on Ubuntu, it should run smoothly for Python version >= 3.8. A list of Python package dependencies can be found in `requirements.txt`. Furthermore, instructions for environment setup of Bluetooth Classic and Wi-Fi fuzzing is available in [braktooth](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks), while [U-Fuzz](https://github.com/asset-group/U-Fuzz) and [5Ghoul](https://github.com/asset-group/5ghoul-5g-nr-attacks) contains instructions of 5G NR fuzzing. Since AirBugCatcher needs to work with protocol fuzzers that are not included in this repository, please setup the desired environment for protocol fuzzers before proceeding to next step. Note that the fuzzers run on Linux only.

It is a wise choice to put AirBugCatcher code inside the `modules/` folder of WDissector fuzzer (i.e., braktooth) because it needs to invoke some functions inside the binding files of WDissector fuzzer. Following instructions and examples assume that AirBugCatcher code is inside the `modules/` folder. The file structure in `modules/` folder should be similar to:
```plain
modules/
├───python/
├───eval/
├───exploits/
├───libs/
├───server/
├───webview/
└───air-bug-catcher/
```

## Hardware Setup

The setup instructions for both target devices and non-target devices can be found in [braktooth](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks).

## WDissector Symbolic Links 

Packet analysis component in AirBugCatcher takes advantage of WDissector bindings for Python. To make the Python binding work smoothly, some binary and configuration files from WDissector are required to be present in AirBugCatcher folder. Such purpose can be achieved by symbolic links. Instructions to create necessary symbolic files are attached below.
```bash
cd modules/air-bug-catcher/
ln -s ../../bin/ bin
ln -s ../../configs/ configs
ln -s ../../bindings/python/wdissector.py wdissector.py
```

## AirBugCatcher

1. Install required dependencies via `pip install -r requirements.txt`.
2. Change `CAPTURE_CACHE_PATH` and `RUN_LOG_PATH` in file `constants.py` to the appropriate paths in your environment, where `CAPTURE_CACHE_PATH` specifies the location for the cache files of packet analysis component and `RUN_LOG_PATH` store the log files during exploits generation.

# Quick Start

Generally speaking, AirBugCatcher involves two stages:
1. Offline Bug Analysis
2. Over-the-Air Bug Reproduction

## Example Fuzzing Logs

We provide fuzzing logs of 5 evaluated target devices in our experiment inside `example_fuzzing_logs/`. Fuzzing logs of each target device are compressed to `7z` archives separately which can be extracted by `p7zip`. The structure of example fuzzing logs is as follows:
```plain
example_fuzzing_logs/
├───5gnr/                                               >5G NR Devices
|   ├───oneplus.7z                                      *OnePlus Phone Fuzzing Log
|   |   ├───capture_nr5g_gnb.pcapng                         Packet Trace
|   |   └───monitor.combined.txt                            Target Log
|   └───simcom.7z                                       *SIM8202G Fuzzing Log
|       └───capture_nr5g_gnb.pcapng                         Packet Trace
├───bt/                                                 >Bluetooth Classic Devices
|   ├───cypress.7z                                      *Cypress Board Fuzzing Log
|   |   └───capture_bluetooth_cypress_fuzzing.pcapng        Packet Trace
|   └───esp32.7z                                        *ESP32-WROOM-32 Fuzzing Log
|       ├───capture_bluetooth.pcapng                        Packet Trace
|       └───monitor.1.txt                                   Target Log
└───wifi/                                               >Wi-Fi Devices
    └───esp32.7z                                        *ESP-WROVER-KIT Fuzzing Logs
        ├───capture_wifi.pcapng                             Packet Trace
        └───monitor.1.txt                                   Target Log
```

## Run AirBugCatcher

To run AirBugCatcher, three components are needed:
1. Fuzzlog: packet analysis logic, which can be different for different target devices.
2. Exploiter: generate test scenarios and test cases and execute test cases, which can be different for different target devices. 
3. AutoExploiter: Coordinator for running all test cases for a fuzzing log

Consider a script for Bluetooth Classic ESP32-WROOM-32 test device shown below:
```python
from auto_exploiter import AutoExploiter
from exploiter.esp32_bt import ESP32BtExploiter
from fuzzlog.esp32_bt import ESP32BtFuzzLog
from utils import ae_logger, session_id

ae_logger.info("Start AirBugCatcher")

fuzzlog = ESP32BtFuzzLog(
    use_cache=False,
    capture_path="/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/capture_bluetooth.pcapng",
    log_path="/home/user/wdissector/modules/auto-exploiter/captures/new_ref_mut/monitor.1.txt",
    same_crash_thresh=2000,
    enable_group_crashes=True,
)
esp32_bt_exploiter = ESP32BtExploiter(
    fuzzlog=fuzzlog,
    session_id=session_id,
    run_dir="/home/user/wdissector",
    host_port="/dev/ttyUSB10",
    target="fc:f5:c4:26:fa:b6",
    target_port="/dev/ttyESP32-fc",
    target_hub_port=2,
    exploit_timeout=60,
    flooding_exploit_timeout=120,
    timeout_exploit_timeout=120,
)
auto_exploiter = AutoExploiter(
    fuzzlog=fuzzlog,
    exploiter=esp32_bt_exploiter,
    session_id=session_id,
    max_fuzzed_pkts=3,
    min_trial_pkts=6,
    min_trial_iter=3,
    max_trial_time=60 * 60,
    enable_flooding=True,
    enable_duplication=True,
    enable_mutation=True,
)

auto_exploiter.run()
```

Parameters inside `ESP32BtFuzzLog`:
- `use_cache`: if cache files are generated during packet analysis process which can speed up the packet analysis process next time when loading the same fuzzing log.
- `capture_path`: packet trace path
- `log_path`: target log path
- `same_crash_thresh`: backtrace hex value offset
- `enable_group_crashes`: control if bugs need to be grouped

Parameters inside `ESP32BtExploiter`:
- `fuzzlog`: fuzzlog object
- `session_id`: session id
- `run_dir`: the working directory of test cases
- `host_port`: Bluetooth device host board port
- `target`: target MAC address
- `target_port`: Bluetooth target device port
- `target_hub_port`: Bluetooth target device USB hub port
- `exploit_timeout`: crash timeout
- `flooding_exploit_timeout`: flooding timeout
- `timeout_exploit_timeout`: hang timeout

Parameters inside `AutoExploiter`:
- `fuzzlog`: fuzzlog object
- `exploiter`: exploiter object
- `session_id`: session id
- `max_fuzzed_pkts`: maximum number of fuzzed packets in one test case
- `min_trial_pkts`: minimum number of trial packets for selecting fuzzed packets
- `min_trial_iter`: minimum number of trial iterations for selecting fuzzed packets
- `max_trial_time`: maximum trial time for executing one bug group
- `enable_flooding`: whether to generate flooding test cases
- `enable_duplication`: whether to include replayed packets in the test case
- `enable_mutation`: whether to include mutated packets in the test case
