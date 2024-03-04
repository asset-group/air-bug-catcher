import hashlib
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from pcapng.exceptions import TruncatedFile

from wdissector import (
    WD_DIR_RX,
    WD_DIR_TX,
    WD_MODE_FULL,
    Machine,
    WDPacketLabelGenerator,
    packet_read_field_abbrev,
    wd_packet_dissect,
    wd_pkt_label,
    wd_read_field_by_offset,
    wd_set_dissection_mode,
    wd_set_packet_direction,
)


def init_logger():
    # TODO: this function needs to be prevented from being called multiple times
    logger = logging.getLogger("auto-exploiter")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    filehandler = logging.FileHandler("auto-exploiter.log", mode="w", encoding="utf8")
    filehandler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s:%(lineno)d - %(message)s"
        )
    )
    logger.addHandler(filehandler)
    return logger


logger = init_logger()


class WDCrash(Exception):
    pass


class WDExploitTimeout(Exception):
    pass


class WDModemTimeout(Exception):
    pass


class WDExploitCompileError(Exception):
    pass


class WDGuruLogSeen(Exception):
    pass


def calc_bytes_sha256(b: bytes):
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(b)

    return hash_sha256.hexdigest()


def calc_file_sha256(file_path: str, chunk_size: int = 4096):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if len(chunk) == 0:
                break
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()


def pcap_packet_reader(path: str):
    # Return a generator to yield EnhancedPacket and its index in the capture
    # (index, EnhancedPacket)
    with open(path, "rb") as f:
        scanner = FileScanner(f)
        packet_index = 0  # this is the packet number in Wireshark
        try:
            for block in scanner:
                if not isinstance(block, EnhancedPacket):
                    continue
                packet_index += 1
                yield packet_index, block
        except TruncatedFile:
            logger.info(
                f"The capture file {path} is truncated. This is normal when Wireshark writes the capture file and does not mean the capture file is broken."
            )
        except Exception:
            logger.error(
                f"Processing capture file: {path} at packet: {packet_index}, packet data: {block.data}.",
                exc_info=True,
            )


def monitor_log(log_path, modem_timeout, exploit_timeout):
    # 1. wait for modem to start until modem_timeout
    # 2. after modem starts, wait until crash or exploit timeout
    # TODO: generate all scripts and compile in the beginning
    # TODO: optimize read logic, no need modem retry
    # TODO: this is for ESP32 bluetooth only
    def custom_readline(log_fd):
        line = log_fd.readline()
        if "Error when loading or compiling C Modules" in line:
            raise WDExploitCompileError
        return line

    with open(log_path, "r", encoding="utf8", errors="ignore") as log:
        # Sometimes modem initiates slowly
        # print("Starting modem...")
        # start = time.time()
        # modem_initialized = False
        # while not modem_initialized:
        #     if time.time() - start > modem_timeout:
        #         raise WDModemTimeout

        #     # Read log file line by line continuously, like tail -f but less instantaneously
        #     line = custom_readline(log)
        #     while line != "":
        #         # when using Qualcomm: [ModemManager] Modem Initialized
        #         # when using ADB: [ModemManager] Modem Configured
        #         if '[ModemManager] Modem Initialized' in line or '[ModemManager] Modem Configured' in line:
        #             modem_initialized = True
        #             break
        #         line = custom_readline(log)
        # time.sleep(1)

        # If the crash does not happen within some timeframe, the exploit can unlikely trigger a crash
        print("Running exploit...")
        start = time.time()
        while True:
            if time.time() - start > exploit_timeout:
                raise WDExploitTimeout

            line = custom_readline(log)
            while line != "":
                if "[Crash]" in line:
                    print(line)
                    # raise WDCrash
                if "Guru Meditation Error" in line:
                    raise WDGuruLogSeen
                line = custom_readline(log)
            time.sleep(1)


def clean_up(exploit_name, temp_log_path):
    # As the exploit is run with `script` command and the exploit script itself will spawn other
    # processes, there might be some orphan processes left. These processes might still take up
    # resources like CPU or modem. The script process will still be there also, so need to clean up.

    # find the process ID of the following commands and kill them
    #   `script /tmp/tmp1edlcn4x --flush` or
    #   `sudo bin/lte_fuzzer --exploit=mac_sch_auto_fuzz_exploit_8263 --EnableSimulator=false`
    pids = (
        subprocess.check_output(["pgrep", "-f", f"{exploit_name}|{temp_log_path}"])
        .decode()
        .strip()
        .split("\n")
    )
    pids = [int(pid) for pid in pids]
    for pid in pids:
        try:
            os.kill(pid, 9)
        except:
            pass


def clear_logcat():
    # If running exploit with devices connected using adb, need to clear log
    subprocess.check_output(
        ["/home/user/wdissector/3rd-party/adb/adb", "shell", "logcat", "-c"]
    )


def run_exploit(
    exploit_name: str,
    modem_timeout: int,
    exploit_timeout: int,
    exploit_running_dir: str,
    host_port: str,
    target: str,
    target_port: str,
    target_hub_port: int,
    log_path=None,
):
    # Run the specified exploit.
    #
    # The exploit is run with command `sudo bin/lte_fuzzer --exploit=some_exploit --EnableSimulator=false`
    # by spawning a new process using `subprocess`.
    #
    # Note:
    #   It is not trivial or easy to get the output of the command as there is no existing IPC method.
    #   Python needs to get the output of the command, ideally in real time, to check if the exploit
    #   runs correctly or any crash happens. By using `subprocess.run` or `subprocess.check_output`,
    #   Python cannot get the full output, possibly because some output is from another processes spawned
    #   by the fuzzer command. The initial solution was to redirect all output to a file using `>` which
    #   works well except that the output is only available in Python after process finishes or times out.
    #   This issue is related to disk write buffer. To get the output in real time, we can utilize `script`
    #   command with `--flush` parameter so that the file is flushed on every write.

    #   More about timeout in process invoking:
    #   https://alexandra-zaharia.github.io/posts/kill-subprocess-and-its-children-on-timeout-python/

    prev_dir = os.getcwd()  # save current directory so that can switch back later
    os.chdir(exploit_running_dir)
    max_retry = 3
    for num_retried in range(max_retry):
        # restart target device before running exploits
        subprocess.run(
            f"/home/user/wdissector/3rd-party/uhubctl/uhubctls -a cycle -p {target_hub_port}",
            shell=True,
            stdout=subprocess.PIPE,
        )
        time.sleep(2.5)

        try:
            # clear_logcat() # TODO: this is for 5G only
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.close()
            # need to run the exploit in the same process group of `script` command, check https://unix.stackexchange.com/a/670123
            """
            1. `fc:f5:c4:26:fa:b6` ESP32
            2. `24:0a:c4:61:1c:1a` ESP32
            3. `20:73:5b:18:6c:f2` cypress device
            """
            cmd = f'echo "set +m && sudo bin/bt_fuzzer --no-gui --host-port {host_port} --target-port {target_port} --target {target} --exploit={exploit_name}" | script {temp_file.name} --flush'
            logger.info(f"Running command: '{cmd}'")
            p = subprocess.Popen(cmd, start_new_session=True, shell=True)
            monitor_log(temp_file.name, modem_timeout, exploit_timeout)
        except WDCrash:
            print("Crash found for exploit:", exploit_name)
            # raise WDCrash, need to wait until guru log, see the next except
        except WDGuruLogSeen:
            """
            [2022-06-23 03:38:48.000314] Guru Meditation Error: Core  0 panic'ed (Interrupt wdt timeout on CPU0).
            [2022-06-23 03:38:48.000362]
            [2022-06-23 03:38:48.000373] Core  0 register dump:
            [2022-06-23 03:38:48.000381] PC      : 0x40082dd2  PS      : 0x00060134  A0      : 0x800fd750  A1      : 0x3ffcc4f0
            [2022-06-23 03:38:48.000389] A2      : 0x00000001  A3      : 0x00000000  A4      : 0x0000f2f2  A5      : 0x60008054
            [2022-06-23 03:38:48.000396] A6      : 0x3ffbdc20  A7      : 0x60008050  A8      : 0x80082dcd  A9      : 0x3ffcc4d0
            [2022-06-23 03:38:48.000404] A10     : 0x00000004  A11     : 0x00000000  A12     : 0x6000804c  A13     : 0xffffffff
            [2022-06-23 03:38:48.000411] A14     : 0x00000000  A15     : 0xfffffffc  SAR     : 0x00000004  EXCCAUSE: 0x00000005
            [2022-06-23 03:38:48.000418] EXCVADDR: 0x00000000  LBEG    : 0x40082d05  LEND    : 0x40082d0c  LCOUNT  : 0x00000000
            """
            # wait until all logs are printed
            time.sleep(2)
            break
        except WDModemTimeout:
            print("Modem timeout")
            num_retried += 1
        except WDExploitTimeout:
            print("Exploit timeout")
            break
        except KeyboardInterrupt:
            print("Keyboard interrupt")
            break
        except WDExploitCompileError:
            print("Compile error")
            num_retried += 1
        finally:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            clean_up(exploit_name, temp_file.name)
    else:
        logger.error(f"Exploit {exploit_name} fails to run after {max_retry} retries.")
    os.chdir(prev_dir)
    output = open(temp_file.name, "r", encoding="utf8", errors="ignore").read()
    if log_path is not None:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        shutil.copyfile(temp_file.name, log_path)
    os.unlink(temp_file.name)  # TODO: why use temp file?

    return output


def restart_modem():
    # TODO check correct port to power cycle, possibly do by call uhubctl first, extract port number from output
    output = subprocess.check_output(
        ["/home/user/wdissector/3rd-party/uhubctl/uhubctls", "-a", "cycle", "-p", "2"]
    )
    time.sleep(8)


print("\n\n--------------------- State Machine ---------------------")
StateMachine = Machine()
ret = StateMachine.init(
    "/home/user/wdissector/configs/bt_config.json"
)  # Load State Mapper configuration
if not ret:
    print("Error initializing state machine")
    exit(1)
# Get wdissector instance from state machine initialization
wd = StateMachine.wd

ret = StateMachine.LoadModel(
    "/home/user/wdissector/configs/models/bt/sdp_rfcomm_query.json"
)  # Load State Machine model
if not ret:
    print("Error loading state machine model")
    exit(1)


def packet_mutated_field(original_pkt, fuzzed_pkt):
    """
    Return the field name of fuzzed packet
    """
    result = []
    for i in find_mutation_loc(original_pkt, fuzzed_pkt):
        # print(i)
        # bluetooth classic needs to used offset 4
        p = original_pkt[4:]
        wd_set_packet_direction(wd, WD_DIR_TX)
        wd_packet_dissect(wd, p, len(p))

        # +7 here is because find_mutation_loc will subtract 7 from real offset,
        # Originally find_mutation_loc is for calculating mutation location used in
        # exploit script, where the buffer is counter from location 7
        result.append(packet_read_field_abbrev(wd_read_field_by_offset(wd, i[0] + 7)))

    return result


def packet_state(pkt, pkt_decoding_offset):
    # TODO: detect packet direction, which is different for bluetooth and 5g
    dir = WD_DIR_TX
    pkt = bytearray(pkt)[pkt_decoding_offset:]
    # 1) Prepare State Mapper
    StateMachine.PrepareStateMapper(wd)
    # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
    wd_set_packet_direction(wd, dir)
    wd_packet_dissect(wd, pkt, len(pkt))

    # 3) Run State Mapper
    transition_ok = StateMachine.RunStateMapper(
        wd, dir == WD_DIR_TX
    )  # 2nd argument force transition to TX state, so we just need to validate RX
    return StateMachine.GetCurrentStateName()


# TODO: wrap this in a function or class, automatically select configs
# TODO: add config file to store all paths variables
# _prev_dir = os.getcwd()
# os.chdir("/home/user/wdissector/bindings/python")
PktLabelGen = WDPacketLabelGenerator()
PktLabel = wd_pkt_label()
ret = PktLabelGen.init(
    "/home/user/wdissector/bindings/python/configs/bt_config.json", True
)  # Load State Mapper configuration
if not ret:
    print("Error initializing packet label generator")
    exit(1)
# os.chdir(_prev_dir)
wd_set_dissection_mode(
    wd, WD_MODE_FULL
)  # Enable FULL dissection mode if using wd_read_field_by_offset


def label_packets(pkt: bytes, direction=WD_DIR_TX, pkt_decoding_offset=4):
    # from Matheus
    # Convert to raw and then to bytearray
    # bluetooth classic needs offset 4
    # TODO: pkt_decoding_offset should be set from capture type
    pkt = bytearray(pkt)[pkt_decoding_offset:]
    # Try generating a label for this packet and collect the matched field and value info
    PktLabel = PktLabelGen.LabelPacket(direction, pkt, len(pkt))

    if PktLabel.label_status is True:
        return f"{PktLabel.pkt_field_name} == {PktLabel.pkt_field_value}"
    else:
        # logger.warn(f"Cannot label packet {pkt}")
        return None


def find_mutation_loc(original_pkt_bytes: bytes, mutated_pkt_bytes: bytes) -> list:
    # Find the different bytes in two packets. There might be multiple differences.
    if len(original_pkt_bytes) != len(mutated_pkt_bytes):
        print("Two packets have different length.")

    res = []
    loc = 0
    # TODO: currently this is for bluetooth only
    for i, j in zip(original_pkt_bytes, mutated_pkt_bytes):
        if i != j:
            res.append((loc - 4 - 7, "0x{:02x}".format(mutated_pkt_bytes[loc])))
        loc += 1
    return res


# exploit_template = Template(
#     open("exploit_templates/exploit_template_ble_mut.cpp", "r", encoding="utf8").read()
# )


# # TODO: change to different script according to parameters
# def gen_exploit_script(module_name, wireshark_filter, offset, mutation):
#     return exploit_template.substitute(
#         module_name=module_name,
#         wireshark_filter=wireshark_filter,
#         offset=offset,
#         mutation=mutation,
#     )


def convert_packet_cpp_array(packet):
    packet_string = ",".join(["0x{:02x}".format(i) for i in packet])
    return f"{{ {packet_string} }}"


def split_crash_id(crash_id: str):
    # Guru xxx|Backtrace: xxx |Backtrace: xxx
    # Backtrace xxx
    splitted = crash_id.split("|")
    reason = None
    backtrace1 = None
    backtrace2 = None

    if "Guru" in splitted[0]:
        reason = splitted[0]
        backtrace1 = splitted[1]
        if len(splitted) == 3:
            backtrace2 = splitted[2]
    else:
        # Backtrace: xxx |Backtrace: xxx
        backtrace1 = splitted[0]
        if len(splitted) == 2:
            backtrace2 = splitted[1]

    return reason, backtrace1, backtrace2


def split_backtrace(bt: str):
    splitted = bt.lstrip("Backtrace:").split(" ")
    first_hex = []
    second_hex = []
    for i in splitted:
        temp = i.split(":")
        first_hex.append(temp[0])
        second_hex.append(temp[1])

    return first_hex, second_hex


def is_same_backtrace(bt1, bt2, threshold: int):
    """
    The following types of backtrace variations are considered as same backtraces. Note that backtraces consist of pairs, and each pair contains two values.
        1. **Either** value in the first pair mismatches
        bt1 > Backtrace:0x4002c7bd:0x3ffcc540 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660
        bt2 > Backtrace:0x40027587:0x3ffcc560 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660

        2. **Either** value in the last pair mismatches
        bt1 > Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
        bt2 > Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc660

        3. The same difference between the corresponding **second** value in each pair. In the following example, the fixed difference is 0x410
        bt1 > Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
        bt2 > Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660

        4. Any combination of the types mentioned above.

        ? should this type be considered as the same crash? The first value in the second last pair is different
        Backtrace:0x40082dcd:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400928d5:0x3ffbc4b0 0x4009153d:0x3ffbc4d0
        Backtrace:0x40082dcf:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009140d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400927a5:0x3ffbc4b0 0x4009140d:0x3ffbc4d0

    Erroneous backtrace should result in returning False.
        1. Backtrace:XXXX |<-CORRUPTED
    """
    if bt1 is None and bt2 is None:
        return True

    if len(bt1) != len(bt2):
        return False

    # TODO: only for state like: [Crash] Crash detected at state TX / LMP / LMP_encapsulated_payload
    if bt1 == bt2:
        return True
    if ":" not in bt1 or ":" not in bt2:
        return False

    if "<-CORRUPTED" in bt1 or "<-CORRUPTED" in bt2:
        return False

    bt1_first_hex, bt1_second_hex = split_backtrace(bt1)
    bt2_first_hex, bt2_second_hex = split_backtrace(bt2)

    # first_hex needs to be identical for the same crash, however, first value OR last value in first_hex can be different
    # maybe calculate number of different values
    first_hex_mismatch = 0
    for idx, i, j in zip(range(len(bt1_first_hex)), bt1_first_hex, bt2_first_hex):
        if i != j and idx != 0 and idx != len(bt1_first_hex) - 1:
            first_hex_mismatch += 1

    if first_hex_mismatch > 0:
        return False

    # second_hex is more complex, they can be different, however, each of them needs to shift with the same
    # difference.
    # Valid shift that can indicate the same crash
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x05 0x0a 0x0c
    # Invalid shift
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x06 0x0a 0x0b
    differences = []
    for i, j in zip(bt1_second_hex, bt2_second_hex):
        differences.append(abs(int(i, 16) - int(j, 16)))
    differences.pop(0)

    # return max(differences) <= threshold and sum(differences) / len(differences) <= 200
    return max(differences) <= threshold and max(differences) == min(differences)


def is_same_crash(crash_id1: str, crash_id2: str, threshold: int = 2000):
    # Mainly for ESP32 crashes, because only ESP32 will generate "useful" crash logs with backtraces
    # to help identify and distinguish crashes
    if crash_id1 == "not_found" or crash_id2 == "not_found":
        return False
    # TODO: <-CORRUPTED backtrace
    if "<-CORRUPTED" in crash_id1 or "<-CORRUPTED" in crash_id2:
        return False
    # bt12 is the second backtrace of crash_id1
    reason1, bt11, bt12 = split_crash_id(crash_id1)
    reason2, bt21, bt22 = split_crash_id(crash_id2)

    # mainly judge by backtraces
    if bt12 is None and bt22 is not None:
        return False
    if bt12 is not None and bt22 is None:
        return False

    # print("test1", crash_id2)
    return is_same_backtrace(bt11, bt21, threshold) and is_same_backtrace(
        bt12, bt22, threshold
    )


if __name__ == "__main__":
    # fuzzed_pkts = [
    #     {"type": "dup", "filter": "xx", "data": [12, 45]},
    #     {"type": "mut", "filter": "xxy", "mutations": [(4, "0xd2")]},
    # ]
    # print(gen_universal_exploit_script(fuzzed_pkts))
    crash1 = "Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660"
    crash2 = "Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250"
    print(is_same_crash(crash1, crash2, 2000))
