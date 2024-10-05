import datetime
import hashlib
import logging
import os
import random
import re
import string
import subprocess
import sys

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from pcapng.exceptions import TruncatedFile
from wdissector import (
    WD_DIR_TX,
    WD_MODE_FULL,
    Machine,
    WDPacketLabelGenerator,
    wd_packet_dissect,
    wd_pkt_label,
    wd_set_dissection_mode,
    wd_set_packet_direction,
)

from constants import RUN_LOG_PATH


def count_mut_dup(exploit_path: str) -> tuple[int, int]:
    """
    Count the number of mutated and duplicated packets inside a exploit script.

    Parameters
    ----------
    exploit_path : str
        Path to the exploit script

    Returns
    -------
    mut_count : int
        Number of mutated packets in the exploit
    dup_count : int
        Number of duplicated packets in the exploit
    """
    # count the number of mutated and duplicated packets inside exploit_path
    exploit_content = open(exploit_path, "r", encoding="utf8", errors="ignore").read()
    mut_count = exploit_content.count("Send mutated packet now")
    dup_count = exploit_content.count("Send duplicated packet now")

    return mut_count, dup_count


def random_string(size: int) -> str:
    """
    Generate a random string consisting of lower case letters and digits.

    Parameters
    ----------
    size : int
        Length of the desired random string

    Returns
    -------
    s : str
        Random string
    """
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(size)
    )


def human_current_date() -> str:
    """
    Generate a human-friendly current date.
    The format is month_day_hour_minute, for example: `10_04_17_05` means `October 4th, 17:05`.

    Parameters
    ----------
    None

    Returns
    -------
    date_str : str
    """
    now = datetime.datetime.now()
    return f"{now.month:02}_{now.day:02}_{now.hour:02}_{now.minute:02}"


def get_logger(name: str) -> logging.Logger:
    """
    Get logger with the specified name.

    Parameters
    ----------
    name : str
        Logger name

    Returns
    -------
    logger : Logger
    """
    # TODO: this function needs to be prevented from being called multiple times
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    filehandler = logging.FileHandler(
        f"{RUN_LOG_PATH}/{name}.log", mode="w", encoding="utf8"
    )
    print(f"AirBugCatcher log is saved in {RUN_LOG_PATH}/{name}.log")
    filehandler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s:%(lineno)d - %(message)s"
        )
    )
    logger.addHandler(filehandler)
    return logger


session_id = random_string(4)
ae_logger = get_logger(f"ae_{human_current_date()}_{session_id}")


def calc_bytes_sha256(b: bytes) -> str:
    """
    Calculate sha256 hash value of a bytes object.

    Parameters
    ----------
    b : bytes

    Returns
    -------
    h : str
        sha256 hash value
    """
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(b)

    return hash_sha256.hexdigest()


def calc_file_sha256(file_path: str, chunk_size: int = 4096) -> str:
    """
    Calculate sha256 hash value of a file.

    Parameters
    ----------
    file_path : str
        Path to file
    chunk_size : int, default 4096
        Chunk when reading the file. The chunk will be read into memory.

    Returns
    -------
    sha256_hash : str
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if len(chunk) == 0:
                break
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()


def pcap_pkt_reader(path: str):
    """
    Capture file reader, using python-pcapng library.

    Parameters
    ----------
    path : str
        Path to the capture file

    Yields
    -------
    packet_id : int
    packet : EnhancedPacket
    """
    # Return a generator to yield EnhancedPacket and its index in the capture: (index, EnhancedPacket)
    with open(path, "rb") as f:
        scanner = FileScanner(f)
        pkt_index = 0  # this is the packet number in Wireshark
        try:
            for block in scanner:
                if not isinstance(block, EnhancedPacket):
                    continue
                pkt_index += 1
                yield pkt_index, block
        except TruncatedFile:
            ae_logger.info(
                f"The capture file {path} is truncated. This is normal when Wireshark writes the capture file and does not mean the capture file is broken."
            )
        except Exception:
            ae_logger.error(
                f"Processing capture file: {path} at packet: {pkt_index}",
                exc_info=True,
            )


def clean_up_process(proc_name_keyword: str):
    """
    Helper function to kill processes whose name contains given keyword.

    As the exploit is executed with `script` command and the exploit script itself will spawn other
    processes, there might be some orphan processes left. These processes might still take up
    resources like CPU or modem, so need to clean up. Be careful to use a specific keyword so that
    no innocent processes will be killed. The command to run the exploits are like:
    - `script /tmp/tmp1edlcn4x --flush` or
    - `sudo bin/lte_fuzzer --exploit=mac_sch_auto_fuzz_exploit_8263 --EnableSimulator=false`.

    Parameter
    ---------
    proc_name_keyword : str
        Process name keyword

    Returns
    -------
    None
    """
    try:
        pids = (
            subprocess.check_output(["pgrep", "-f", proc_name_keyword])
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
    except:
        pass


class WDissectorTool:
    """
    WDissector useful tools.

    WDissectorTool class provides easy access to some useful functions developed by WDissector.

    Attributes
    ----------
    protocol : str
        Protocol used in WDissector
    enable_full_dissection : bool
        Enable the full dissection mode of WDissector. This mode is no long needed in AirBugCatcher.
    """

    def __init__(self, protocol, enable_full_dissection: bool = False) -> None:
        """
        Initialize WDissector instance.
        """
        if protocol == "bt":
            state_machine_config = "/home/user/wdissector/configs/bt_config.json"
            model_config = "/home/user/wdissector/configs/models/bt/sdp_rfcomm_query.json"
        elif protocol == "5g":
            state_machine_config = "/home/user/wdissector/configs/5gnr_gnb_config.json"
            model_config = "/home/user/wdissector/configs/models/5gnr_gnb/nr-softmodem.json"
        elif protocol == "wifi":
            state_machine_config = "/home/user/wdissector/configs/wifi_ap_config.json"
            model_config = "/home/user/wdissector/configs/models/wifi_ap/wpa2_eap.json"

        self.StateMachine = Machine()
        # Load State Mapper configuration
        if not self.StateMachine.init(state_machine_config):
            ae_logger.error("Error initializing state machine")
            exit(1)
        # Get wdissector instance from state machine initialization
        self.wd = self.StateMachine.wd

        if not self.StateMachine.LoadModel(model_config):
            ae_logger.error("Error loading state machine model")
            exit(1)

        self.PktLabelGen = WDPacketLabelGenerator()
        self.PktLabel = wd_pkt_label()
        # Load State Mapper configuration
        if not self.PktLabelGen.init(state_machine_config, True):
            ae_logger.error("Error initializing packet label generator")
            exit(1)

        # Enable FULL dissection mode if using wd_read_field_by_offset
        if enable_full_dissection:
            wd_set_dissection_mode(self.wd, WD_MODE_FULL)

    def pkt_state(self, pkt: bytes, pkt_decoding_offset: int):
        """
        Get state of a packet.

        Parameters
        ----------
        pkt : bytes
            Packet data in bytes
        pkt_decoding_offset : int
            Offset to decode the packet. In some scenarios, WDissector may
            need to decode a packet from the middle.

        Returns
        -------
        state : str
        """
        # TODO: detect packet direction, which is different for bluetooth and 5g
        dir = WD_DIR_TX
        pkt = bytearray(pkt)[pkt_decoding_offset:]
        # 1) Prepare State Mapper
        self.StateMachine.PrepareStateMapper(self.wd)
        # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
        wd_set_packet_direction(self.wd, dir)
        wd_packet_dissect(self.wd, pkt, len(pkt))

        # 3) Run State Mapper
        transition_ok = self.StateMachine.RunStateMapper(
            self.wd, dir == WD_DIR_TX
        )  # 2nd argument force transition to TX state, so we just need to validate RX
        return self.StateMachine.GetCurrentStateName()

    def label_pkt(self, pkt: bytes, direction=WD_DIR_TX, pkt_decoding_offset: int = 4):
        """
        Get the label of a packet. The label is used to identify a packet and it is
        in the form of Wireshark filter.

        Parameters
        ----------
        pkt : bytes
            Packet data in bytes
        direction : WD_DIR_TX or WD_DIR_RX
            Packet direction
        pkt_decoding_offset : int
            Offset to decode the packet. In some scenarios, WDissector may
            need to decode a packet from the middle.

        Returns
        -------
        label : str

        """
        # Convert to raw and then to bytearray
        # bluetooth classic needs offset 4
        # TODO: pkt_decoding_offset should be set from capture type
        pkt = bytearray(pkt)[pkt_decoding_offset:]
        # Try generating a label for this packet and collect the matched field and value info
        PktLabel = self.PktLabelGen.LabelPacket(direction, pkt, len(pkt))

        if PktLabel.label_status is True:
            return f"{PktLabel.pkt_field_name} == {PktLabel.pkt_field_value}"
        else:
            # logger.warn(f"Cannot label packet {pkt}")
            return None


def find_mutation_loc(
    protocol: str, original_pkt_bytes: bytes, mutated_pkt_bytes: bytes
) -> list[tuple[int, str]]:
    """
    Find the mutation locations by comparing the two packets.

    Parameters
    ----------
    protocol : str
        Protocol which the packet bytes belong to
    original_pkt_bytes : bytes
        Original packet data
    mutated_pkt_bytes : bytes
        mutate packet data

    Returns
    -------
    locations : list[tuple[int, str]]
        List of mutation locations. Each item in the list is a tuple consisting of
        **mutation offset** and **value of mutated byte**.
    """
    # TODO: integrate into fuzzlog class, this is wdissector only however
    # Find the different bytes in two packets. There might be multiple differences.
    if len(original_pkt_bytes) != len(mutated_pkt_bytes):
        ae_logger.info("Two packets have different length.")

    if protocol == "bt":
        offset = -4 - 7
    elif protocol == "5g":
        offset = 0
    elif protocol == "wifi":
        offset = -9
    else:
        ae_logger.error("Unknown protocol")

    res = []
    loc = 0
    # TODO: currently this is for bluetooth only
    for i, j in zip(original_pkt_bytes, mutated_pkt_bytes):
        if i != j:
            res.append((loc + offset, "0x{:02x}".format(mutated_pkt_bytes[loc])))
        loc += 1
    return res


def convert_bytes_to_cpp_array(b: bytes):
    """
    Helper function to convert Python bytes to a C++ array.

    Parameters
    ----------
    b : bytes
        Python bytes

    Returns
    -------
    cpp_array : str
    """
    # Convert b"abcd" to {'0x61', '0x62', '0x63', '0x64'}
    pkt_string = ",".join([hex(i) for i in b])
    return f"{{ {pkt_string} }}"


def split_crash_id(crash_id: str):
    """
    Split crash identifier into smaller parts.

    Parameters
    ----------
    crash_id : str
        Crash identifier

    Returns
    -------
    assert_error : str
        Assert error line in `crash_id`
    guru_error : str | None
        Guru Meditation error line in `crash_id`
    backtrace1 : str
        The first backtrace
    backtrace2 : str | None
        The second backtrace
    """
    # Guru xxx|Backtrace: xxx |Backtrace: xxx
    # Backtrace xxx
    splitted = crash_id.split("|")
    assert_error = splitted[0]
    guru_error = None
    backtrace1 = None
    backtrace2 = None

    if "Guru" in splitted[1]:
        guru_error = splitted[1]
        backtrace1 = splitted[2]
        if len(splitted) == 4:
            backtrace2 = splitted[3]
    else:
        # Backtrace: xxx |Backtrace: xxx
        backtrace1 = splitted[1]
        if len(splitted) == 3:
            backtrace2 = splitted[2]

    backtrace1 = re.sub(r"[^: ]0x", " 0x", backtrace1)
    if backtrace2 is not None:
        backtrace2 = re.sub(r"[^: ]0x", " 0x", backtrace2)

    return assert_error, guru_error, backtrace1, backtrace2


def split_backtrace(bt: str):
    """
    Split backtrace into hex values. The hex values inside the backtrace are
    usually paired and each pair is separated by space like: `0x01:0x02 0x03 0x04`.

    Parameters
    ----------
    bt : str
        Backtrace

    Returns
    -------
    first_hex : list[str]
        List of the first hex values of each pair of the hex value.
    second_hex : list[str]
        List of the second hex values of each pair of the hex value.
    """
    splitted = bt.lstrip("Backtrace: ").lstrip("Backtrace:").split(" ")
    first_hex = []
    second_hex = []
    for i in splitted:
        temp = i.split(":")
        first_hex.append(temp[0])
        second_hex.append(temp[1])

    return first_hex, second_hex


def is_same_backtrace(bt1, bt2, threshold: int, first_hex_mismatch_thresh: int = 1):
    """
    Check if two backtrace are the same.

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

        TODO: ? should this type be considered as the same crash? The first value in the second last pair is different
        Backtrace:0x40082dcd:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400928d5:0x3ffbc4b0 0x4009153d:0x3ffbc4d0
        Backtrace:0x40082dcf:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009140d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400927a5:0x3ffbc4b0 0x4009140d:0x3ffbc4d0

    Erroneous backtrace should return False.
        1. Backtrace:XXXX |<-CORRUPTED

    Parameters
    ----------
    bt1 : None | str
        The first backtrace
    bt2 : None | str
        The second backtrace
    threshold : int
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.
    first_hex_mismatch_thresh : int
        In some scenarios, the two backtraces can be the same backtrace even some first hex values are mismatched.

    Returns
    -------
    is_bt1_bt2_same : bool
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
    first_hex_mismatch_count = 0
    for idx, i, j in zip(range(len(bt1_first_hex)), bt1_first_hex, bt2_first_hex):
        if i != j and idx != 0 and idx != len(bt1_first_hex) - 1:
            first_hex_mismatch_count += 1

    if first_hex_mismatch_count > first_hex_mismatch_thresh:
        return False

    # second_hex is more complex, they can be different, however, each of them may shift with the same difference.
    # Valid shift that can indicate the same crash
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x05 0x0a 0x0c  < different is always 0x04
    # Invalid shift
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x06 0x0a 0x0b  < different is 0x05 0x04 0x03
    differences = []
    for i, j in zip(bt1_second_hex, bt2_second_hex):
        differences.append(abs(int(i, 16) - int(j, 16)))
    # The first difference may vary even in the case of same backtrace
    differences.pop(0)

    # return max(differences) <= threshold and sum(differences) / len(differences) <= 200
    return max(differences) <= threshold and max(differences) == min(differences)


def is_same_corrupted_crash(crash_id1: str, crash_id2: str, threshold: int = 2000):
    """
    Check if two **corrupted** crash identifiers can be classified as the same one.

    Parameters
    ----------
    crash_id1 : str
        The first crash identifier
    crash_id2 : str
        The second crash identifier
    threshold : int, default 2000
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.

    Returns
    -------
    is_same : bool

    See Also
    --------
    `is_same_crash` for checking the normal crash identifiers.
    """
    if ("<-CORRUPTED" in crash_id1 and "<-CORRUPTED" not in crash_id2) or (
        "<-CORRUPTED" not in crash_id1 and "<-CORRUPTED" in crash_id2
    ):
        return False

    if ("LoadProhibited" in crash_id1 and "StoreProhibited" in crash_id2) or (
        "LoadProhibited" in crash_id2 and "StoreProhibited" in crash_id1
    ):
        return False

    # corrupted crash identifier only has one backtrace
    bt1 = crash_id1.replace(" |<-CORRUPTED", "").split("|")[-1]
    bt2 = crash_id1.replace(" |<-CORRUPTED", "").split("|")[-1]

    return is_same_backtrace(bt1, bt2, threshold, first_hex_mismatch_thresh=0)


def is_same_crash(crash_id1: str, crash_id2: str, threshold: int = 2000):
    """
    Check if two crash identifiers can be classified as the same one.

    Parameters
    ----------
    crash_id1 : str
        The first crash identifier
    crash_id2 : str
        The second crash identifier
    threshold : int, default 2000
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.

    Returns
    -------
    is_same : bool

    See Also
    --------
    `is_same_corrupted_crash` for checking the **corrupted** crash identifiers.
    """
    # Mainly for ESP32 crashes, because only ESP32 will generate "useful" crash logs with backtraces
    # to help identify and distinguish crashes
    if crash_id1 == crash_id2:
        return True
    if crash_id1 == "not_found" or crash_id2 == "not_found":
        return False
    if ("<-CORRUPTED" in crash_id1) or ("<-CORRUPTED" in crash_id2):
        # TODO: <-CORRUPTED backtrace
        return is_same_corrupted_crash(crash_id1, crash_id2, threshold)
    if "|" not in crash_id1 or "|" not in crash_id2:
        return False

    # bt12 is the second backtrace of crash_id1
    assert_error1, guru_error1, bt11, bt12 = split_crash_id(crash_id1)
    assert_error2, guru_error2, bt21, bt22 = split_crash_id(crash_id2)
    if assert_error1 != "" and assert_error1 == assert_error2:
        return True

    # mainly judge by backtraces
    if bt12 is None and bt22 is not None:
        return False
    if bt12 is not None and bt22 is None:
        return False

    return is_same_backtrace(bt11, bt21, threshold) and is_same_backtrace(
        bt12, bt22, threshold
    )


def extract_ts(s: str) -> float:
    """
    Extract and convert timestamp from a string like `[2022-06-22 22:54:46.827969] Guru Meditation Error:`.

    Parameters
    ----------
    s : str
        String that contains a timestamp

    Returns
    -------
    ts : float
        Unix timestamp, in seconds.
        If no `[2022-06-22 22:54:46.827969]`-like string are found in the input, return 0.
    """
    timestamp_re = re.compile(r"^\[.*?\]")
    if len(timestamp_re.findall(s)) == 0:
        return 0
    else:
        dt = datetime.datetime.strptime(
            timestamp_re.findall(s)[0], "[%Y-%m-%d %H:%M:%S.%f]"
        )
        return dt.timestamp()


if __name__ == "__main__":
    # fuzzed_pkts = [
    #     {"type": "dup", "filter": "xx", "data": [12, 45]},
    #     {"type": "mut", "filter": "xxy", "mutations": [(4, "0xd2")]},
    # ]
    # print(gen_universal_exploit_script(fuzzed_pkts))
    crash1 = "Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660"
    crash2 = "Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250"
    print(is_same_crash(crash1, crash2, 2000))
    print(is_same_crash(crash1, crash2, 2000))
