import os
import pickle
from dataclasses import dataclass
from typing import Callable, Literal

from utils import ae_logger, calc_bytes_sha256

BoardType = Literal["esp32", "cypress", "oneplus"]
ProtocolType = Literal["5g", "bt", "wifi"]


class Crash:
    """
    Crash class contains the information and packets related to a crash.

    Attributes
    ----------
    fuzzed_pkts : list["FuzzedPkt"]
        List of fuzzed packets before the crash (and after the last crash) from the fuzzing logs
    loc : int
        Location of crash in fuzzing logs
    iteration : int
        Iteration of crash in fuzzing logs
    identifier : str | None
        Identifier of crash
    crash_type : str
        Type of crash, possible values are `normal`, `timeout` and `flooding`
    raw : bytes
        Raw string of crash comment
    timestamp : int
        Timestamp when crash happens
    """

    def __init__(
        self,
        fuzzed_pkts: list["FuzzedPkt"],
        loc: int,
        iteration: int,
        identifier: str | None,
        crash_type: str,
        raw: bytes,
        timestamp: int,
    ) -> None:
        self.fuzzed_pkts = fuzzed_pkts  # this should be in ascending order by "loc" key
        self.loc = loc
        self.iteration = iteration
        self.identifier = identifier
        self.type = crash_type
        self.raw = raw
        self.timestamp = timestamp


@dataclass
class FuzzedPkt:
    """
    FuzzedPkt class contains the information of one fuzzed packet in fuzzing log.
    """

    pkt_bytes: bytes
    loc: int
    iteration: int
    state: str
    filter: str | None
    type: Literal["mutation", "duplication"]
    fuzz_info: dict | None
    prev_pkt_bytes: bytes


class FuzzLog:
    """
    Fuzzlog class contains the information about the fuzzing logs.
    The detailed implementation for different protocols and devices can be found in this folder.

    Attributes
    ----------
    protocol : ProtocolType
        Protocol of the fuzzing logs
    board : BoardType
        Board in which the fuzzing logs are generated on, such as ESP32 or Cypress
    use_cache : bool
        Whether or not to enable the cache mechanism
    has_trace_log : bool
        Whether or not the fuzzing log contains target trace logs, such as Guru Meditation logs in ESP32
    enable_group_crashes : bool
        Whether or not to enable crash grouping
    """

    def __init__(
        self,
        *,
        protocol: ProtocolType,
        board: BoardType,
        use_cache: bool,
        has_trace_log: bool,
        enable_group_crashes: bool,
    ) -> None:
        self.protocol = protocol
        self.board = board
        self.use_cache = use_cache
        self.has_trace_log = has_trace_log
        self.enable_group_crashes = enable_group_crashes

        self.crashes: list[Crash]
        self.grouped_crashes: list[list[Crash]] = []

    def is_same_crash_id(self, id1, id2):
        """
        Check if two crash identifiers can be classified as the same

        Parameters
        ----------
        id1 : str | None
            The first crash identifier
        id2: str | None
            The second crash identifier

        Returns
        -------
        is_same : bool
        """
        raise NotImplementedError

    def get_crash_id(self, trace_log_path: str, run_log_path: str, target_crash_type: str):
        """
        Get crash identifier from exploit log.

        Parameters
        ----------
        trace_log_path : str
            Path to target trace log
        run_log_path : str
            Path to exploit running log
        target_crash_type: str
            Type of crash, possible values are `normal`, `timeout` and `flooding`

        Returns
        -------
        crash_id : str | None
            Crash identifier
        """
        raise NotImplementedError

    def group_crashes(self):
        """
        Group the same kind of crashes based on their identifiers.

        Developer note: `itertools.groupby` is not a feasible solution here.
        """
        if not self.enable_group_crashes:
            self.grouped_crashes = [[crash] for crash in self.crashes]
        else:
            same_crash_indexes_map: dict[int, list] = {}
            for idx1, crash1 in enumerate(self.crashes):
                same_crash_indexes_map[idx1] = []
                for idx2, crash2 in enumerate(self.crashes):
                    if self.is_same_crash_id(crash1.identifier, crash2.identifier):
                        same_crash_indexes_map[idx1].append(idx2)

            visited = set()
            for k, v in same_crash_indexes_map.items():
                if k in visited:
                    continue
                visited.add(k)
                temp = set([k])
                for i in v:
                    temp.add(i)
                    visited.add(i)
                    for j in same_crash_indexes_map[i]:
                        temp.add(j)
                        visited.add(j)

                self.grouped_crashes.append([self.crashes[i] for i in temp])

        ae_logger.info(
            f"Total {len(self.crashes)} crashes, {len(self.grouped_crashes)} are unique."
        )


class FuzzLogCache:
    """
    Cache is stored in the filesystem with file name being the sha256 hash of capture file.
    For reference, loading and finding crashes from a 997 MB capture file containing 5.7 million
    packets takes about 2 minutes without cache.

    The cache content might be outdated after the function which generates it is changed so that
    the format of cache content is altered. In this case, the cache should always be regenerated.
    A hacky way to determine if a function is changed in Python is to leverage func.__code__ object.
    More information can be found at: https://rushter.com/blog/python-bytecode-patch/. Note that this
    __code__.co_code might differ when running using different versions of Python or on different machines.

    Cache file is a pickled Python dictionary:
    {
        "cache_version":
        "cache_obj":
    }
    """

    def __init__(self, cache_path: str, refs: list[Callable]) -> None:
        # When one of refs changes, the cache is considered as outdated.
        self.cache_path = cache_path
        self.cache_version = calc_bytes_sha256(
            b"".join([ref.__code__.co_code for ref in refs])
        )

    def save(self, cache_obj):
        # cache_obj can be anything that is able to be pickled
        with open(self.cache_path, "wb") as f:
            pickle.dump({"cache_obj": cache_obj, "cache_version": self.cache_version}, f)

    def load(self):
        if not os.path.exists(self.cache_path):
            return None

        with open(self.cache_path, "rb") as f:
            try:
                cache = pickle.load(f)
                if cache["cache_version"] == self.cache_version:
                    return cache["cache_obj"]
            except:
                # logger here
                pass

        return None
