import base64
import json
import os

from scapy.all import rdpcap

from constants import CAPTURE_CACHE_PATH
from utils import ae_logger, calc_file_sha256

from .fuzzlog import Crash, FuzzedPkt, FuzzLog, FuzzLogCache


class NordicBleFuzzLog(FuzzLog):
    def __init__(
        self,
        *,
        use_cache: bool,
        enable_group_crashes: bool,
        access_address: bytes,
        capture_path: str,
        fuzzed_pkt_info_path: str,
        crash_report_path: str,
    ) -> None:
        super().__init__(
            protocol="ble",
            board="nordic",
            use_cache=use_cache,
            has_trace_log=False,
            enable_group_crashes=enable_group_crashes,
        )
        self.access_address = access_address
        self.capture_path = capture_path
        self.fuzzed_pkt_info_path = fuzzed_pkt_info_path
        self.crash_report_path = crash_report_path

        self.crashes: list[Crash]

        # Initialize cache
        if self.use_cache:
            capture_sha256 = calc_file_sha256(self.capture_path)
            cache_path = os.path.join(CAPTURE_CACHE_PATH, f"{capture_sha256}.pickle")
            self.fuzzlog_cache = FuzzLogCache(cache_path, [self.discover_crashes])

        self.discover_crashes()
        self.group_crashes()

    def is_same_crash_id(self, id1, id2):
        return id1 == id2

    def discover_crashes(self):
        ae_logger.info("Discovering crashes...")
        # Load from cache if possible
        if self.use_cache and self.fuzzlog_cache is not None:
            crashes = self.fuzzlog_cache.load()
            if crashes is not None:
                self.crashes = crashes
                return

        self.crashes = []

        # Load fuzzed packet information because this information is not included in pcap file
        with open(self.fuzzed_pkt_info_path, "r", encoding="utf8") as f:
            fuzzed_pkt_info = json.load(f)

        crash_report = []
        with open(self.crash_report_path, "r", encoding="utf8") as f:
            for idx, line in enumerate(f):
                if idx == 0:
                    # skip header
                    continue
                crash_report.append(line[:-1].split(","))
        crash_report.sort(key=lambda x: int(x[-1]))

        crash_report_pointer = 0
        fuzzed_pkts: list[FuzzedPkt] = []

        fuzzed_pkt_info_pointer = 0
        for idx, pkt in enumerate(rdpcap(self.capture_path), start=1):
            if pkt.load[17:21] != self.access_address:
                # Desired access address
                # Filter retrieved from Wireshark using btle.access_address. Not all packets
                # are desired because broadcasted packet are also inside.
                continue

            # iteration starts from 0
            while True:
                ts, state, layer, mutation, duplication, iteration = fuzzed_pkt_info[
                    "packet_info"
                ][fuzzed_pkt_info_pointer]
                if ts > pkt.time:
                    break
                fuzzed_pkt_info_pointer += 1

            # mutation
            mutation_fields = {}
            if mutation is not None and len(mutation) != 0:
                for i in mutation:
                    try:
                        v = base64.b64decode(i[2]).decode()
                        if v.isdigit():
                            v = int(v)
                    except:
                        v = base64.b64decode(i[2])

                    mutation_fields[i[0]] = mutation_fields.get(i[0], []) + [(i[1], v)]

                fuzzed_pkts.append(
                    FuzzedPkt(
                        pkt_bytes=pkt.load,
                        loc=idx,
                        iteration=iteration,
                        state=None,
                        filter=layer,
                        type="mutation",
                        fuzz_info=mutation_fields,
                        prev_pkt_bytes=prev_pkt_bytes,
                    )
                )

            if duplication is not None:
                fuzzed_pkts.append(
                    FuzzedPkt(
                        pkt_bytes=pkt.load,
                        loc=idx,
                        iteration=iteration,
                        state=None,
                        filter=layer,
                        type="duplication",
                        fuzz_info=duplication,
                        prev_pkt_bytes=prev_pkt_bytes,
                    )
                )

            if int(crash_report[crash_report_pointer][-1]) < iteration:
                self.crashes.append(
                    Crash(
                        fuzzed_pkts=fuzzed_pkts[:],
                        loc=idx,
                        iteration=iteration,
                        identifier=crash_report[crash_report_pointer][1],
                        crash_type="normal",
                        raw=None,
                        timestamp=pkt.time,
                    )
                )
                crash_report_pointer += 1
                fuzzed_pkts = []

            prev_pkt_bytes = pkt.load

        if len(fuzzed_pkts) != 0:
            self.crashes.append(
                Crash(
                    fuzzed_pkts=fuzzed_pkts,
                    loc=idx,
                    iteration=iteration,
                    identifier=crash_report[crash_report_pointer][1],
                    crash_type="normal",
                    raw=None,
                    timestamp=pkt.time,
                )
            )

        # Save cache of possible
        if self.use_cache and self.fuzzlog_cache is not None:
            self.fuzzlog_cache.save(self.crashes)
