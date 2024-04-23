from scapy.all import sniff, IP, Raw, TCP, ICMP, DNS, DNSRR
import socket
import pandas as pd
from datetime import datetime
import threading
import time


class PacketSniffer:
    def __init__(self):
        self.flows = {}
        self.df_lock = threading.Lock()
        self.df_flows = pd.DataFrame()
        self.local_ip = self.get_ip_address()
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.df_update_thread = threading.Thread(target=self.update_df_flows)
        self.sniffing = True
        self.df_updating = True

    def get_ip_address(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except socket.error as e:
            return None

    def process_packet(self, packet):
        with self.df_lock:
            if IP in packet:
                tcp_flags_abbr = "-"
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = str(packet.sport)
                    dst_port = str(packet.dport)
                    protocol = str(packet[IP].proto)
                    payload = bytes(packet[Raw].load)
                    if TCP in packet:
                        flags_shorthand = packet.sprintf('%TCP.flags%')
                        flags_full = {
                            'F': 'FIN',
                            'S': 'SYN',
                            'R': 'RST',
                            'P': 'PUSH',
                            'A': 'ACK',
                            'U': 'URG',
                            'E': 'ECE',
                            'C': 'CWR'
                        }
                        full_flags = [flags_full.get(flag, flag) for flag in flags_shorthand]
                        tcp_flags_abbr = ' '.join(full_flags)

                except Exception:
                    return None

                flow_key = tuple((src_ip, dst_ip, tcp_flags_abbr, src_port, dst_port, protocol))

                if flow_key not in self.flows:
                    self.flows[flow_key] = {
                        "protocol": protocol,
                        "in_bytes": 0,
                        "in_pkts": 0,
                        "out_bytes": 0,
                        "out_pkts": 0,
                        "cum_tcp_flags": 0,
                        "cum_client_tcp_flags": 0,
                        "cum_server_tcp_flags": 0,
                        "min_ttl": packet[IP].ttl,
                        "max_ttl": packet[IP].ttl,
                        "long_pkt": len(bytes(packet)),
                        "short_pkt": len(bytes(packet)),
                        "size": {
                            "up_to_128": 0,
                            "128_to_256": 0,
                            "256_to_512": 0,
                            "512_to_1024": 0,
                            "1024_to_1514": 0,
                        },
                        "tcp_win": {
                            "max_in": 0,
                            "max_out": 0,
                        },
                        "icmp": {
                            "icmp_type": 0,
                            "icmp_v4_type": 0,
                        },
                        "dns": {
                            "query_id": 0,
                            "query_type": 0,
                            "ttl_ans": 0,
                        }
                    }
                elif flow_key in self.flows:
                    self.flows[flow_key]["min_ttl"] = min(self.flows[flow_key]["min_ttl"], packet[IP].ttl)
                    self.flows[flow_key]["max_ttl"] = max(self.flows[flow_key]["max_ttl"], packet[IP].ttl)
                    self.flows[flow_key]["long_pkt"] = max(
                        self.flows[flow_key]["long_pkt"], len(bytes(packet))
                    )
                    self.flows[flow_key]["short_pkt"] = min(
                        self.flows[flow_key]["short_pkt"], len(bytes(packet))
                    )

                if len(packet[IP]) <= 128:
                    self.flows[flow_key]["size"]["up_to_128"] += 1
                elif 128 < len(packet[IP]) <= 256:
                    self.flows[flow_key]["size"]["128_to_256"] += 1
                elif 256 < len(packet[IP]) <= 512:
                    self.flows[flow_key]["size"]["256_to_512"] += 1
                elif 512 < len(packet[IP]) <= 1024:
                    self.flows[flow_key]["size"]["512_to_1024"] += 1
                elif 1024 < len(packet[IP]) <= 1514:
                    self.flows[flow_key]["size"]["1024_to_1514"] += 1

                if src_ip == self.local_ip:
                    self.flows[flow_key]["out_pkts"] += 1
                    self.flows[flow_key]["out_bytes"] += len(payload)
                    if self.flows[flow_key]["out_pkts"] == 1:
                        self.flows[flow_key]["out_flow"] = {
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "first_timestamp": datetime.utcfromtimestamp(packet.time),
                            "re_flow_bytes": 0,
                            "re_flow_counts": 0,
                        }
                    try:
                        self.flows[flow_key]["out_flow"]["bytes_speed"] = round(
                            self.flows[flow_key]["out_bytes"]
                            / (
                                    datetime.utcfromtimestamp(packet.time)
                                    - self.flows[flow_key]["out_flow"]["first_timestamp"]
                            ).total_seconds()
                        )
                        self.flows[flow_key]["out_flow"]["bits_speed"] = round(
                            (self.flows[flow_key]["out_bytes"] * 8)
                            / (
                                    datetime.utcfromtimestamp(packet.time)
                                    - self.flows[flow_key]["out_flow"]["first_timestamp"]
                            ).total_seconds()
                        )
                    except ZeroDivisionError:
                        self.flows[flow_key]["out_flow"]["bytes_speed"] = 0
                        self.flows[flow_key]["out_flow"]["bits_speed"] = 0
                elif dst_ip == self.local_ip:
                    self.flows[flow_key]["in_pkts"] += 1
                    self.flows[flow_key]["in_bytes"] += len(payload)
                    if self.flows[flow_key]["in_pkts"] == 1:
                        self.flows[flow_key]["in_flow"] = {
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "first_timestamp": datetime.utcfromtimestamp(packet.time),
                            "re_flow_bytes": 0,
                            "re_flow_counts": 0,
                        }
                    try:
                        self.flows[flow_key]["in_flow"]["bytes_speed"] = round(
                            self.flows[flow_key]["in_bytes"]
                            / (
                                    datetime.utcfromtimestamp(packet.time)
                                    - self.flows[flow_key]["in_flow"]["first_timestamp"]
                            ).total_seconds()
                        )
                        self.flows[flow_key]["in_flow"]["bits_speed"] = round(
                            (self.flows[flow_key]["in_bytes"] * 8)
                            / (
                                    datetime.utcfromtimestamp(packet.time)
                                    - self.flows[flow_key]["in_flow"]["first_timestamp"]
                            ).total_seconds()
                        )
                    except ZeroDivisionError:
                        self.flows[flow_key]["in_flow"]["bytes_speed"] = 0
                        self.flows[flow_key]["in_flow"]["bits_speed"] = 0

                if TCP in packet:
                    if src_ip == self.local_ip:
                        self.flows[flow_key]["tcp_win"]["max_in"] = max(self.flows[flow_key]["tcp_win"]["max_in"],
                                                                        packet[TCP].window)
                    elif dst_ip == self.local_ip:
                        self.flows[flow_key]["tcp_win"]["max_out"] = max(self.flows[flow_key]["tcp_win"]["max_out"],
                                                                         packet[TCP].window)
                    if packet[TCP].flags:
                        self.flows[flow_key]["cum_tcp_flags"] += 1
                        if src_ip == self.local_ip:
                            self.flows[flow_key]["cum_client_tcp_flags"] += 1
                            if packet[TCP].flags != "A" and len(packet[TCP].payload) > 0:
                                if (
                                        packet[TCP].flags in ("S", "F")
                                        or len(packet[TCP].payload) > 0
                                ):
                                    if packet[TCP].ack > packet[TCP].seq + len(
                                            packet[TCP].payload
                                    ):
                                        self.flows[flow_key]["out_flow"]["re_flow_bytes"] += len(
                                            packet[TCP].payload
                                        )
                                        self.flows[flow_key]["out_flow"]["re_flow_counts"] += 1
                        elif dst_ip == self.local_ip:
                            self.flows[flow_key]["cum_server_tcp_flags"] += 1
                            if packet[TCP].flags != "A" and len(packet[TCP].payload) > 0:
                                if (
                                        packet[TCP].flags in ("S", "F")
                                        or len(packet[TCP].payload) > 0
                                ):
                                    if packet[TCP].ack > packet[TCP].seq + len(
                                            packet[TCP].payload
                                    ):
                                        self.flows[flow_key]["in_flow"]["re_flow_bytes"] += len(
                                            packet[TCP].payload
                                        )
                                        self.flows[flow_key]["in_flow"]["re_flow_counts"] += 1

                if ICMP in packet:
                    self.flows[flow_key]["icmp"]["icmp_type"] = packet[ICMP].type * 256 + packet[ICMP].code
                    self.flows[flow_key]["icmp"]["icmp_v4_type"] = packet[ICMP].type

                if DNS in packet:
                    self.flows[flow_key]["dns"]["query_id"] = packet[DNS].id
                    self.flows[flow_key]["dns"]["query_type"] = packet[DNS].qr
                    if packet.haslayer(DNSRR):
                        for answer in packet[DNS].an:
                            if answer.type == 1:
                                self.flows[flow_key]["dns"]["ttl_ans"] = answer.ttl

    def update_df_flows(self):
        while self.df_updating:
            with self.df_lock:
                rows = []
                for flow_key, flow_data in self.flows.items():
                    try:
                        if "out_flow" in flow_data:
                            out_row = (
                                    [flow_key[0], flow_key[1], flow_key[2]] +
                                    [flow_data["out_flow"]["src_port"], flow_data["out_flow"]["dst_port"]]
                                    + [
                                        flow_data[key]
                                        for key in flow_data
                                        if key not in ["out_flow", "in_flow", "size", "tcp_win", "icmp", "dns"]
                                    ]
                                    + [
                                        flow_data["out_flow"]["bytes_speed"],
                                        flow_data["in_flow"]["bytes_speed"],
                                        flow_data["out_flow"]["re_flow_bytes"],
                                        flow_data["out_flow"]["re_flow_counts"],
                                        flow_data["in_flow"]["re_flow_bytes"],
                                        flow_data["in_flow"]["re_flow_counts"],
                                    ]
                                    + [
                                        flow_data["out_flow"]["bits_speed"],
                                        flow_data["in_flow"]["bits_speed"],
                                        flow_data["size"]["up_to_128"],
                                        flow_data["size"]["128_to_256"],
                                        flow_data["size"]["256_to_512"],
                                        flow_data["size"]["512_to_1024"],
                                        flow_data["size"]["1024_to_1514"],
                                    ]
                                    + [
                                        flow_data["tcp_win"]["max_in"],
                                        flow_data["tcp_win"]["max_out"],
                                    ]
                                    + [
                                        flow_data["icmp"]["icmp_type"],
                                        flow_data["icmp"]["icmp_v4_type"],
                                    ]
                                    + [
                                        flow_data["dns"]["query_id"],
                                        flow_data["dns"]["query_type"],
                                        flow_data["dns"]["ttl_ans"],
                                    ]
                            )
                            rows.append(out_row)
                    except KeyError:
                        out_row = (
                                [flow_key[0], flow_key[1], flow_key[2]] +
                                [flow_data["out_flow"]["src_port"], flow_data["out_flow"]["dst_port"]]
                                + [
                                    flow_data[key]
                                    for key in flow_data
                                    if key not in ["out_flow", "in_flow", "size", "tcp_win", "icmp", "dns"]
                                ]
                                + [
                                    flow_data["out_flow"]["bytes_speed"],
                                    0,
                                    flow_data["out_flow"]["re_flow_bytes"],
                                    flow_data["out_flow"]["re_flow_counts"],
                                    0,
                                    0,
                                ]
                                + [
                                    flow_data["out_flow"]["bits_speed"],
                                    0,
                                    flow_data["size"]["up_to_128"],
                                    flow_data["size"]["128_to_256"],
                                    flow_data["size"]["256_to_512"],
                                    flow_data["size"]["512_to_1024"],
                                    flow_data["size"]["1024_to_1514"],
                                ]
                                + [
                                    flow_data["tcp_win"]["max_in"],
                                    flow_data["tcp_win"]["max_out"],
                                ]
                                + [
                                    flow_data["icmp"]["icmp_type"],
                                    flow_data["icmp"]["icmp_v4_type"],
                                ]
                                + [
                                    flow_data["dns"]["query_id"],
                                    flow_data["dns"]["query_type"],
                                    flow_data["dns"]["ttl_ans"],
                                ]
                        )
                        rows.append(out_row)
                    try:
                        if "in_flow" in flow_data:
                            in_row = (
                                    [flow_key[0], flow_key[1], flow_key[2]] +
                                    [flow_data["in_flow"]["src_port"], flow_data["in_flow"]["dst_port"]]
                                    + [
                                        flow_data[key]
                                        for key in flow_data
                                        if key not in ["out_flow", "in_flow", "size", "tcp_win", "icmp", "dns"]
                                    ]
                                    + [
                                        flow_data["out_flow"]["bytes_speed"],
                                        flow_data["in_flow"]["bytes_speed"],
                                        flow_data["out_flow"]["re_flow_bytes"],
                                        flow_data["out_flow"]["re_flow_counts"],
                                        flow_data["in_flow"]["re_flow_bytes"],
                                        flow_data["in_flow"]["re_flow_counts"],
                                    ]
                                    + [
                                        flow_data["out_flow"]["bits_speed"],
                                        flow_data["in_flow"]["bits_speed"],
                                        flow_data["size"]["up_to_128"],
                                        flow_data["size"]["128_to_256"],
                                        flow_data["size"]["256_to_512"],
                                        flow_data["size"]["512_to_1024"],
                                        flow_data["size"]["1024_to_1514"],
                                    ]
                                    + [
                                        flow_data["tcp_win"]["max_in"],
                                        flow_data["tcp_win"]["max_out"],
                                    ]
                                    + [
                                        flow_data["icmp"]["icmp_type"],
                                        flow_data["icmp"]["icmp_v4_type"],
                                    ]
                                    + [
                                        flow_data["dns"]["query_id"],
                                        flow_data["dns"]["query_type"],
                                        flow_data["dns"]["ttl_ans"],
                                    ]
                            )
                            rows.append(in_row)
                    except KeyError:
                        in_row = (
                                [flow_key[0], flow_key[1], flow_key[2]] +
                                [flow_data["in_flow"]["src_port"], flow_data["in_flow"]["dst_port"]]
                                + [
                                    flow_data[key]
                                    for key in flow_data
                                    if key not in ["out_flow", "in_flow", "size", "tcp_win", "icmp", "dns"]
                                ]
                                + [
                                    0,
                                    flow_data["in_flow"]["bytes_speed"],
                                    0,
                                    0,
                                    flow_data["in_flow"]["re_flow_bytes"],
                                    flow_data["in_flow"]["re_flow_counts"],
                                ]
                                + [
                                    0,
                                    flow_data["in_flow"]["bits_speed"],
                                    flow_data["size"]["up_to_128"],
                                    flow_data["size"]["128_to_256"],
                                    flow_data["size"]["256_to_512"],
                                    flow_data["size"]["512_to_1024"],
                                    flow_data["size"]["1024_to_1514"],
                                ]
                                + [
                                    flow_data["tcp_win"]["max_in"],
                                    flow_data["tcp_win"]["max_out"],
                                ]
                                + [
                                    flow_data["icmp"]["icmp_type"],
                                    flow_data["icmp"]["icmp_v4_type"],
                                ]
                                + [
                                    flow_data["dns"]["query_id"],
                                    flow_data["dns"]["query_type"],
                                    flow_data["dns"]["ttl_ans"],
                                ]
                        )
                        rows.append(in_row)
                columns = [
                    "IPV4_SRC_ADDRESS",
                    "IPV4_DST_ADDRESS",
                    "TCP_FLAG_ABBR",
                    "L4_SRC_PORT",
                    "L4_DST_PORT",
                    "PROTOCOL",
                    "IN_BYTES",
                    "IN_PKTS",
                    "OUT_BYTES",
                    "OUT_PKTS",
                    "TCP_FLAGS",
                    "CLIENT_TCP_FLAGS",
                    "SERVER_TCP_FLAGS",
                    "MIN_TTL",
                    "MAX_TTL",
                    "LONGEST_FLOW_PKT",
                    "SHORTEST_FLOW_PKT",
                    "SRC_TO_DST_SECOND_BYTES",
                    "DST_TO_SRC_SECOND_BYTES",
                    "RETRANSMITTED_IN_BYTES",
                    "RETRANSMITTED_IN_PKTS",
                    "RETRANSMITTED_OUT_BYTES",
                    "RETRANSMITTED_OUT_PKTS",
                    "SRC_TO_DST_AVG_THROUGHPUT",
                    "DST_TO_SRC_AVG_THROUGHPUT",
                    "NUM_PKTS_UP_TO_128_BYTES",
                    "NUM_PKTS_128_TO_256_BYTES",
                    "NUM_PKTS_256_TO_512_BYTES",
                    "NUM_PKTS_512_TO_1024_BYTES",
                    "NUM_PKTS_1024_TO_1514_BYTES",
                    "TCP_WIN_MAX_IN",
                    "TCP_WIN_MAX_OUT",
                    "ICMP_TYPE",
                    "ICMP_IPV4_TYPE",
                    "DNS_QUERY_ID",
                    "DNS_QUERY_TYPE",
                    "DNS_TTL_ANSWER",
                ]
                self.df_flows = pd.DataFrame(rows, columns=columns)
            time.sleep(0.01)

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0)

    def start_sniffing(self):
        self.sniffer_thread.start()

    def start_df_update(self):
        self.df_update_thread.start()

    def stop_sniffing_and_df_updating(self):
        if self.sniffer_thread.is_alive():
            self.sniffing = False
            self.sniffer_thread.join()
            self.df_updating = False
            self.df_update_thread.join()
        return

    def get_df_flows(self):
        with self.df_lock:
            protocol_mapping = {
                '6': 'TCP',
                '17': 'UDP',
                '1': 'ICMP',
                '2': 'IGMP',
                '80': 'HTTP',
                '443': 'HTTPS',
                '21': 'FTP',
                '25': 'SMTP',
                '110': 'POP3',
                '143': 'IMAP',
                '53': 'DNS',
                '67': 'DHCP',
                '68': 'DHCP',
                '22': 'SSH',
                '23': 'Telnet'
            }
            columns = ["IPV4_SRC_ADDRESS", "IPV4_DST_ADDRESS", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL",
                       "TCP_FLAG_ABBR",
                       "IN_BYTES", "OUT_BYTES"]
            table_data = self.df_flows[columns]

            table_data.loc[:, "PROTOCOL"] = table_data.loc[:, "PROTOCOL"].map(protocol_mapping)
            return table_data

    def get_per_min_df_flows(self):
        with self.df_lock:
            return self.df_flows.iloc[:, 3:]

    def empty_df_flows(self):
        self.flows = {}