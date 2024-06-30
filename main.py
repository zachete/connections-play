import psutil
import socket
from scapy.all import *


def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def packet_handler(packet):
    if "IP" in packet:
        ip_src = packet["IP"].src
        port_src = packet["IP"].sport
        ip_dst = packet["IP"].dst
        port_dst = packet["IP"].dport
        size = len(packet["IP"])

        for connection in psutil.net_connections():
            connection_data = {
                "laddr_ip": connection.laddr.ip,
                "laddr_port": connection.laddr.port,
                "raddr_ip": connection.raddr.ip if connection.raddr != () else "",
                "raddr_port": connection.raddr.port if connection.raddr != () else "",
                "pid": connection.pid,
            }

            if (
                connection_data["laddr_ip"] == ip_src
                and connection_data["laddr_port"] == port_src
                and connection_data["raddr_ip"] == ip_dst
                and connection_data["raddr_port"] == port_dst
            ):
                process_name = psutil.Process(connection_data["pid"]).name()

                print(
                    f'{size} bytes sended, {connection_data["laddr_ip"]}:{connection_data["laddr_port"]} -> {get_domain_name(connection_data["raddr_ip"])}:{connection_data["raddr_port"]} ({process_name}) '
                )


sniff(prn=packet_handler)
