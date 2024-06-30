import psutil
import socket


def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def pretty_print_connections(connections):
    for connection in connections:
        domain_name = get_domain_name(connection['raddr_ip'])
        process_name = psutil.Process(connection['pid']).name()

        print(
            f"{connection['laddr_ip']}:{connection['laddr_port']} -> {domain_name}:{connection['raddr_port']} ({process_name})")


def is_right_address(ip):
    return ip not in ['127.0.0.1', '0.0.0.0', '::', ':']


final_connections = []


for connection in psutil.net_connections():
    if is_right_address(connection.laddr.ip) and is_right_address(connection.laddr.ip):
        final_connections.append({
            'laddr_ip': connection.laddr.ip,
            'laddr_port': connection.laddr.port,
            'raddr_ip': connection.raddr.ip if connection.raddr != () else '',
            'raddr_port': connection.raddr.port if connection.raddr != () else '',
            'pid': connection.pid
        })

pretty_print_connections(final_connections)
