import socket
import scapy.all as scapy

def send_via_udp(ip, port, data):
    """Відправляє дані через UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (ip, port))
    sock.close()

def process_pcap_and_send(pcap_file, udp_ip, udp_port):
    """Зчитує дані з pcap файлу, упаковує їх і відправляє по UDP."""
    # Зчитуємо всі пакети з pcap файлу
    packets = scapy.rdpcap(pcap_file)

    for packet in packets:
        # Отримуємо сирі дані пакету
        raw_data = bytes(packet)

        # Відправляємо пакет через UDP
        send_via_udp(udp_ip, udp_port, raw_data)
        print(f"Відправлено пакет з довжиною {len(raw_data)} байт на {udp_ip}:{udp_port}")

if __name__ == "__main__":
    # Параметри
    pcap_file = "example.pcap"  # Заміни на шлях до свого файлу pcap
    udp_ip = "127.0.0.1"  # IP адреса для відправки
    udp_port = 8080  # Порт для відправки

    # Обробка pcap та відправка через UDP
    process_pcap_and_send(pcap_file, udp_ip, udp_port)
