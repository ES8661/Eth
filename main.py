import socket
import struct
import tkinter as tk
from tkinter import scrolledtext
import threading

# Словник з відомими портами для UDP і TCP
known_ports = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    123: "NTP",
    161: "SNMP",
    5060: "SIP",
    8080: "HTTP-alt",
    40376:"RTP"
}

# Основні номери протоколів
protocols = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

class PacketProcessor:
    def __init__(self):
        self.stats = {
            'Total': 0,
            'Ethernet': 0,
            'IPv4': 0,
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'DNS': 0,
            'FTP': 0,
            'SSH': 0,
            'NTP': 0,
            'SIP': 0,
            'SMTP': 0,
            'RTP': 0,
        }

    def process_packet(self, data):
        """Основна функція обробки пакета."""
        self.stats['Total'] += 1  # Загальна кількість пакетів
        if len(data) < 14:
            return "Недостатньо даних для Ethernet заголовку"

        ethernet_header = data[:14]
        eth = struct.unpack('!6s6sH', ethernet_header)
        eth_protocol = eth[2]  # Забираємо без перевертання байтів

        self.stats['Ethernet'] += 1  # Збільшуємо лічильник Ethernet

        log_message = (
            f"Ethernet II:\n"
            f"    Destination: {self.format_mac_address(eth[0])}\n"
            f"    Source: {self.format_mac_address(eth[1])}\n"
            f"    Type: 0x{eth_protocol:04x}\n"
        )

        if eth_protocol == 0x0800:  # IPv4
            self.stats['IPv4'] += 1  # Збільшуємо лічильник IPv4
            log_message += self.process_ipv4_packet(data[14:])
        else:
            log_message += f"    Невідомий протокол: 0x{eth_protocol:04x}\n"

        # Виведення HEX та ASCII
        log_message += f"\nHex Data and ASCII:\n{self.format_hex_view(data)}"
        return log_message

    def process_ipv4_packet(self, packet):
        """Обробляє IPv4 заголовок."""
        if len(packet) < 20:
            return "Недостатньо даних для IPv4 заголовку"

        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]
        src_ip = self.format_ip_address(iph[8])
        dst_ip = self.format_ip_address(iph[9])

        protocol_name = protocols.get(protocol, f"Unknown ({protocol})")

        log_message = (
            f"    Internet Protocol Version 4:\n"
            f"        Source: {src_ip}\n"
            f"        Destination: {dst_ip}\n"
            f"        Protocol: {protocol_name}\n"
        )

        if protocol == 6:  # TCP
            self.stats['TCP'] += 1  # Збільшуємо лічильник TCP
            log_message += self.process_tcp_packet(packet[20:])
        elif protocol == 17:  # UDP
            self.stats['UDP'] += 1  # Збільшуємо лічильник UDP
            log_message += self.process_udp_packet(packet[20:])

        return log_message

    def process_tcp_packet(self, packet):
        """Обробляє TCP заголовок."""
        if len(packet) < 20:
            return "Недостатньо даних для TCP заголовку"

        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        service_src = known_ports.get(src_port, "Невідомо")
        service_dst = known_ports.get(dst_port, "Невідомо")

        # Оновлюємо статистику для відомих TCP сервісів
        if service_src in self.stats:
            self.stats[service_src] += 1
        if service_dst in self.stats:
            self.stats[service_dst] += 1

        log_message = (
            f"        Transmission Control Protocol:\n"
            f"            Source Port: {src_port} ({service_src})\n"
            f"            Destination Port: {dst_port} ({service_dst})\n"
        )

        return log_message

    def process_udp_packet(self, packet):
        """Обробляє UDP заголовок."""
        if len(packet) < 8:
            return "Недостатньо даних для UDP заголовку"

        udp_header = struct.unpack('!HHHH', packet[:8])
        src_port = udp_header[0]
        dst_port = udp_header[1]
        service_src = known_ports.get(src_port, "Невідомо")
        service_dst = known_ports.get(dst_port, "Невідомо")

        # Оновлюємо статистику для відомих UDP сервісів
        if service_src in self.stats:
            self.stats[service_src] += 1
        if service_dst in self.stats:
            self.stats[service_dst] += 1

        log_message = (
            f"        User Datagram Protocol:\n"
            f"            Source Port: {src_port} ({service_src})\n"
            f"            Destination Port: {dst_port} ({service_dst})\n"
        )

        return log_message

    def format_mac_address(self, mac):
        """Форматує MAC-адресу для виведення."""
        return ':'.join(f'{b:02x}' for b in mac)

    def format_ip_address(self, ip):
        """Форматує IP-адресу для виведення."""
        return '.'.join(map(str, ip))

    def format_hex_view(self, data):
        """Форматує дані у вигляді hex-таблиці та ASCII."""
        hex_output = ""
        for i in range(0, len(data), 16):
            hex_chunk = data[i:i + 16]
            hex_line = ' '.join(f'{byte:02x}' for byte in hex_chunk)
            ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in hex_chunk)
            hex_output += f"{i:04x}   {hex_line:<48}   {ascii_line}\n"
        return hex_output

class UDPReceiver(threading.Thread):
    def __init__(self, gui, ip, port):
        threading.Thread.__init__(self)
        self.gui = gui
        self.ip = ip
        self.port = port
        self.processor = PacketProcessor()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))
        self.gui.log(f"Слухання UDP на {self.ip}:{self.port}...")

        while True:
            data, addr = sock.recvfrom(65535)
            self.gui.log(f"Отримано дані від {addr}")
            result = self.processor.process_packet(data)
            self.gui.log(result)

            # Оновлюємо статистику після обробки пакету
            self.gui.update_stats(self.processor.stats)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP Packet Receiver")

        # Ввід для IP та порту
        self.ip_label = tk.Label(root, text="IP:")
        self.ip_label.grid(column=0, row=0)
        self.ip_entry = tk.Entry(root, width=15)
        self.ip_entry.grid(column=1, row=0)
        self.ip_entry.insert(0, "127.0.0.1")

        self.port_label = tk.Label(root, text="Port:")
        self.port_label.grid(column=0, row=1)
        self.port_entry = tk.Entry(root, width=15)
        self.port_entry.grid(column=1, row=1)
        self.port_entry.insert(0, "8080")

        # Кнопка для запуску сервера
        self.start_button = tk.Button(root, text="Start", command=self.start_receiver)
        self.start_button.grid(column=0, row=2, columnspan=2)

        # Лог виведення
        self.log_area = scrolledtext.ScrolledText(root, width=100, height=40)
        self.log_area.grid(column=0, row=3, columnspan=2)

        # Виведення статистики
        self.stats_label = tk.Label(root, text="Статистика протоколів:")
        self.stats_label.grid(column=0, row=4, columnspan=2)
        self.stats_area = tk.Text(root, height=25, width=50)
        self.stats_area.grid(column=0, row=5, columnspan=2)

    def start_receiver(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())

        self.receiver = UDPReceiver(self, ip, port)
        self.receiver.start()

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def update_stats(self, stats):
        """Оновлює виведення статистики."""
        self.stats_area.delete(1.0, tk.END)
        total = stats['Total']
        for protocol, count in stats.items():
            if protocol != 'Total':
                percentage = (count / total) * 100 if total > 0 else 0
                self.stats_area.insert(tk.END, f"{protocol}: {count} пакети ({percentage:.2f}%)\n")

# Запуск GUI
root = tk.Tk()
app = App(root)
root.mainloop()

