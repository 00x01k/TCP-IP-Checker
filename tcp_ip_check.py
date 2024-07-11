```python
import socket
import argparse
import time
import subprocess
import re
from scapy.all import sr, IP, TCP, conf
import warnings
import platform
from colorama import init, Fore, Style

# Инициализация colorama
init(autoreset=True)

# Игнорируем предупреждения Scapy о маршрутах
warnings.filterwarnings("ignore", category=RuntimeWarning)

def log_and_print(message, log_file=None, color=Fore.WHITE):
    print(color + message + Style.RESET_ALL)
    if log_file:
        with open(log_file, 'a') as f:
            f.write(message + '\n')

def resolve_dns(host, log_file=None):
    """Разрешение DNS для заданного хоста."""
    try:
        ip = socket.gethostbyname(host)
        log_and_print(f"DNS разрешил {host} в {ip}", log_file, Fore.GREEN)
        return ip
    except socket.error as e:
        log_and_print(f"Не удалось разрешить DNS для {host}: {e}", log_file, Fore.RED)
        return None

def check_tcp_connection(host, port, timeout=5, log_file=None):
    """Проверка TCP-соединения с указанным хостом и портом."""
    try:
        start_time = time.time()
        with socket.create_connection((host, port), timeout) as sock:
            end_time = time.time()
            log_and_print(f"Успешно подключились к {host} на порту {port}", log_file, Fore.GREEN)
            log_and_print(f"Время подключения: {end_time - start_time:.2f} секунд", log_file, Fore.GREEN)
            return True
    except socket.timeout:
        log_and_print(f"Подключение к {host} на порту {port} истекло", log_file, Fore.RED)
    except socket.error as e:
        log_and_print(f"Не удалось подключиться к {host} на порту {port}: {e}", log_file, Fore.RED)
    return False

def ping(host, count=4, log_file=None):
    """Отправка ICMP-эхо запросов к хосту."""
    try:
        response = subprocess.run(
            ["ping", "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if response.returncode == 0:
            log_and_print(f"Ping до {host} успешен:", log_file, Fore.GREEN)
            log_and_print(response.stdout, log_file, Fore.GREEN)
        else:
            log_and_print(f"Ping до {host} неудачен:", log_file, Fore.RED)
            log_and_print(response.stderr, log_file, Fore.RED)
    except Exception as e:
        log_and_print(f"Не удалось выполнить ping: {e}", log_file, Fore.RED)

def scapy_tcp_syn(host, port, log_file=None):
    """Отправка TCP SYN пакета к указанному хосту и порту с использованием scapy."""
    try:
        conf.verb = 0  # Отключаем подробный вывод Scapy
        ans, unans = sr(IP(dst=host)/TCP(dport=port, flags="S"), timeout=5)
        for sent, received in ans:
            if received[TCP].flags == "SA":
                log_and_print(f"Порт {port} на {host} открыт (получен SYN-ACK).", log_file, Fore.GREEN)
                return True
        log_and_print(f"Порт {port} на {host} закрыт или фильтруется.", log_file, Fore.RED)
    except Exception as e:
        log_and_print(f"Не удалось отправить TCP SYN пакет к {host} на порту {port}: {e}", log_file, Fore.RED)
    return False

def traceroute(host, log_file=None):
    """Выполнение трассировки маршрута до хоста."""
    try:
        log_and_print(f"Трассировка маршрута до {host}:", log_file, Fore.YELLOW)
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["tracert", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
        else:
            result = subprocess.run(
                ["traceroute", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
        log_and_print(result.stdout, log_file, Fore.YELLOW)
    except FileNotFoundError:
        log_and_print("Утилита 'traceroute' или 'tracert' не найдена. Установите ее для выполнения трассировки маршрута.", log_file, Fore.RED)
    except Exception as e:
        log_and_print(f"Не удалось выполнить трассировку маршрута: {e}", log_file, Fore.RED)

def packet_loss(host, count=10, log_file=None):
    """Проверка потери пакетов путём отправки ICMP-эхо запросов."""
    try:
        response = subprocess.run(
            ["ping", "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if response.returncode == 0:
            log_and_print(f"Пинг до {host} выполнен успешно:", log_file, Fore.GREEN)
            log_and_print(response.stdout, log_file, Fore.GREEN)

            # Извлечение информации о потере пакетов с помощью регулярных выражений
            match = re.search(r'(\d+)% packet loss', response.stdout)
            if match:
                packet_loss_percentage = match.group(1)
                log_and_print(f"Потеря пакетов: {packet_loss_percentage}%", log_file, Fore.GREEN)
            else:
                log_and_print("Не удалось определить потерю пакетов.", log_file, Fore.RED)
        else:
            log_and_print(f"Пинг до {host} неудачен:", log_file, Fore.RED)
            log_and_print(response.stderr, log_file, Fore.RED)
    except Exception as e:
        log_and_print(f"Не удалось выполнить проверку потери пакетов: {e}", log_file, Fore.RED)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Выполнение полной проверки TCP/IP соединения с расширенными функциями")
    parser.add_argument("host", type=str, help="Хост для проверки")
    parser.add_argument("--ports", type=int, nargs='+', default=[80, 443, 22, 21], help="Список портов для проверки (по умолчанию: 80, 443, 22, 21)")
    parser.add_argument("--timeout", type=int, default=5, help="Таймаут подключения в секундах (по умолчанию: 5)")
    parser.add_argument("--ping-count", type=int, default=4, help="Количество ping-запросов (по умолчанию: 4)")
    parser.add_argument("--traceroute", action='store_true', help="Выполнить трассировку маршрута до хоста")
    parser.add_argument("--packet-loss", action='store_true', help="Проверить потерю пакетов")
    parser.add_argument("--log-file", type=str, help="Файл для логирования результатов")

    args = parser.parse_args()

    log_file = args.log_file
    if log_file:
        with open(log_file, 'w') as f:
            f.write(f"Начало полной проверки TCP/IP соединения для хоста {args.host}\n")

    log_and_print(f"Начало полной проверки TCP/IP соединения для хоста {args.host}...", log_file, Fore.CYAN)

    ip = resolve_dns(args.host, log_file)
    if ip:
        for port in args.ports:
            log_and_print(f"Проверка порта {port}...", log_file, Fore.CYAN)
            check_tcp_connection(ip, port, args.timeout, log_file)
            scapy_tcp_syn(ip, port, log_file)
        
        ping(ip, args.ping_count, log_file)
        
        if args.traceroute:
            traceroute(ip, log_file)
        
        if args.packet_loss:
            packet_loss(ip, args.ping_count, log_file)
