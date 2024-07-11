# TCP-IP-Checker
# TCP/IP Checker

TCP/IP Checker - это утилита для выполнения полной проверки TCP/IP соединения с различными функциями, такими как проверка доступности портов, трассировка маршрута и проверка потерь пакетов.

## Возможности

- Разрешение DNS
- Проверка TCP-соединений
- Отправка ICMP-эхо запросов (ping)
- Трассировка маршрута до хоста
- Проверка потерь пакетов
- Логирование результатов в файл

## Установка

1. Клонируйте репозиторий:

    ```sh
    git clone https://github.com/yourusername/tcp_ip_checker.git
    cd tcp_ip_checker
    ```

2. Установите необходимые библиотеки:

    ```sh
    pip install -r requirements.txt
    sudo apt-get install traceroute  # для Debian/Ubuntu
    sudo yum install traceroute      # для CentOS/RHEL
    sudo dnf install traceroute      # для Fedora
    
    ```

## Использование

Запустите скрипт из командной строки, передав нужные параметры:

```sh
python tcp_ip_check.py example.com --ports 80 443 22 --traceroute --packet-loss --ping-count 10 --log-file result.log


Начало полной проверки TCP/IP соединения для хоста example.com...
DNS разрешил example.com в 93.184.216.34
Проверка порта 80...
Успешно подключились к 93.184.216.34 на порту 80
Время подключения: 0.12 секунд
...
Параметры командной строки
host - Хост для проверки.
--ports - Список портов для проверки (по умолчанию: 80, 443, 22, 21).
--timeout - Таймаут подключения в секундах (по умолчанию: 5).
--ping-count - Количество ping-запросов (по умолчанию: 4).
--traceroute - Выполнить трассировку маршрута до хоста.
--packet-loss - Проверить потерю пакетов.
--log-file - Файл для логирования результатов.
