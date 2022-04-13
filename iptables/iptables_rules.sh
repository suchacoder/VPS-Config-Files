#!/bin/bash
#
# Объявление переменных
export IPT="iptables"
export IPT6="ip6tables"
# Интерфейс который смотрит в интернет
export WAN=eth0
export WAN_IP=your_ip

echo "==================================================================="
echo "======================== IPTABLES RULES ==========================="
echo "==================================================================="
cat > /etc/rsyslog.d/10-iptables.conf << EOL
:msg, contains, "IPTables-Dropped: " -/var/log/iptables.log
& ~
EOL
systemctl restart rsyslog
cat > /etc/logrotate.d/iptables << EOL
/var/log/iptables.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    sharedscripts
}
EOL
logrotate -f /etc/logrotate.conf

# Очистка всех цепочек iptables
$IPT -F

# Установим политики по умолчанию для трафика ip4
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Установим политики по умолчанию для трафика ip6
$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP

# разрешаем локальный траффик для loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Разрешаем исходящие соединения самого сервера
$IPT -A OUTPUT -o $WAN -j ACCEPT

# Состояние ESTABLISHED говорит о том, что это не первый пакет в соединении.
# Пропускать все уже инициированные соединения, а также дочерние от них
$IPT -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
# Пропускать новые, а так же уже инициированные и их дочерние соединения
$IPT -A OUTPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
# Разрешить форвардинг для уже инициированных и их дочерних соединений
$IPT -A FORWARD -p all -m state --state ESTABLISHED,RELATED -j ACCEPT

# Отбрасывать все пакеты, которые не могут быть идентифицированы
# и поэтому не могут иметь определенного статуса.
$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A FORWARD -m state --state INVALID -j DROP

# Открываем порт для ssh
$IPT -A INPUT -i $WAN -p tcp --dport 55655 -j ACCEPT
# Открываем порт для DNS
$IPT -A INPUT -i $WAN -p udp --dport 53 -j ACCEPT
# Открываем порт 80
$IPT -A INPUT -p tcp --dport 80 -j ACCEPT
# Открываем порт 443
$IPT -A INPUT -p tcp --dport 443 -j ACCEPT
#Открываем порт zabbix_agent
iptables -A INPUT -p tcp --dport 10050 -j ACCEPT

#Защищаемся от DDoS атак
###  Отбросить недействительные пакеты ###
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
###  отбросить   TCP-пакеты, которые являются новыми и не являются SYN ###
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
###  отбросить пакеты SYN с подозрительным значением MSS ###
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
###  блокировать пакеты с поддельными флагами TCP ###
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
###  удалить ICMP (этот протокол обычно не нужен) ###
iptables -t mangle -A PREROUTING -p icmp -j DROP
###  ограничение количества соединений на источник IP ###
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset
### 9: Ограничить пакеты RST ###
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
### 10: ограничение количества новых TCP-соединений в секунду для каждого IP-адреса источника. ###
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
### SSH защита от перебора ###
iptables -A INPUT -p tcp --dport 55655 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 55655 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
### Защита от сканирования портов ###
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

# Рзрешаем пинги
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Логирование
# Все что не разрешено, но ломится отправим в цепочку LOG_in
$IPT -N LOG_in

# Логируем все из LOG цепочки
$IPT -A INPUT -j LOG_in
$IPT -A OUTPUT -j LOG_in
$IPT -A LOG_in -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
$IPT -A LOG_in -j DROP

# Записываем правила
iptables-save > /etc/iptables.rules
echo "==================================================================="
echo "================ TIME SYNCHRONIZATION COMPLETE ===================="
echo "==================================================================="
exit
