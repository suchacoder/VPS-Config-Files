#!/bin/sh
# Jim McKibben
# SSH Port easy customization
# Allows Local Loopback
# Allows DNS Query and Response
# Blocks bad source
# Blocks non local Loopback
# DOS Protection and reporting
# DOS SYN Flood
# DOS ICMP
# DOS SSH
# Logging
# Admin IP / Monitoring Section
# IPSET Blocklist Support
# Fixed SRC/DST Admin
# Allowed blocklist response

IPT=/sbin/iptables
IFACE="ens3"
ADMIN="181.21.0.0/16"
SSHPORT="44555"
DNS_SERVER="8.8.4.4 8.8.8.8"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
URTPORTS="1337,1339"

echo "Enabling Firewall..."

# IPv4 rules

# Loopback rules
echo "Enabling loopback rules..."
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -i !lo -d 127.0.0.0/8 -j REJECT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A OUTPUT -o !lo -d 127.0.0.0/8 -j REJECT

# This should be one of the first rules.
# so dns lookups are already allowed for your other rules
echo "Allowing DNS lookups (tcp, udp port 53) to server '$DNS_SERVER'..."
for ip in $DNS_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $IFACE -p udp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT
	$IPT -A OUTPUT -o $IFACE -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $IFACE -p tcp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT
done

# Allowing repositories
echo "Enabling Repositories..."
for ip in $PACKAGE_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$ip" -m multiport --dport 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $IFACE -p tcp -s "$ip" -m multiport --sport 80,443 -m state --state ESTABLISHED -j ACCEPT
done

# Admin IPs Version 2
echo "Enabling admin's IP..."
$IPT -A INPUT -s $ADMIN -j ACCEPT
$IPT -A OUTPUT -d $ADMIN -j ACCEPT

# Stateful table
echo "Making the firegual statefull..."
$IPT -N STATEFUL > /dev/null
$IPT -F STATEFUL
$IPT -I STATEFUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A STATEFUL -m conntrack --ctstate NEW -i !eth0 -j ACCEPT
$IPT -A STATEFUL -j LOG --log-prefix "iptables stateful LOG: "

# Enable IPSET blacklists - logs blocked attempts and responds with port unreachable
echo "Enabling IPSET..."
ipset restore < /etc/ipset-blacklist/ip-blacklist.restore
$IPT -I INPUT 1 -i $IFACE -m set --match-set blacklist src -j LOG --log-prefix "iptables IP Blacklist: "
$IPT -I INPUT 2 -i $IFACE -m set --match-set blacklist src -j DROP

# Allow SSH
echo "Allowing SSH... "
$IPT -A INPUT -i $IFACE -p tcp -s $ADMIN --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -o $IFACE -p tcp -d $ADMIN --sport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allows Inbound NEW DOS SSH Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
echo "Enabling DOS SSH atack prevention... "
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables SSH Attempt on port $SSHPORT: "
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j REJECT
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT

# Log and allow UrT
echo "Logging and allowing UrT connections..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -j LOG --log-prefix "iptables: UrT INC Connections: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o $IFACE -p udp -m multiport --sport $URTPORTS -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
echo "Enabling UrT DOS atack prevention..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables UrT Attack on port $URTPORTS: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j REJECT
$IPT -A INPUT -i $IFACE -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -j ACCEPT

# Drop all packets to port 111 except those from localhost
echo "Rejecting all packets to port 111 excecpt packets from localhost... "
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset

# kill off identd quick
echo "Killing identd..."
$IPT -A INPUT -i $IFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Don't log route packets coming from routers - too much logging
echo "Rejecting router's packets..."
$IPT -A INPUT -i $IFACE -p udp --dport 520 -j REJECT

# Don't log smb/windows sharing packets - too much logging
echo "Disabling logging smb packets..."
$IPT -A INPUT -i $IFACE -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -i $IFACE -p udp --dport 137:139 -j REJECT

# Drop INVALID packets
echo "Dropping INVALID packets... "
$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP

# Blocking excessive syn packet
echo "Blocking syn packets... "
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A SYN_FLOOD -j DROP

# LOGGING
echo "Creating LOGGING chain..."
$IPT -N LOGGING > /dev/null
$IPT -F LOGGING
$IPT -A INPUT -j LOGGING
$IPT -A OUTPUT -j LOGGING
$IPT -A LOGGING -p tcp -j LOG --log-prefix "iptables: tcp: "
$IPT -A LOGGING -p udp -j LOG --log-prefix "iptables: udp: "
$IPT -A LOGGING -p icmp -j LOG --log-prefix "iptables: icmp: "
$IPT -A LOGGING -p tcp -j REJECT --reject-with tcp-reset
$IPT -A LOGGING -p udp -j REJECT --reject-with icmp-port-unreachable
$IPT -A LOGGING -p icmp -j REJECT --reject-with icmp-port-unreachable
$IPT -A LOGGING -m limit --limit 1/min -j LOG --log-level 4
$IPT -A LOGGING -j DROP

# Block
# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
echo "Blocking reserved ip addresses... "
$IPT -A INPUT -i $IFACE -s 1.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 2.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 5.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 7.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 10.0.0.0/8 -j LOGGING

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A INPUT -i eth0 -s 23.0.0.0/8 -j DUMP
echo "Blocking US commercial IP... "
$IPT -A INPUT -i $IFACE -s 27.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 31.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 36.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 39.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 41.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 42.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 58.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 59.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 60.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 127.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 169.254.0.0/16 -j LOGGING
$IPT -A INPUT -i $IFACE -s 172.16.0.0/12 -j LOGGING
$IPT -A INPUT -i $IFACE -s 192.168.0.0/16 -j LOGGING
$IPT -A INPUT -i $IFACE -s 197.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 224.0.0.0/3 -j LOGGING
$IPT -A INPUT -i $IFACE -s 240.0.0.0/8 -j LOGGING

# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IPT -A OUTPUT -o $IFACE -d 1.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 2.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 5.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 7.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 10.0.0.0/8 -j LOGGING

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A OUTPUT -o eth0 -d 23.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o $IFACE -d 27.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 31.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 36.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 39.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 41.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 42.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 58.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 59.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 60.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 127.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 169.254.0.0/16 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 172.16.0.0/12 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 192.168.0.0/16 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 197.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 224.0.0.0/3 -j LOGGING
$IPT -A OUTPUT -o $IFACE -d 240.0.0.0/8 -j LOGGING

# All policies set to DROP
echo "Setting up DROP policy..."
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP

## Uncomment to test new firewall rules
#sleep 60 && sh -c /home/chuck/bin/killgual.sh
