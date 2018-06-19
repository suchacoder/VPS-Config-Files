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
ADMIN="181.21.0.0/16"
SSHPORT="4455"
DNS_SERVER="8.8.4.4 8.8.8.8"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
URTPORTS="1337,1338,1339"

echo "Enabling Firewall..."

# IPv4 rules

# Loopback rules
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -i !lo -d 127.0.0.0/8 -j REJECT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A OUTPUT -o !lo -d 127.0.0.0/8 -j REJECT

# This should be one of the first rules.
# so dns lookups are already allowed for your other rules
for ip in $DNS_SERVER
do
	echo "Allowing DNS lookups (tcp, udp port 53) to server '$ip'"
	$IPT -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p udp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
	$IPT -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
done

# Allowing repositories
for ip in $PACKAGE_SERVER
do
	echo "Allow connection to '$ip' on port 80"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 80  -m state --state ESTABLISHED     -j ACCEPT

	echo "Allow connection to '$ip' on port 443"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 443 -m state --state ESTABLISHED     -j ACCEPT
done

# LOGGING
$IPT -N LOGGING > /dev/null
$IPT -F LOGGING
$IPT -A LOGGING -p tcp -j LOG --log-prefix "iptables: tcp: "
$IPT -A LOGGING -p udp -j LOG --log-prefix "iptables: udp: "
$IPT -A LOGGING -p icmp -j LOG --log-prefix "iptables: icmp: "
$IPT -A LOGGING -p tcp -j REJECT --reject-with tcp-reset
$IPT -A LOGGING -p udp -j REJECT --reject-with icmp-port-unreachable
$IPT -A LOGGING -p icmp -j REJECT --reject-with icmp-port-unreachable
$IPT -A LOGGING -j DROP

# Stateful table
$IPT -N STATEFUL > /dev/null
$IPT -F STATEFUL
$IPT -I STATEFUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A STATEFUL -m conntrack --ctstate NEW -i !eth0 -j ACCEPT
$IPT -A STATEFUL -j LOGGING

# Blocking excessive syn packet
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A SYN_FLOOD -j DROP

# Admin IPs Version 2
$IPT -A INPUT -s $ADMIN -j ACCEPT
$IPT -A OUTPUT -d $ADMIN -j ACCEPT

# Allow SSH
$IPT -A INPUT -i eth0 -p tcp -m tcp -s $ADMIN --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -o eth0 -p tcp -m tcp -d $ADMIN --sport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Enable IPSET blacklists - logs blocked attempts and responds with port unreachable
ipset restore < /etc/ipset-blacklist/ip-blacklist.restore
$IPT -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "IP Blacklist: "
$IPT -A INPUT -m set --match-set blacklist src -j REJECT --reject-with icmp-port-unreachable
#iptables -I INPUT 1 -m set --match-set blacklist src -j DROP

# IPSET Output Blocklist - allows reject packet to be sent with no log but no further communication
$IPT -A OUTPUT -m set --match-set blacklist dst -p icmp --icmp-type port-unreachable -j ACCEPT
$IPT -A OUTPUT -m set --match-set blacklist dst -j LOG --log-prefix "IP Blacklist: "
$IPT -A OUTPUT -m set --match-set blacklist dst -j REJECT --reject-with icmp-port-unreachable

# Allow UrT
$IPT -A INPUT -i eth0 -p udp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p udp -m multiport --sport $URTPORTS -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# Block
# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IPT -A INPUT -i eth0 -s 0.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 1.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 2.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 5.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 7.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 10.0.0.0/8 -j LOGGING

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A INPUT -i eth0 -s 23.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 27.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 31.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 36.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 39.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 41.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 42.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 58.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 59.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 60.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 127.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 169.254.0.0/16 -j LOGGING
$IPT -A INPUT -i eth0 -s 172.16.0.0/12 -j LOGGING
$IPT -A INPUT -i eth0 -s 192.168.0.0/16 -j LOGGING
$IPT -A INPUT -i eth0 -s 197.0.0.0/8 -j LOGGING
$IPT -A INPUT -i eth0 -s 224.0.0.0/3 -j LOGGING
$IPT -A INPUT -i eth0 -s 240.0.0.0/8 -j LOGGING

# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IPT -A OUTPUT -o eth0 -d 0.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 1.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 2.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 5.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 7.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 10.0.0.0/8 -j LOGGING

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A OUTPUT -o eth0 -d 23.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 27.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 31.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 36.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 39.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 41.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 42.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 58.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 59.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 60.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 127.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 169.254.0.0/16 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 172.16.0.0/12 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 192.168.0.0/16 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 197.0.0.0/8 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 224.0.0.0/3 -j LOGGING
$IPT -A OUTPUT -o eth0 -d 240.0.0.0/8 -j LOGGING

# Drop all packets to port 111 except those from localhost
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset

# kill off identd quick
$IPT -A INPUT -i eth0 -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Allows Inbound NEW DOS SSH Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables: SSH Attempt on port $SSHPORT : "
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j REJECT
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT

# Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
$IPT -A INPUT -i eth0 -p tcp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i eth0 -p tcp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables: UrT Attack on port $URTPORTS : "
$IPT -A INPUT -i eth0 -p tcp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j REJECT
$IPT -A INPUT -i eth0 -p tcp -m multiport --dport $URTPORTS -m conntrack --ctstate NEW -j ACCEPT

# Don't log route packets coming from routers - too much logging
$IPT -A INPUT -i eth0 -p udp --dport 520 -j REJECT

# Don't log smb/windows sharing packets - too much logging
$IPT -A INPUT -i eth0 -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -i eth0 -p udp --dport 137:139 -j REJECT

# All policies set to DROP
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP

# Outbound for NEW SSH
#$IPT -A OUTPUT -o eth0 -p tcp --dport $SSHPORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Inbound ESTABLISHED SSH
#$IPT -A INPUT -i eth0 -p tcp --sport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# DOS HTTP Attack prevention
# Need re-evaluation, the current rates do not allow for WordPress image upload features
# Plus, the timings reportedly slows down current site browsing to an unusable level - hence the commented out "DROP"
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode srcip --hashlimit-name http -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode srcip --hashlimit-name https -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT

# Outbound HTTP, and HTTPS
#$IPT -A OUTPUT -o eth0 -p tcp --dport 80 --sport 1024:65535 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 1024:65535 --sport 80 -j ACCEPT
#$IPT -A OUTPUT -o eth0 -p tcp --dport 443 --sport 1024:65535 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 1024:65535 --sport 443 -j ACCEPT

# Inbound SMTP
#$IPT -A INPUT -i eth0 -p tcp --sport 1024:65535 --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUPUT -o eth0 -p tcp --sport 25 --dport 1024:65535 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Outbound SMTP
#$IPT -A INPUT -i eth0 -p tcp --sport 25 --dport 1024:65535 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -o eth0 -p tcp --sport 1024:65535 --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Allow rsync from a specific network
#$IPT -A INPUT -i eth0 -p tcp -s 192.168.101.0/24 --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -o eth0 -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow SVN
#$IPT -A INPUT -i eth0 -p tcp --dport 3690 --sport 1024:65535 -j ACCEPT
#$IPT -A OUTPUT -o eth0 -p tcp --sport 3690 --dport 1024:65535 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 3667 --sport 1024:65535 -j ACCEPT
#$IPT -A OUTPUT -o eth0 -p tcp --sport 3667 --dport 1024:65535 -j ACCEPT

# Allow all related
#$IPT -A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

## Uncomment to test new firewall rules
#sleep 120 && sh -c /home/chuck/bin/killgual.sh
