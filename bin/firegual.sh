#!/bin/sh
# Jim McKibben
# 2015-01-11
# Version 2.6.2
# Iptables Firewall configuration script
# Allows HTTP, HTTPS, SSH, SMTP
# SSH Port easy customization
# Allows Local Loopback
# Allows specific ICMP
# Allows DNS Query and Response
# Blocks bad source
# Blocks non local Loopback
# DOS Protection and reporting
# DOS SYN Flood
# DOS ICMP
# Report logged HTTPs usage - HTTPs IPv6 disabled
# DOS SSH
# Logging
# Admin IP / Monitoring Section
# IPv6 support
# IPSET Blocklist Support
# Fixed SRC/DST Admin
# Allowed blocklist response

IPT=/sbin/iptables
IP6T=/sbin/ip6tables
ADMIN="0.0.0.0"
ADMINSUBNET01="0.0.0.0/32"
SSHPORT="4455"

echo "Enabling Firewall"

# IPv4 rules

# Specialty IPs
# These IPs will be allowed to ping
# They won't have to worry about DDoS rulesets
#$IPT -N ADMIN_IP
#$IPT -A ADMIN_IP -p tcp -m multiport --sports $SSHPORT,25,80,443,10050,10051 -j ACCEPT
#$IPT -A ADMIN_IP -p tcp -m multiport --dports $SSHPORT,25,80,443,10050,10051 -j ACCEPT
#$IPT -A ADMIN_IP -i eth0 -p icmp --icmp-type destination-unreachable -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPT -A ADMIN_IP -i eth0 -p icmp --icmp-type time-exceeded -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPT -A ADMIN_IP -i eth0 -p icmp --icmp-type echo-reply -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPT -A ADMIN_IP -i eth0 -p icmp --icmp-type echo-request -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPT -A ADMIN_IP -i eth0 -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "iptables: PING-DROP: "
#$IPT -A ADMIN_IP -i eth0 -p icmp -j DROP

# Loopback rules
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -i !lo -d 127.0.0.0/8 -j REJECT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A OUTPUT -o !lo -d 127.0.0.0/8 -j REJECT

# DUMP
$IPT -N DUMP > /dev/null
$IPT -F DUMP
$IPT -A DUMP -p tcp -j LOG --log-prefix "iptables: tcp: "
$IPT -A DUMP -p udp -j LOG --log-prefix "iptables: udp: "
$IPT -A DUMP -p tcp -j REJECT --reject-with tcp-reset
$IPT -A DUMP -p udp -j REJECT --reject-with icmp-port-unreachable
$IPT -A DUMP -j DROP

# Stateful table
$IPT -N STATEFUL > /dev/null
$IPT -F STATEFUL
$IPT -I STATEFUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A STATEFUL -m conntrack --ctstate NEW -i !eth0 -j ACCEPT
$IPT -A STATEFUL -j DUMP

# Blocking excessive syn packet
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A SYN_FLOOD -j DROP

# Admin IPs Version 2
$IPT -A INPUT -s $ADMIN -j ACCEPT
$IPT -A OUTPUT -d $ADMIN -j ACCEPT
$IPT -A INPUT -s $ADMINSUBNET01 -j ACCEPT
$IPT -A OUTPUT -d $ADMINSUBNET01 -j ACCEPT

# Allow SSH
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport 4455 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p tcp -m tcp --sport 4455 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Enable blacklists
ipset restore < /etc/ipset-blacklist/ip-blacklist.restore
iptables -I INPUT 1 -m set --match-set blacklist src -j DROP

# IPSET Input Blocklist - logs block and responds with port unreachable
#$IPT -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "IP Blacklist: "
#$IPT -A INPUT -m set --match-set blacklist src -j REJECT --reject-with icmp-port-unreachable

# IPSET Output Blocklist - allows reject packet to be sent with no log but no further communication
#$IPT -A OUTPUT -m set --match-set blacklist dst -p icmp --icmp-type port-unreachable -j ACCEPT
#$IPT -A OUTPUT -m set --match-set blacklist dst -j LOG --log-prefix "IP Blacklist: "
#$IPT -A OUTPUT -m set --match-set blacklist dst -j REJECT --reject-with icmp-port-unreachable

# Allow inbound DNS
$IPT -A INPUT -i eth0 -p udp --sport 1024:65535 --dport 53 -j ACCEPT
$IPT -A OUTPUT -p udp --sport 53 --dport 1024:65535 -j ACCEPT

# Allow UrT

$IPT -A INPUT -i eth0 -p udp -m multiport --dport 1337,1338,1339 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o eth0 -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p udp -m multiport --sport 1337,1338,1339 --dport 27900 -j ACCEPT

# Block
# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IPT -A INPUT -i eth0 -s 0.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 1.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 2.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 5.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 7.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 10.0.0.0/8 -j DUMP

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A INPUT -i eth0 -s 23.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 27.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 31.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 36.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 39.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 41.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 42.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 58.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 59.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 60.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 127.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 169.254.0.0/16 -j DUMP
$IPT -A INPUT -i eth0 -s 172.16.0.0/12 -j DUMP
$IPT -A INPUT -i eth0 -s 192.168.0.0/16 -j DUMP
$IPT -A INPUT -i eth0 -s 197.0.0.0/8 -j DUMP
$IPT -A INPUT -i eth0 -s 224.0.0.0/3 -j DUMP
$IPT -A INPUT -i eth0 -s 240.0.0.0/8 -j DUMP

# drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IPT -A OUTPUT -o eth0 -d 0.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 1.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 2.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 5.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 7.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 10.0.0.0/8 -j DUMP

# Mostly US Commercial IP space, Google Fiber, and Business ISPs
#$IPT -A OUTPUT -o eth0 -d 23.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 27.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 31.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 36.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 39.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 41.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 42.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 58.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 59.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 60.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 127.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 169.254.0.0/16 -j DUMP
$IPT -A OUTPUT -o eth0 -d 172.16.0.0/12 -j DUMP
$IPT -A OUTPUT -o eth0 -d 192.168.0.0/16 -j DUMP
$IPT -A OUTPUT -o eth0 -d 197.0.0.0/8 -j DUMP
$IPT -A OUTPUT -o eth0 -d 224.0.0.0/3 -j DUMP
$IPT -A OUTPUT -o eth0 -d 240.0.0.0/8 -j DUMP

# Allow certain inbound ICMP types (ping, traceroute..)
$IPT -A INPUT -i eth0 -p icmp --icmp-type destination-unreachable -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IPT -A INPUT -i eth0 -p icmp --icmp-type time-exceeded -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IPT -A INPUT -i eth0 -p icmp --icmp-type echo-reply -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IPT -A INPUT -i eth0 -p icmp --icmp-type echo-request -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IPT -A INPUT -i eth0 -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "iptables: PING-DROP: "
$IPT -A INPUT -i eth0 -p icmp -j DROP

# Drop all packets to port 111 except those from localhost
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset

# kill off identd quick
$IPT -A INPUT -i eth0 -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Allow all established, related in
#$IPT -A INPUT -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allows Inbound NEW DOS SSH Attack prevention (only 4 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 
--hitcount 4 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables: SSH Attempt on port $SSHPORT : 
"
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 
--hitcount 4 --name DEFAULT --rsource -j REJECT
$IPT -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT

# Inbound ESTABLISHED SSH (out is in Multi-out)
$IPT -A INPUT -i eth0 -p tcp --dport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Multi-out for inbound SSH
$IPT -A OUTPUT -o eth0 -p tcp --sports $SSHPORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Outbound SSH
#$IPT -A OUTPUT -o eth0 -p tcp --dport $SSHPORT  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# DOS HTTP Attack prevention
# Need re-evaluation, the current rates do not allow for WordPress image upload features
# Plus, the timings reportedly slows down current site browsing to an unusable level - hence the commented out "DROP"
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode srcip 
--hashlimit-name http -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode 
srcip --hashlimit-name https -j ACCEPT
#$IPT -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT

# Allow Ping from Outside to Inside
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Allow outbound DNS
$IPT -A INPUT -i eth0 -p udp --dport 1024:65535 --sport 53 -j ACCEPT
$IPT -A OUTPUT -p udp --dport 53 --sport 1024:65535 -j ACCEPT

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

# Don't log route packets coming from routers - too much logging
$IPT -A INPUT -i eth0 -p udp --dport 520 -j REJECT

# Don't log smb/windows sharing packets - too much logging
$IPT -A INPUT -i eth0 -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -i eth0 -p udp --dport 137:139 -j REJECT

# All policies set to DROP
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP
#$IPT --policy ADMIN_IP DROP

# IPv6 rules

# Specialty IPs
# These IPs will be allowed to ping
# They won't have to worry about DDoS rulesets
#$IP6T -N ADMIN_IP
#$IP6T -A ADMIN_IP -p tcp -m multiport --sports $SSHPORT,25,80,443,10050,10051 -j ACCEPT
#$IP6T -A ADMIN_IP -p tcp -m multiport --dports $SSHPORT,25,80,443,10050,10051 -j ACCEPT
#$IP6T -A ADMIN_IP -i eth0 -p icmp --icmp-type destination-unreachable -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IP6T -A ADMIN_IP -i eth0 -p icmp --icmp-type time-exceeded -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IP6T -A ADMIN_IP -i eth0 -p icmp --icmp-type echo-reply -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IP6T -A ADMIN_IP -i eth0 -p icmp --icmp-type echo-request -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IP6T -A ADMIN_IP -i eth0 -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "iptables: PING-DROP: "
#$IP6T -A ADMIN_IP -i eth0 -p icmp -j DROP

# DUMP
$IP6T -N DUMP > /dev/null
$IP6T -F DUMP
$IP6T -A DUMP -p tcp -j LOG --log-prefix "ip6tables: tcp: "
$IP6T -A DUMP -p udp -j LOG --log-prefix "ip6tables: udp: "
$IP6T -A DUMP -p tcp -j REJECT --reject-with tcp-reset
$IP6T -A DUMP -p udp -j REJECT --reject-with icmp-port-unreachable
$IP6T -A DUMP -j DROP

# Add Admin IPs to INPUT Chain
#$IP6T -A INPUT -s $ADMINV6 -j ADMIN_IP
#$IP6T -A OUTPUT -d $ADMINV6 -j ADMIN_IP

# Blocking excessive syn packet
$IP6T -N SYN_FLOOD
$IP6T -A INPUT -p tcp --syn -j SYN_FLOOD
$IP6T -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IP6T -A SYN_FLOOD -j DROP

# Stateful table
$IP6T -N STATEFUL > /dev/null
$IP6T -F STATEFUL
$IP6T -I STATEFUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IP6T -A STATEFUL -m conntrack --ctstate NEW -i !eth0 -j ACCEPT
$IP6T -A STATEFUL -j DUMP

# Loopback rules
$IP6T -A INPUT -i lo -j ACCEPT
$IP6T -A INPUT -i !lo -d ::1 -j REJECT
$IP6T -A OUTPUT -o lo -j ACCEPT
$IP6T -A OUTPUT -o !lo -d ::1 -j REJECT

# Block
# Drop reserved addresses incoming (these are reserved addresses)
# but may change soon
$IP6T -A INPUT -i eth0 -s ::1 -j DUMP

# Drop reserved addresses outgoing (these are reserved addresses)
# but may change soon
$IP6T -A OUTPUT -o eth0 -d ::1 -j DUMP

# Allow certain inbound ICMP types (ping, traceroute..)
$IP6T -A INPUT -i eth0 -p icmp --icmp-type destination-unreachable -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IP6T -A INPUT -i eth0 -p icmp --icmp-type time-exceeded -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IP6T -A INPUT -i eth0 -p icmp --icmp-type echo-reply -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IP6T -A INPUT -i eth0 -p icmp --icmp-type echo-request -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IP6T -A INPUT -i eth0 -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "ip6tables: PING-DROP: "
$IP6T -A INPUT -i eth0 -p icmp -j DROP

# Drop all packets to port 111 except those from localhost
$IP6T -A INPUT ! -s ::1 -p tcp --dport 111 -j REJECT --reject-with tcp-reset

# kill off identd quick
$IP6T -A INPUT -i eth0 -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Allow all established, related in
#$IP6T -A INPUT -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allows Inbound NEW DOS SSH Attack prevention (only 4 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
#$IP6T -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
#$IP6T -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 
--hitcount 4 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "ip6tables: SSH Attempt on port $SSHPORT : 
"
#$IP6T -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 
--hitcount 4 --name DEFAULT --rsource -j REJECT
#$IP6T -A INPUT -i eth0 -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT

# Inbound ESTABLISHED SSH (out is in Multi-out)
#$IP6T -A INPUT -i eth0 -p tcp --dport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# DOS HTTP Attack prevention
# For this, no one seems to be using IPv6 for legitimet browsing, so, I've been disabling it
#$IP6T -A INPUT -i eth0 -p tcp --dport 80 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 80 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode 
srcip --hashlimit-name http -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 80 -j DROP
#$IP6T -A INPUT -i eth0 -p tcp --dport 443 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 443 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode 
srcip --hashlimit-name https -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 443 -j DROP

# Allow Ping from Outside to Inside
$IP6T -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Multi-out for inbound SSH, HTTP, and HTTPS
#$IP6T -A OUTPUT -o eth0 -p tcp -m multiport --sports $SSHPORT,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Outbound SSH
#$IP6T -A INPUT -i eth0 -p tcp --sport $SSHPORT  -m conntrack --ctstate ESTABLISHED -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --dport $SSHPORT  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Allow inbound DNS
$IP6T -A INPUT -i eth0 -p udp --sport 1024:65535 --dport 53 -j ACCEPT
$IP6T -A OUTPUT -p udp --sport 53 --dport 1024:65535 -j ACCEPT

# Allow outbound DNS
$IP6T -A INPUT -i eth0 -p udp --dport 1024:65535 --sport 53 -j ACCEPT
$IP6T -A OUTPUT -p udp --dport 53 --sport 1024:65535 -j ACCEPT

# Outbound HTTP, and HTTPS
#$IP6T -A OUTPUT -o eth0 -p tcp --dport 80 --sport 1024:65535 -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 1024:65535 --sport 80 -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --dport 443 --sport 1024:65535 -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 1024:65535 --sport 443 -j ACCEPT

# Inbound SMTP
#$IP6T -A INPUT -i eth0 -p tcp --sport 1024:65535 --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IP6T -A OUPUT -o eth0 -p tcp --sport 25 --dport 1024:65535 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Outbound SMTP
#$IP6T -A INPUT -i eth0 -p tcp --sport 25 --dport 1024:65535 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --sport 1024:65535 --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Allow rsync from a specific network
#$IP6T -A INPUT -i eth0 -p tcp -s 192.168.101.0/24 --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow SVN
#$IP6T -A INPUT -i eth0 -p tcp --dport 3690 --sport 1024:65535 -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --sport 3690 --dport 1024:65535 -j ACCEPT
#$IP6T -A INPUT -i eth0 -p tcp --dport 3667 --sport 1024:65535 -j ACCEPT
#$IP6T -A OUTPUT -o eth0 -p tcp --sport 3667 --dport 1024:65535 -j ACCEPT

# Allow all related
#$IP6T -A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Don't log route packets coming from routers - too much logging
$IP6T -A INPUT -i eth0 -p udp --dport 520 -j REJECT

# Don't log smb/windows sharing packets - too much logging
$IP6T -A INPUT -i eth0 -p tcp --dport 137:139 -j REJECT
$IP6T -A INPUT -i eth0 -p udp --dport 137:139 -j REJECT

# All policies set to DROP
$IP6T --policy INPUT DROP
$IP6T --policy OUTPUT DROP
$IP6T --policy FORWARD DROP
#$IP6T --policy ADMIN_IP DROP
