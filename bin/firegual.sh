#!/bin/sh
# SSH Port easy customization
# Allows Local Loopback
# Allows DNS Query and Response
# Blocks bad source
# Blocks non local Loopback
# Blocks port scanners
# Blocks spoofed/invalid packets
# Blocks Smurf attacks
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
DNS_SERVER="108.61.10.10"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
IPSET_HOSTS="104.16.37.47,104.16.38.47,104.20.4.21,104.20.5.21,138.201.14.212,151.101.4.133,185.21.103.31,188.40.39.38,199.188.221.36,208.70.186.167,209.124.55.40"
URTPORTS="1337,1339"
AUTH_MASTER_PORTS="27952,27900"

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
for repositories in $PACKAGE_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$repositories" -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $IFACE -p tcp -s "$repositories" -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
done

# Allowing IPSET hosts
echo "Enabling IPSET hosts..."
for hosts in $IPSET_HOSTS
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$IPSET_HOSTS" -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT -i $IFACE -p tcp -s "$IPSET_HOSTS" -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
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
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j DROP
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT

# Log and allow UrT
echo "Logging and allowing UrT connections..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -j LOG --log-prefix "iptables: UrT Connections: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -j ACCEPT
$IPT -A OUTPUT -o $IFACE -p udp -m multiport --sports $URTPORTS -j ACCEPT

echo "Allowing auth and masterlist..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --sports $AUTH_MASTER_PORTS -j ACCEPT
$IPT -A OUTPUT -o $IFACE -p udp -m multiport --dports $AUTH_MASTER_PORTS -j ACCEPT

echo "Deny Gameservers"
$IPT -A INPUT -i $IFACE -p udp --sport 27960 -j DROP

# Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
echo "Enabling UrT DOS atack prevention..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 20/m --log-prefix "iptables UrT Attack on port $URTPORTS: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j DROP
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -j ACCEPT

# Drop all packets to port 111 except those from localhost
echo "Rejecting all packets to port 111 excecpt packets from localhost... "
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset

# kill off identd quick
echo "Killing identd..."
$IPT -A INPUT -i $IFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Don't log route packets coming from routers - too much logging
echo "Rejecting router's packets..."
$IPT -A INPUT -p udp --dport 520 -j REJECT

# Don't log smb/windows sharing packets - too much logging
echo "Disabling logging smb packets..."
$IPT -A INPUT -i $IFACE -p tcp --dport 137:139 -j REJECT
$IPT -A INPUT -i $IFACE -p udp --dport 137:139 -j REJECT

# Blocking excessive syn packet
echo "Blocking syn packets..."
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A SYN_FLOOD -j DROP

# Stop smurf attacks
echo "Enabling smurf attack detector..."
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type address-mask-request -j DROP
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IPT -A INPUT -i $IFACE -p icmp -m icmp -j DROP

# Drop excessive RST packets to avoid smurf attacks
$IPT -A INPUT -i $IFACE -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

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

# Send spoofed packers to the LOGGING chain tobe processed and then droped
echo "Enabliing Spoof attack detector..."

# These adresses are mostly used for LAN's, so if these would come to a WAN-only server, drop them
$IPT -A INPUT -i $IFACE -s 10.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 127.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 169.254.0.0/16 -j LOGGING
$IPT -A INPUT -i $IFACE -s 172.16.0.0/12 -j LOGGING
$IPT -A INPUT -i $IFACE -s 192.168.0.0/16 -j LOGGING

# Multicast-adresses
$IPT -A INPUT -i $IFACE -s 0.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -d 0.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 224.0.0.0/4 -j LOGGING
$IPT -A INPUT -i $IFACE -d 224.0.0.0/4 -j LOGGING
$IPT -A INPUT -i $IFACE -s 240.0.0.0/5 -j LOGGING
$IPT -A INPUT -i $IFACE -d 240.0.0.0/5 -j LOGGING
$IPT -A INPUT -i $IFACE -d 239.255.255.0/24 -j LOGGING
$IPT -A INPUT -i $IFACE -d 255.255.255.255 -j LOGGING

# Reserved adresses and US comercial ips
$IPT -A INPUT -i $IFACE -s 1.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 2.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 5.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 7.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 27.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 31.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 36.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 39.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 41.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 42.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 58.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 59.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 60.0.0.0/8 -j LOGGING
$IPT -A INPUT -i $IFACE -s 197.0.0.0/8 -j LOGGING

# Drop INVALID packets
echo "Dropping INVALID packets... "
$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP
$IPT -A OUTPUT -m conntrack --ctstate INVALID -j DROP
$IPT -A FORWARD -m conntrack --ctstate INVALID -j DROP

# All policies set to DROP
echo "Setting up DROP policy..."
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP

## Uncomment to test new firewall rules
#sleep 60 && sh -c /home/chuck/bin/killgual.sh
