#!/bin/sh
# SSH Port ez customization
# Admin IP ez customization
# Ez testing rules without locking you out of your vps :p
# Statefull
# Allows UrT INC and OUT packets
# Allows Ubuntu's repositorie (by ez modification to allow your distro's repos)
# Allows Local Loopback
# Allows DNS Query and Response
# Allows retriving bad boys IPs from well known hosts like Firehol
# IPSET Blocklist Support
# Blocks and bans port scanners
# Blocks bad source
# Blocks non local Loopback
# Blocks spoofed/invalid packets
# Blocks Smurf attacks
# LOG and Blocks DOS
# DOS SYN Flood
# DOS ICMP
# DOS SSH
# Logging blocked packages

IPT=/sbin/iptables
IFACE="ens3"
ADMIN="181.21.0.0/16"
SSHPORT="44555"
DNS_SERVER="108.61.10.10"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
IPSET_HOSTS="104.16.37.47,104.16.38.47,104.20.4.21,104.20.5.21,138.201.14.212,151.101.4.133,185.21.103.31,188.40.39.38,199.188.221.36,208.70.186.167,209.124.55.40"
URTPORTS="1337,1339"
AUTH_MASTER_PORTS="27952,27900"
TCP_SERVICES="53,44555"
UDP_SERVICES="53,68,1337,1339"

echo "Enabling Firewall..."

# IPv4 rules

# Loopback rules
echo "\e[32mEnabling \e[33mloopback rules..."
$IPT -A INPUT -i lo -j ACCEPT -m comment --comment "Loopback interface"
$IPT -A INPUT -i !lo -d 127.0.0.0/8 -j REJECT -m comment --comment "Loopback interface"
$IPT -A OUTPUT -o lo -j ACCEPT -m comment --comment "Loopback interface"
$IPT -A OUTPUT -o !lo -d 127.0.0.0/8 -j REJECT -m comment --comment "Loopback interface"

# This should be one of the first rules, so dns lookups are already allowed for your other rules
# Allow outgoing DNS queries
echo "\e[32mAllowing \e[33mDNS lookups (tcp, udp port 53) to server \e[32m'$DNS_SERVER'..."
for ip in $DNS_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "OUT udp DNS Lookups"
	$IPT -A INPUT -i $IFACE -p udp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "INC udp DNS Lookups"
	$IPT -A OUTPUT -o $IFACE -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "OUT tcp DNS Lookups"
	$IPT -A INPUT -i $IFACE -p tcp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "INC tcp DNS Lookups"

done

# This should be one of the first rules, so dns lookups are already allowed for your other rules
# Allow incomming DNS queries
echo "\e[32mAllowing \e[33mDNS lookups (tcp, udp port 53) to server \e[32m'$DNS_SERVER'..."
for ip in $DNS_SERVER
do
	$IPT -A INPUT -i $IFACE -p udp -s $ip --sport 53 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "INC udp DNS Lookups"
	$IPT -A OUTPUT -o $IFACE -p udp -d $ip --dport 53 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "OUT udp DNS Lookups"
	$IPT -A INPUT -i $IFACE -p tcp -s $ip --sport 53 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "INC tcp DNS Lookups"
	$IPT -A OUTPUT -o $IFACE -p tcp -d $ip --dport 53 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "OUT tcp DNS Lookups"
done

# Allowing repositories
echo "\e[32mEnabling \e[33mRepositories..."
for repositories in $PACKAGE_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$repositories" -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "Repositories"
	$IPT -A INPUT -i $IFACE -p tcp -s "$repositories" -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "Repositories"
done

# Allowing IPSET hosts to retrieve bad guys IP's
echo "\e[32mEnabling \e[33mIPSET hosts..."
for hosts in $IPSET_HOSTS
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$IPSET_HOSTS" -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "IPSET hosts"
	$IPT -A INPUT -i $IFACE -p tcp -s "$IPSET_HOSTS" -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT -m comment --comment "IPSET hosts"
done

# Admin IPs Version 2
echo "\e[32mEnabling \e[33madmin's IP..."
$IPT -A INPUT -s $ADMIN -j ACCEPT -m comment --comment "Admin's IP"
$IPT -A OUTPUT -d $ADMIN -j ACCEPT -m comment --comment "Admin's IP"

# Enable IPSET blacklists - logs blocked attempts and drop packets
echo "\e[32mEnabling \e[33mIPSET..."
ipset restore < /etc/ipset-blacklist/ip-blacklist.restore
$IPT -I INPUT 7 -i $IFACE -m set --match-set blacklist src -j LOG --log-prefix "iptables IPset Blacklists: "
$IPT -I INPUT 8 -i $IFACE -m set --match-set blacklist src -j DROP -m comment --comment "DROP IPset Blacklists"

# LOG and DROP script kiddies scanning ports
echo "\e[32mActivating \e[33mport scanner detector..."
ipset -N bad_guys iphash
$IPT -I INPUT 9 -i $IFACE -p tcp -m set --match-set bad_guys src -j LOG --log-prefix "iptables IPset tcp port scan"
$IPT -I INPUT 10 -i $IFACE -p udp -m set --match-set bad_guys src -j LOG --log-prefix "iptables IPset udp port scan"
$IPT -I INPUT 11 -i $IFACE -p tcp -m multiport ! --dports $TCP_SERVICES -m conntrack --ctstate NEW -j SET --add-set bad_guys src -m comment --comment "Port scanner"
$IPT -I INPUT 12 -i $IFACE -p udp -m multiport ! --dports $UDP_SERVICES -j SET --add-set bad_guys src -m comment --comment "Port scanner"
$IPT -I INPUT 13 -m set --match-set bad_guys src -j DROP -m comment --comment "DROP port scanner"

# Stateful table
echo "\e[33mMaking \e[33mthe firegual statefull..."
$IPT -N STATEFUL > /dev/null
$IPT -F STATEFUL
$IPT -I STATEFUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Statefull"
$IPT -A STATEFUL -m conntrack --ctstate NEW -i !eth0 -j ACCEPT -m comment --comment "Statefull"
#$IPT -A STATEFUL -j LOG --log-prefix "iptables stateful LOG: "

# Allow SSH
echo "\e[32mAllowing \e[33mSSH... "
$IPT -A INPUT -i $IFACE -p tcp -s $ADMIN --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "ACCEPT SSH"
$IPT -A OUTPUT -o $IFACE -p tcp -d $ADMIN --sport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "ACCEPT SSH"

# Allows Inbound NEW DOS SSH Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
echo "\e[32mEnabling \e[33mDOS SSH \e[31matack \e[33mprevention... "
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 10/m --log-prefix "iptables LOG SSH Attempt: "
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j DROP -m comment --comment "SSH DROP DOS "
$IPT -A INPUT -i $IFACE -p tcp -m tcp --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "ACCEPT SSH "

# Log and allow UrT
echo "\e[36mLogging \e[33mand \e[32mallowing \e[33mUrT connections..."
#$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m limit --limit 10/sec --limit-burst 5 -j LOG --log-level 7 --log-prefix "iptables LOG UrT Connections: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -j ACCEPT -m comment --comment "ACCEPT INC UrT"
$IPT -A OUTPUT -o $IFACE -p udp -m multiport --sports $URTPORTS -j ACCEPT -m comment --comment "ACCEPT OUT UrT"

echo "\e[32mAllowing \e[33mauth and masterlist..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --sports $AUTH_MASTER_PORTS -j ACCEPT -m comment --comment "INC UrT Auth and Master"
$IPT -A OUTPUT -o $IFACE -p udp -m multiport --dports $AUTH_MASTER_PORTS -j ACCEPT -m comment --comment "OUT UrT Auth and Master"

echo "\e[31mDROP \e[33mGameservers"
$IPT -A INPUT -i $IFACE -p udp --sport 27960 -j DROP -m comment --comment "DROP INC GameServers"
#$IPT -A OUTPUT -o $IFACE -p udp --dport 27960 -j ACCEPT -m comment --comment "Allow OUT packets GameServers"

# Attack prevention (only 3 attempts by an IP every 3 minutes, drop the rest)
# The ACCEPT at the end is necessary or, it wouldn't accept any connection
echo "\e[32mEnabling \e[33mUrT DOS \e[31matack \e[33mprevention..."
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --set --name DEFAULT --rsource
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j LOG -m limit --limit 10/s --log-prefix "iptables UrT Attack on port $URTPORTS: "
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -m recent --update --seconds 180 --hitcount 3 --name DEFAULT --rsource -j DROP -m comment --comment "UrT DOS prevention"
$IPT -A INPUT -i $IFACE -p udp -m multiport --dports $URTPORTS -m conntrack --ctstate NEW -j ACCEPT

# Drop all packets to port 111 except those from localhost
echo "\e[31mRejecting \e[33mall packets to port 111 excecpt packets from \e[32mlocalhost... "
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset -m comment --comment "Reject Spoof"

# kill off identd quick
echo "\e[31mKilling identd..."
$IPT -A INPUT -i $IFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset -m comment --comment "Reject identd"

# Don't log route packets coming from routers - too much logging
echo "\e[31mRejecting \e[33mrouter's packets..."
$IPT -A INPUT -p udp --dport 520 -j REJECT -m comment --comment "Reject router packets"

# Don't log smb/windows sharing packets - too much logging
echo "\e[31mDisabling \e[36mlogging \e[33msmb packets..."
$IPT -A INPUT -i $IFACE -p tcp --dport 137:139 -j REJECT -m comment --comment "Reject smb"
$IPT -A INPUT -i $IFACE -p udp --dport 137:139 -j REJECT -m comment --comment "Reject smb"

# Blocking excessive syn packet
echo "\e[31mBlocking \e[33msyn packets..."
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPT -A SYN_FLOOD -j DROP -m comment --comment "Block excessive syn"

# Stop smurf attacks
echo "\e[32mEnabling \e[33msmurf \e[31mattack \e[33mdetector..."
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type address-mask-request -j DROP -m comment --comment "Block smurf attacks"
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type timestamp-request -j DROP -m comment --comment "Block smurf attacks"
$IPT -A INPUT -i $IFACE -p icmp -m icmp -j DROP

# Drop excessive RST packets to avoid smurf attacks
$IPT -A INPUT -i $IFACE -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT -m comment --comment "Block smurf attacks"

# Drop INVALID packets
echo "\e[31mDropping \e[33mINVALID packets... "
$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP -m comment --comment "Drop INVALID packets"
$IPT -A OUTPUT -m conntrack --ctstate INVALID -j DROP -m comment --comment "Drop INVALID packets"
$IPT -A FORWARD -m conntrack --ctstate INVALID -j DROP -m comment --comment "Drop INVALID packets"

# LOGGING
echo "\e[33mCreating \e[36mLOGGING chain..."
$IPT -N LOGGING > /dev/null
$IPT -F LOGGING
$IPT -A INPUT -j LOGGING
$IPT -A OUTPUT -j LOGGING
$IPT -A LOGGING -p tcp -j LOG --log-prefix "iptables LOGGING tcp: "
$IPT -A LOGGING -p udp -j LOG --log-prefix "iptables LOGGING udp: "
$IPT -A LOGGING -p icmp -j LOG --log-prefix "iptables LOGGING icmp: "
$IPT -A LOGGING -m limit --limit 1/s -j LOG --log-level 4
$IPT -A LOGGING -p tcp -j DROP -m comment --comment "LOGGING"
$IPT -A LOGGING -p udp -j DROP -m comment --comment "LOGGING"
$IPT -A LOGGING -p icmp -j DROP -m comment --comment "LOGGING"
$IPT -A LOGGING -j DROP

# Send spoofed packers to the LOGGING chain tobe processed and then droped
echo "\e[32mEnabliing \e[33mSpoof \e[31mattack \e[33mdetector..."

# These adresses are mostly used for LAN's, so if these would come to a WAN-only server, drop them
$IPT -A INPUT -i $IFACE -s 10.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP LAN Spoof"
$IPT -A INPUT -i $IFACE -s 127.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP LAN Spoof"
$IPT -A INPUT -i $IFACE -s 169.254.0.0/16 -j LOGGING -m comment --comment "LOG and DROP LAN Spoof"
$IPT -A INPUT -i $IFACE -s 172.16.0.0/12 -j LOGGING -m comment --comment "LOG and DROP LAN Spoof"
$IPT -A INPUT -i $IFACE -s 192.168.0.0/16 -j LOGGING -m comment --comment "LOG and DROP LAN Spoof"

# Multicast-addresses
$IPT -A INPUT -i $IFACE -s 0.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -d 0.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -s 224.0.0.0/4 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -d 224.0.0.0/4 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -s 240.0.0.0/5 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -d 240.0.0.0/5 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -d 239.255.255.0/24 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"
$IPT -A INPUT -i $IFACE -d 255.255.255.255 -j LOGGING -m comment --comment "LOG and DROP multicast-addresses Spoof"

# Reserved adresses and US comercial ips
$IPT -A INPUT -i $IFACE -s 1.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 2.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 5.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 7.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 27.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 31.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 36.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 39.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 41.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 42.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 58.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 59.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 60.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"
$IPT -A INPUT -i $IFACE -s 197.0.0.0/8 -j LOGGING -m comment --comment "LOG and DROP reserved adresses Spoof"

# All policies set to DROP
echo "\e[33mSetting up \e[31mDROP \e[33mpolicy..."
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD DROP

## Uncomment to test new firewall rules
#sleep 60 && sh -c /home/chuck/bin/killgual.sh
