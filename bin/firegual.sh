#!/bin/sh

echo "\e[32m     .                     s                    ..         ..             .x+=:."
echo "\e[31m    @88>                  :8              . uW8"       "d88"                    ""
echo "\e[33m    %8P   .d             .88               t888       5888R                 .   <k"
echo "\e[34m     .    @8Ne.   .u    :888ooo      u     8888   .   '888R       .u      .@8Ned8"
echo "\e[35m   .@88u  %8888:u@88N -*8888888   us888u.  9888.z88N   888R    ud8888.  .@^%8888"
echo "\e[36m  ''888E    888I  888.  8888   .@88  8888  9888  888E  888R  :888'8888.x88:   )8b."
echo "\e[37m    888E    888I  888I  8888   9888  9888  9888  888E  888R  d888 '88%8888N=*8888"
echo "\e[31m    888E    888I  888I  8888   9888  9888  9888  888E  888R  8888.+     %8"   "R88"
echo "\e[32m    888E  uW888L  888' .8888Lu=9888  9888  9888  888E  888R  8888L       @8Wou 9%"
echo "\e[33m    888E  ""88888Nu88P  88888  9888  9888  8888  888   888B  8888c        88888P"
echo "\e[34m    R888"   "88888F       Y"   "888*""888"  "%888*"    "*888%  88888%      ^F"
echo "\e[35m     ""      888 ^              ^Y"   "Y"     "         %"      "YP'"
echo "\e[36m             *8E"
echo "\e[37m              8>                                       \e[33mFun*T|Chuck <leanhack@gmail.com>"

# SSH Port ez customization
# Admin IP ez customization
# Ez testing rules without locking you out of your vps :p
# Statefull
# Allows Ubuntu's repositorie (by ez modification to allow your distro's repos)
# Allows Local Loopback
# Allows DNS Query and Response
# Allows retriving bad boys IPs from well known hosts like Firehol
# Allows SSH
# Allows UrT INC and OUT packets
# Allows Teamspeak
# Allows HTTP
# IPSET Blocklist Support
# Rate limiting per IP
# Blocks and bans port scanners
# Blocks bad source
# Blocks non local Loopback
# Blocks spoofed/invalid packets
# Blocks Smurf attacks
# LOG and Blocks DOS
# DOS SYN Flood
# DOS ICMP
# DOS SSH
# DOS HTTP
# Allow rsync from a specific network
# Logging blocked packages

# Executables
IPT=$(which iptables)
IPT6=$(which ip6tables)
IPSET=$(which ipset)

# VARs
IFACE="eth0"
ADMIN="181.191.0.0/16"
SSHPORT="4949"
OPENVPNPORT="1194"
DNS_SERVER="204.152.204.100,204.152.204.10"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
IPSET_HOSTS="104.16.37.47,104.16.38.47,104.20.4.21,104.20.5.21,138.201.14.212,151.101.4.133,185.21.103.31,188.40.39.38,199.188.221.36,208.70.186.167,209.124.55.40"
TCP_SERVICES="4949"
UDP_SERVICES="1194"
#HTTP_PORTS="80,443"
#WIREGUARDPORT="51820"

echo "\e[32mEnabling Firewall..."

# Flush old rules, custom tables and sets
#echo "\e[32mFlushing old rules, tables and sets..."
#$IPT -F
#$IPT -X
#$IPT -t nat -F
#$IPT -t nat -X
#$IPT -t mangle -F
#$IPT -t mangle -X
#$IPT -t raw -F
#$IPT -t raw -X
#$IPT -t security -F
#$IPT -t security -X
#$IPSET -F
#$IPSET -X

# IPv4 rules

# Loopback rules
echo "\e[32mEnabling \e[33mloopback rules..."
$IPT -A INPUT -i lo -j ACCEPT -m comment --comment "LOOPBACK INTERFACE"
$IPT -A INPUT -i !lo -d 127.0.0.0/8 -j REJECT -m comment --comment "LOOPBACK INTERFACE"
$IPT -A OUTPUT -o lo -j ACCEPT -m comment --comment "LOOPBACK INTERFACE"
$IPT -A OUTPUT -o !lo -d 127.0.0.0/8 -j REJECT -m comment --comment "LOOPBACK INTERFACE"

# Stateful table
echo "\e[33mMaking \e[33mthe firegual statefull..."
$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "STATEFULL"

# This should be one of the first rules, so dns lookups are already allowed for your other rules
# Allow outgoing DNS queries
echo "\e[32mAllowing \e[33m OUT DNS lookups (udp port 53) to server \e[32m'$DNS_SERVER'..."
for ip in $DNS_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p udp -d $ip --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "OUT UDP DNS LOOKUPS"
	$IPT -A INPUT -i $IFACE -p udp -s $ip --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "INC UDP DNS LOOKUPS"
done

# Allowing repositories
echo "\e[32mEnabling \e[33mRepositories..."
for repositories in $PACKAGE_SERVER
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$repositories" -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "REPOS"
	$IPT -A INPUT -i $IFACE -p tcp -s "$repositories" -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "REPOS"
done

# Allowing IPSET hosts to retrieve bad guys IP's
echo "\e[32mEnabling \e[33mIPSET hosts..."
for hosts in $IPSET_HOSTS
do
	$IPT -A OUTPUT -o $IFACE -p tcp -d "$IPSET_HOSTS" -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "IPSET HOSTS"
	$IPT -A INPUT -i $IFACE -p tcp -s "$IPSET_HOSTS" -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "IPSET HOSTS"
done

# Enable IPSET blacklists - logs blocked attempts and drop packets
echo "\e[32mEnabling \e[33mIPSET 'blacklist'..."
$IPSET restore < /etc/ipset-blacklist/ip-blacklist.restore
$IPT -A INPUT -i $IFACE -m set --match-set blacklist src -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[IPSET] Blacklist: "
$IPT -A INPUT -i $IFACE -m set --match-set blacklist src -j DROP -m comment --comment "DROP IPSET BLACKLIST"

# LOG and DROP script kiddies scanning ports
echo "\e[32mActivating \e[33mport scanner detector..."
$IPSET -N bad_guys iphash
$IPT -A INPUT -i $IFACE -p tcp -m set --match-set bad_guys src -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[IPSET] TCP bad_guy: "
$IPT -A INPUT -i $IFACE -p udp -m set --match-set bad_guys src -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[IPSET] UDP bad_guy: "
$IPT -A INPUT -i $IFACE -p tcp ! --dport $TCP_SERVICES -j SET --add-set bad_guys src -m comment --comment "[TCP PORT SCAN]"
$IPT -A INPUT -i $IFACE -p udp ! --dport $UDP_SERVICES -j SET --add-set bad_guys src -m comment --comment "[UDP PORT SCAN]"
$IPT -A INPUT -m set --match-set bad_guys src -j DROP -m comment --comment "[DROP PORT SCANNERS]"

# Admin IPs Version 2
echo "\e[32mEnabling \e[33madmin's IP..."
$IPT -A INPUT -s $ADMIN -j ACCEPT -m comment --comment "ADMIN's IP"
$IPT -A OUTPUT -d $ADMIN -j ACCEPT -m comment --comment "ADMIN's IP"

# Allow OpenVPN and INC and OUT traffic
$IPT -A INPUT -i eth0 -p udp --dport $OPENVPNPORT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT -m comment --comment "ACCEPT INC OpenVPN"
$IPT -A OUTPUT -o eth0 -p udp --sport $OPENVPNPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "ACCEPT OUT OpenVPN"

# OpenVPN Masquerade outgoing traffic
echo "\e[32mMASQUERADING \e[33mOpenVPN... "
$IPT -t nat -A POSTROUTING -o eth0 -j MASQUERADE -m comment --comment "MASQUARADE out IP"

# Forward everything
$IPT -A FORWARD -j ACCEPT -m comment --comment "FORWARDING all"

# Allow Echo Request and Reply
echo "\e[32mAllow \e[33mecho requests and reply..."
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT -m comment --comment "ACCEPT ICMP REQUEST"
$IPT -A OUTPUT -o $IFACE -p icmp -m icmp --icmp-type echo-reply -j ACCEPT -m comment --comment "ACCEPT ICMP REPLY"

# All tcp connections should begin with syn
echo "\e[33mLogging and Forcing connections to begin with SYN..."
$IPT -A INPUT -i $IFACE -p tcp ! --syn -m conntrack --ctstate NEW -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[NON SYN CONN]: "
$IPT -A INPUT -i $IFACE -p tcp ! --syn -m conntrack --ctstate NEW -j DROP -m comment --comment "DROP NON SYN CONN"

# Blocking excessive syn packet
echo "\e[31mBlocking \e[33mSYN packets..."
$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[SYN FLOOD]: "
$IPT -A SYN_FLOOD -j DROP -m comment --comment "DROP EXCESSIVE SYN"

# LOG and DROP INVALID packets
echo "\e[31mDropping \e[33mINVALID packets... "
$IPT -A INPUT -i $IFACE -m conntrack --ctstate INVALID -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[INVALID PACKETS]: "
$IPT -A INPUT -i $IFACE -m conntrack --ctstate INVALID -j DROP -m comment --comment "DROP INVALID PACKETS"

# Protection against spoofing attacks
echo "\e[33mLogging and \e[31mdropping \e[33mspooffing \e[31mattacks"
$IPT -t raw -I PREROUTING -m rpfilter --invert -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[SPOOFING]: "
$IPT -t raw -I PREROUTING -m rpfilter --invert -j DROP

# Chain for preventing SSH brute-force attacks. Permits 10 new connections within 5 minutes from a single host
# then drops incomming connections from that host.
# Beyond a burst of 100 connections we log at up 1 attempt per second to prevent filling of logs
$IPT -N SSHBF
$IPT -N LOG_AND_DROP
$IPT -A INPUT -p tcp -m multiport --dports $SSHPORT,22 -m conntrack --ctstate NEW -j SSHBF
$IPT -A SSHBF -m recent --name sshnerds --rttl --rcheck --hitcount 3 --seconds 10 -j LOG_AND_DROP
$IPT -A SSHBF -m recent --name sshnerds --rttl --rcheck --hitcount 4 --seconds 1800 -j LOG_AND_DROP
$IPT -A LOG_AND_DROP -j LOG --log-prefix "[SSHBF]: " --log-level 7
$IPT -A LOG_AND_DROP -j DROP

# LOG and DROP all packets that are going to broadcast, multicast or anycast address
echo "\e[33mLogging and \e[31mdropping \e[33mbroadcast, multicast or anycast address \e[31mattacks"
$IPT -A INPUT -i $IFACE -m addrtype --dst-type BROADCAST -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[BROADCAST SPOOF]: "
$IPT -A INPUT -i $IFACE -m addrtype --dst-type MULTICAST -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[MULTICAST SPOOF]: "
$IPT -A INPUT -i $IFACE -m addrtype --dst-type ANYCAST -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[ANYCAST SPOOF]: "
$IPT -A INPUT -i $IFACE -m addrtype --dst-type BROADCAST -j DROP
$IPT -A INPUT -i $IFACE -m addrtype --dst-type MULTICAST -j DROP
$IPT -A INPUT -i $IFACE -m addrtype --dst-type ANYCAST -j DROP

# Drop all packets to port 111 except those from localhost
echo "\e[31mRejecting \e[33mall packets to port 111 excecpt packets from \e[32mlocalhost... "
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[LOCAL SPOOFED]: "
$IPT -A INPUT ! -s 127.0.0.0/8 -p tcp --dport 111 -j REJECT --reject-with tcp-reset -m comment --comment "REJECT SPOOF"

# kill off identd quick
echo "\e[31mKilling \e[33midentd..."
$IPT -A INPUT -i $IFACE -p tcp --dport 113 -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[IDENTD]: "
$IPT -A INPUT -i $IFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset -m comment --comment "REJECT IDENTD"

# ICMP packets should fit in a Layer 2 frame, thus they should never be fragmented
# Fragmented icmp packets are a typical sign of a denial of service attack
echo "\e[36mLOG \e[33mand \e[31mDROP \e[33mfragmented icmp packets..."
$IPT -A INPUT -i $IFACE -p icmp --fragment -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[FRAGMENTED ICMP]: "
$IPT -A INPUT -i $IFACE -p icmp --fragment -j DROP -m comment --comment "DROP FRAGMENTED ICMP"

# Chain for preventing ping flooding - up to 2 pings per second from a single
# source, again with log limiting. Also prevents us from ICMP REPLY flooding
# some victim when replying to ICMP ECHO from a spoofed source.
echo "\e[31mDROP \e[33mIMCP FLOOD..."
$IPT -N ICMPFLOOD
$IPT -A ICMPFLOOD -m recent --set --name ICMP --rsource
$IPT -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 2 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[ICMP FLOOD]: "
$IPT -A ICMPFLOOD -m recent --update --seconds 1 --hitcount 2 --name ICMP --rsource --rttl -j DROP -m comment --comment "DROP ICMP FLOOD"

# Stop smurf attacks
echo "\e[32mEnabling \e[33msmurf \e[31mattack \e[33mdetector..."
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type address-mask-request -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[SMURF MASK]: "
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type timestamp-request -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "[SMURF TIMESTAMP]: "
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type address-mask-request -j DROP -m comment --comment "DROP SMURF ATTACK"
$IPT -A INPUT -i $IFACE -p icmp -m icmp --icmp-type timestamp-request -j DROP -m comment --comment "DROP SMURF ATTACK"
$IPT -A INPUT -i $IFACE -p icmp -j DROP

# All policies set to DROP
echo "\e[33mSetting up \e[31mDROP \e[33mpolicy..."
$IPT --policy INPUT DROP
$IPT --policy OUTPUT DROP
$IPT --policy FORWARD ACCEPT

# Allow SSH
#echo "\e[32mAllowing \e[33mSSH... "
#$IPT -A INPUT -i $IFACE -p tcp -s $ADMIN --dport $SSHPORT -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "ACCEPT SSH"
#$IPT -A OUTPUT -o $IFACE -p tcp -d $ADMIN --sport $SSHPORT -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "ACCEPT SSH"

# Rate Limit
#echo "\e[32mEnabling \e[33mRate Limiter"
#$IPT -N RATE_LIMIT
#$IPT -A INPUT -i $IFACE -p all -m conntrack --ctstate NEW -j RATE_LIMIT
#$IPT -A RATE_LIMIT -m limit --limit 50/sec --limit-burst 20 --jump ACCEPT -m comment --comment "GLOBAL CONN LIMIT"
#$IPT -A RATE_LIMIT -m hashlimit --hashlimit-mode srcip --hashlimit-upto 50/sec --hashlimit-burst 20 --hashlimit-name conn_rate_limit -j ACCEPT -m comment --comment "LIMIT PER IP"
#$IPT -A RATE_LIMIT -m limit --limit 1/sec -j LOG --log-prefix "iptables [RATE LIMIT] exceed: "
#$IPT -A RATE_LIMIT -j DROP

# Allow rsync from a specific network
#$IPT -A INPUT -i $IFACE -p tcp -s 192.168.101.0/24 --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -o $IFACE -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# DOS HTTP Attack prevention
# Need re-evaluation, the current rates do not allow for WordPress image upload features
# Plus, the timings reportedly slows down current site browsing to an unusable level - hence the commented out "DROP"
#$IPT -A INPUT -i $IFACE -p tcp --dport 80 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i $IFACE -p tcp --dport 80 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode srcip --hashlimit-name http -j ACCEPT
#$IPT -A INPUT -i $IFACE -p tcp --dport 80 -j ACCEPT
#$IPT -A INPUT -i $IFACE -p tcp --dport 443 -m limit --limit 45/minute --limit-burst 300 -j ACCEPT
#$IPT -A INPUT -i $IFACE -p tcp --dport 443 -m hashlimit --hashlimit-upto 80/min --hashlimit-burst 800 --hashlimit-mode srcip --hashlimit-name https -j ACCEPT
#$IPT -A INPUT -i $IFACE -p tcp --dport 443 -j ACCEPT

# IPv6 rules

# Script to block IPs reading a file, same scheme might be used for $blacklist or $whitelist IPs
#if [ -f geo-ip-block.txt ]
#then
#        for BLOCKED_IP in 'cat geo-ip-block.txt'
#        do
#                iptables -A INPUT -s $BLOCKED_IP -j DROP
#        done
#else
#        echo "No Geo-IP Blocking file exists"
#fi

## Uncomment to test new firewall rules
#sleep 60 && sh -c /home/chuck/bin/killgual.sh
