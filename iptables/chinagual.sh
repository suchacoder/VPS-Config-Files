#!/bin/bash

###########################################################
# Unification of terms
# The terms of the rules and comments are unified below for the sake of clarity
# ACCEPT : accept packets
# DROP   : destruction
# REJECT : rejection
##########################################################

###########################################################
# Cheat sheet
#
# -A, --append       Add one or more new rules to a given chain
# -D, --delete       Remove one or more rules from the specified chain
# -P, --policy       Set the policy of the specified chain to the specified target
# -N, --new-chain    Create a new user-defined chain
# -X, --delete-chain Delete the specified user-defined chain
# -F                 Table initialization
#
# -p, --protocol      protocol             Specify protocol (tcp, udp, icmp, all)
# -s, --source        IP address [/ mask]  Source address. Describe the IP address or host name
# -d, --destination   IP address [/ mask]  Destination address. Describe the IP address or host name
# -i, --in-interface  device               Specifies the interface on which packets come in
# -o, --out-interface device               Specify the interface from which the packet exits
# -j, --jump          target               Specify the action when the conditions are met
# -t, --table         table                Specify a table
# -m state --state    situation            Specify the packet status as a condition
#                                          NEW, ESTABLISHED, RELATED, INVALID can be specified for state.
# !                                        Invert the condition (other than)
###########################################################

# path

PATH=/sbin:/usr/sbin:/bin:/usr/bin


RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"


###########################################################
# IP definition
# Define as needed. Works without definition
###########################################################

# Internal network range
# LOCAL_NET="xxx.xxx.xxx.xxx/xx"

# A somewhat restrictive internal network
# LIMITED_LOCAL_NET="xxx.xxx.xxx.xxx/xx"

# ZABBIX server IP
# ZABBIX_IP="xxx.xxx.xxx.xxx"

# Define a setting that represents all IPs
# ANY="0.0.0.0/0"

# trusted hosts (array)
# ALLOW_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

# ban list unconditional discard list (array)
# DENY_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

###########################################################
# port definition
###########################################################

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

##########################################################
# The program must be executed as the root user
###########################################################

if [ $((UID)) != 0 ]; then
  echo -e "$RED ERROR: You need to run this script as ROOT user $NO_COLOR" >&2
  exit 2
fi


###########################################################
# Features
###########################################################

# iptables initialization, delete all rules
initialize()
{
	iptables -F # initialization table
	iptables -X # delete chain
	iptables -Z # clear packet counter byte counter
	iptables -P INPUT   ACCEPT
	iptables -P OUTPUT  ACCEPT
	iptables -P FORWARD ACCEPT
}

#
finailize()
{
	service iptables save && # Save settings
	service iptables restart && # Try restarting with the saved one
	return 0
	return 1
}

# For development
if [ "$1" == "-t" ]
then
	iptables() { echo "iptables $@"; }
	finailize() { echo "finailize"; }
fi

###########################################################
# Initialize iptables
###########################################################
initialize

###########################################################
# Policy decision
###########################################################
iptables -P INPUT   DROP # All DROP. It's a good idea to close all the holes before opening the required ports.
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

###########################################################
# Trusted hosts allowed
###########################################################

# local host
# lo stands for local loopback and refers to your own host
iptables -A INPUT -i lo -j ACCEPT # SELF -> SELF

# Local network
# $LOCAL_NET Allows communication with other servers on the LAN if is set
if [ "$LOCAL_NET" ]
then
	iptables -A INPUT -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
fi

# Trusted host
# $ALLOW_HOSTS Allows interaction with the host if is set
if [ "${ALLOW_HOSTS}" ]
then
	for allow_host in ${ALLOW_HOSTS[@]}
	do
		iptables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
	done
fi

###########################################################
# $DENY_HOSTS Access from is discarded
###########################################################
if [ "${DENY_HOSTS}" ]
then
	for deny_host in ${DENY_HOSTS[@]}
	do
		iptables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
		iptables -A INPUT -s $deny_host -j DROP
	done
fi

###########################################################
# Packet communication is allowed after session is established
###########################################################
iptables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

###########################################################
# Attack countermeasures: Stealth Scan
###########################################################
iptables -N STEALTH_SCAN # "STEALTH_SCAN" Make a chain with the name
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j DROP

# Packets that look like stealth scans "STEALTH_SCAN" Jump to the chain
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

###########################################################
# Attack countermeasures: Port scan by fragment packet, DOS attack
# namap -v -sF Measures such as
###########################################################
iptables -A INPUT -f -j LOG --log-prefix 'fragment_packet:'
iptables -A INPUT -f -j DROP

###########################################################
# Attack countermeasures: Ping of Death
###########################################################
# Discard after 10 pings more than once per second
iptables -N PING_OF_DEATH # "PING_OF_DEATH" Make a chain with the name
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 10 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_PING_OF_DEATH \
         -j RETURN

# Discard ICMP that exceeds the limit
iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
iptables -A PING_OF_DEATH -j DROP

# ICMP jumps to "PING_OF_DEATH" chain
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

###########################################################
# Attack countermeasures: SYN Flood Attack
# In addition to this, Syn Cookies should be enabled.
###########################################################
iptables -N SYN_FLOOD # "SYN_FLOOD" Make a chain with the name
iptables -A SYN_FLOOD -p tcp --syn \
         -m hashlimit \
         --hashlimit 200/s \
         --hashlimit-burst 3 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_SYN_FLOOD \
         -j RETURN

# Commentary
# -m hashlimit                       Use hashlimit instead of limit to limit per host
# --hashlimit 200/s                  Up to 200 connections per second
# --hashlimit-burst 3                If the connection exceeding the above upper limit is made 3 times in a row, the limit will be applied.
# --hashlimit-htable-expire 300000   Validity period of records in the management table (unit: ms)
# --hashlimit-mode srcip             Manage the number of requests by source address
# --hashlimit-name t_SYN_FLOOD       /proc/net/ipt_hashlimit Hash table name stored in
# -j RETURN                          If within the limit, return to the parent chain

# Discard SYN packets that exceed the limit
iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
iptables -A SYN_FLOOD -j DROP

# SYN packets jump to the "SYN_FLOOD" chain
iptables -A INPUT -p tcp --syn -j SYN_FLOOD

###########################################################
# Attack countermeasures: HTTP DoS/DDoS Attack
###########################################################
iptables -N HTTP_DOS # "HTTP_DOS" Make a chain with the name
iptables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 100 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_HTTP_DOS \
         -j RETURN

# Commentary
# -m hashlimit                       Use hashlimit instead of limit to limit per host
# --hashlimit 1/s                    Up to 1 connection per second
# --hashlimit-burst 100              If you exceed the above upper limit 100 times in a row, you will be limited.
# --hashlimit-htable-expire 300000   Validity period of records in the management table (unit: ms)
# --hashlimit-mode srcip             Manage the number of requests by source address
# --hashlimit-name t_HTTP_DOS        /proc/net/ipt_hashlimit Hash table name stored in
# -j RETURN                          If within the limit, return to the parent chain

# Destroy a connection that exceeds the limit
iptables -A HTTP_DOS -j LOG --log-prefix "http_dos_attack: "
iptables -A HTTP_DOS -j DROP

# Packets to HTTP jump to the "HTTP_DOS" chain
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS

###########################################################
# Attack countermeasures: IDENT port probe
# ident To prepare for future attacks by attackers using ident, or to prepare for user's
# Perform a port survey to see if your system is vulnerable to attack
# There is likely to be.
# If we DROP, the response of the mail server etc. will be degraded, so REJECT
###########################################################
iptables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset

###########################################################
# Attack countermeasures: SSH Brute Force
# SSH prepares for password brute force attacks on servers that use password authentication
# Allow connection attempts only 5 times per minute.
# Use REJECT instead of DROP to prevent the SSH client side from repeating reconnection.
# If the SSH server has password authentication ON, uncomment the following
###########################################################
# iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --set
# iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ssh_brute_force: "
# iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# Attack countermeasures: FTP Brute Force
# Since FTP is password authentication, it prepares for password brute force attacks.
# Allow connection attempts only 5 times per minute.
# Use REJECT instead of DROP to prevent the FTP client side from repeating reconnection.
# If you have an FTP server running, uncomment the following
###########################################################
# iptables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --set
# iptables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ftp_brute_force: "
# iptables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# discard broadcast packets
###########################################################
iptables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 192.168.1.255   -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1       -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 224.0.0.1       -j DROP

###########################################################
# Input permission from all hosts (ANY)
###########################################################

# ICMP: Settings to respond to pingsv
iptables -A INPUT -p icmp -j ACCEPT # ANY -> SELF

# HTTP, HTTPS
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF

# SSH: If you want to limit the host, write the trusted host in TRUST_HOSTS and comment out the following
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SEL

# FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT # ANY -> SELF

# DNS
iptables -A INPUT -p tcp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF
iptables -A INPUT -p udp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF

# SMTP
# iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

# POP3
# iptables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT # ANY -> SELF

# IMAP
# iptables -A INPUT -p tcp -m multiport --sports $IMAP -j ACCEPT # ANY -> SELF

###########################################################
# Allow input from local network (restricted)
###########################################################

if [ "$LIMITED_LOCAL_NET" ]
then
	# SSH
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $SSH -j ACCEPT # LIMITED_LOCAL_NET -> SELF

	# FTP
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $FTP -j ACCEPT # LIMITED_LOCAL_NET -> SELF

	# MySQL
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $MYSQL -j ACCEPT # LIMITED_LOCAL_NET -> SELF
fi

###########################################################
# Input permission from a specific host
###########################################################

if [ "$ZABBIX_IP" ]
then
	# Allow Zabbix related
	iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi

##################################################################
# other than that
# Log and discard anything that does not apply to the above rules
##################################################################
iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP


# For development
if [ "$1" == "-t" ]
then
	exit 0;
fi

###############################################################
# SSH lockout workaround
# Sleep for 30 seconds and then reset iptables.
# If SSH isn't locked out, you should be able to press Ctrl-C.
###############################################################
trap 'finailize && exit 0' 2 # Trap Ctrl-C
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
