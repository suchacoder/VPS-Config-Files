#!/bin/bash

# Location of executables
IPSET=$(which ipset)
IPTABLES=$(which iptables)

# VARs
IFACE="eth0"
ADMIN="181.191.143.0/32"
SSHPORT="44555"
URTPORT="27960,27961,27962"
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"
TCP_SERVICES="44555"
UDP_SERVICES="27960,27961,27962"
#HTTP_PORTS="80,443"

# Common definitions
COMMENT="-m comment --comment"
LOG="ULOG --ulog-nlgroup 1 --ulog-prefix"
DONT_LOG=""

# Set default policy for response to unwanted packets, should be set to DROP
# in production, but this allows you to change all of the rules at once.
# This is useful for testing, where you can set the tables to REJECT
# so that you can see if they are working immediately while testing.
REJECT=DROP


# iptables function
# Used inplace of calling iptables directly or a variable pointing to iptables.
#
# Usage:
# iptables TABLE RULE MESSAGE ACTION(S)
iptables() {

  local parameters=$#           # Number of parameters given
  local table=$1                # Table to use
  local rule=$2                 # Rule to perform
  local message=$3              # Message, used for both comments and logging (Optional)
  declare -a actions=("${@:4}") # Action(s) to be preformed (Multiple can be specified)

  #local comment=""
  # If message is not empty, use it as a comment and to insert a LOG jump.
  #if [ -n "$message" ]; then
   # comment=$COMMENT "$message"
   # $IPTABLES $comment $table $rule --jump $LOG "$message"
  #fi

  # If 3 or less parameters are given; create a simple table and rule statement.
  if [ "$parameters" -le 3 ]; then
    $IPTABLES $comment $table $rule

  # If more than 4 parameters are given; use them each as jump targets.
  elif [ "$parameters" -ge 4 ]; then

    for jump in "$actions"; do
      $IPTABLES $comment $table $rule --jump ${jump}
    done

  fi
}


echo "Configuring netfilter:"


# Flush old rules, custom tables and sets
echo " * flushing old rules"
$IPTABLES --flush
$IPTABLES --delete-chain
## Only flush and destroy ipset one time, then comment it to keep blacklisted IPs ##
#$IPSET --flush
#$IPSET --destroy


# Set default policies for all three default chains
echo " * setting default policies"
$IPTABLES --policy INPUT $REJECT
$IPTABLES --policy FORWARD $REJECT
$IPTABLES --policy OUTPUT ACCEPT


# Create chains to reduce the number of rules each packet must traverse.
echo " * creating custom rule chains"
$IPSET create blacklist hash:net family inet hashsize 16384 maxelem 500000
$IPSET restore -! < /home/chuck/ipset/ipset.restore
$IPSET create whitelist hash:ip
$IPTABLES --new-chain bad_packets
$IPTABLES --new-chain bad_tcp_packets
$IPTABLES --new-chain icmp_packets
$IPTABLES --new-chain udp_inbound
$IPTABLES --new-chain udp_utbound
$IPTABLES --new-chain tcp_inbound
$IPTABLES --new-chain tcp_outbound


# bad_packets chain
#
echo " * * creating bad packet chain"

table="--append bad_packets"

# Drop INVALID packets immediately
iptables "$table --protocol ALL" "-m conntrack --ctstate INVALID" "Invalid packet" "$REJECT"

# Then check the tcp packets for additional problems
iptables "$table --protocol tcp" "" "$DONT_LOG" "bad_tcp_packets"

# All good, so return
iptables "$table --protocol ALL" "" "$DONT_LOG" "RETURN"


# bad_tcp_packets chain
#
echo " * * creating bad TCP packet chain"

table="--append bad_tcp_packets --protocol tcp"

# The unclean module is should eliminate the need for bad packet rules,
# but it is marked as expiremental and not considered production ready.
# iptables "$table" "-m unclean" "$DONT_LOG" "$REJECT"

# All TCP sessions should begin with SYN
iptables "$table" "! --syn -m conntrack --ctstate NEW" "Bad TCP packet" "$REJECT"

iptables "$table" "--tcp-flags ALL NONE"                     "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags ALL ALL"                      "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags ALL FIN,URG,PSH"              "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags ALL SYN,RST,ACK,FIN,URG"      "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags SYN,RST SYN,RST"              "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags SYN,FIN SYN,FIN"              "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags FIN,SYN FIN,SYN"              "Stealth scan"   "$REJECT"
iptables "$table" "--tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE" "Bad TCP packet" "$REJECT"
iptables "$table" "--tcp-flags FIN,RST FIN,RST"              "Bad TCP packet" "$REJECT"
iptables "$table" "--tcp-flags FIN,ACK FIN"                  "Bad TCP packet" "$REJECT"
iptables "$table" "--tcp-flags ACK,URG URG"                  "Bad TCP packet" "$REJECT"

iptables "$table" "" "$DONT_LOG" "RETURN"


# icmp_packets chain
#
echo " * * creating ICMP packet chain"

table="--append icmp_packets --protocol icmp"

# ICMP packets should fit in a Layer 2 frame, thus they should
# never be fragmented.  Fragmented icmp packets are a typical sign
# of a denial of service attack.
iptables "$table" "--fragment" "ICMP Fragment" "$REJECT"

# Stop smurf attacks
iptables "$table" "-m icmp --icmp-type address-mask-request" "Smurf attack" "$REJECT"
iptables "$table" "-m icmp --icmp-type timestamp-request" "Smurf attack" "$REJECT"

# Echo Request
iptables "$table" "-m icmp --icmp-type echo-request -m limit --limit 1/second" "$DONT_LOG" "ACCEPT"

# Time Exceeded
iptables "$table" "-m icmp --icmp-type time-exceeded" "$DONT_LOG" "ACCEPT"

# Not matched, so return so it will be logged
iptables "$table" "" "$DONT_LOG" "RETURN"


# udp_inbound chain
#
echo " * * creating inbound UDP packet chain"

table="--append udp_inbound --protocol udp"
subtable="$table -m multiport --destination-ports "$URTPORT""
rule="-m limit --limit 70/minute --limit-burst 100"
iptables "$subtable" "$rule" "$DONT_LOG" "ACCEPT"
# Not matched, so return for logging
iptables "--append udp_inbound --protocol udp" "" "$LOG" "RETURN"


# udp_outbound chain
#
echo " * * creating outbound UDP packet chain"

# No match, so ACCEPT
iptables "--append udp_outbound --protocol udp" "" "$DONT_LOG" "ACCEPT"


# tcp_inbound chain
#
echo " * * creating inbound TCP packet chain"

table="--append tcp_inbound --protocol tcp --source 0/0"


# SSH
echo " * * * allowing ssh on port 44555"

subtable="$table --destination-port $SSHPORT"
rule="-m recent --name SSH --update --seconds 60 --hitcount 1"
iptables "$subtable" "$rule" "*** SSH over rate limit ***" "$REJECT"
rule="-m recent --name SSH --set"
iptables "$subtable" "$rule" "*** SSH connection attempt ***"
iptables "$subtable" "" "*** SSH connection accepted ***" "ACCEPT"


# Web Server

# HTTP
#echo " * * * allowing http on port 80"
#subtable="$table --destination-port http"
#rule="-m limit --limit 50/minute --limit-burst 100"
#iptables "$subtable" "$rule" "$DONT_LOG" "ACCEPT"


# HTTPS
#echo " * * * allowing https on port 443"
#subtable="$table --destination-port https"
#rule="-m limit --limit 50/minute --limit-burst 100"
#iptables "$subtable" "$rule" "$DONT_LOG" "ACCEPT"


# Not matched, so return so it will be logged
iptables "$table" "" "$DONT_LOG" "RETURN"



# tcp_outbound chain
#
echo " * * creating outbound TCP packet chain"

# No match, so ACCEPT
iptables "--append tcp_outbound --protocol tcp --source 0/0" "" "$DONT_LOG" "ACCEPT"




###############################################################################
#
# INPUT Chain
#
# Inbound Internet Packet Rules
#
###############################################################################
#$IPTABLES --append bad_tcp_packets --protocol tcp --syn -m limit --limit 100/s --limit-burst 100 --jump ACCEPT
#$IPTABLES --append bad_tcp_packets --protocol tcp --syn -m connlimit --connlimit-above 100 --jump REJECT --reject-with tcp-reset

table="--append INPUT"

# Allow all on localhost interface
iptables "$table" "--in-interface lo" "$DONT_LOG" "ACCEPT"

# Drop bad packets
$IPTABLES $table --protocol ALL --jump bad_packets

# Accept established connections
iptables "$table" "-m conntrack --ctstate ESTABLISHED,RELATED" "$DONT_LOG" "ACCEPT"

# Allow previously whitelisted hosts through
iptables "$table" "-m set --match-set whitelist src" "$DONT_LOG" "ACCEPT"

# Drop blacklisted hosts right away
iptables "$table" "-m set --match-set blacklist src" "$DONT_LOG" "$REJECT"

# Immediately ban and drop a host attempting to access ports that should not be open
iptables "$table --protocol tcp" "-m multiport ! --ports $TCP_SERVICES" "$DONT_LOG" "SET --add-set blacklist src" "$REJECT"
#iptables "$table --protocol udp" "-m multiport ! --ports $UDP_SERVICES" "$DONT_LOG" "SET --add-set blacklist src" "$REJECT"

# Route the rest to the appropriate user chain
$IPTABLES $table --protocol tcp --jump tcp_inbound
$IPTABLES $table --protocol udp --jump udp_inbound
$IPTABLES $table --protocol icmp --jump icmp_packets

# Log packets that still don't match
iptables "$table" "-m limit --limit 3/minute --limit-burst 3" "Packet died"


# Save settings
#$(which ipset) save > /home/chuck/ipset/ipset.restore
$(which iptables-save) > /home/chuck/iptables_saved/nerdgual.rules

# Woraround cuz for some nerd reason ipset restore ain't workin' for me #
#for ip in `sed -i '1d;s/add\ blacklist\ //g' /home/chuck/ipset/ipset.restore`; do ipset add blacklist $ip ; done

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
