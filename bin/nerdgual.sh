#!/bin/bash

# Location of executables
IPSET=$(which ipset)
IPTABLES=$(which iptables)

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
$IPSET flush
$IPSET destroy


# Set default policies for all three default chains
echo " * setting default policies"
$IPTABLES --policy INPUT ACCEPT
$IPTABLES --policy FORWARD ACCEPT
$IPTABLES --policy OUTPUT ACCEPT


# Create chains to reduce the number of rules each packet must traverse.
echo " * creating custom rule chains"
#$IPSET create blacklist hash:net family inet hashsize 16384 maxelem 500000
#$IPSET create whitelist hash:ip
$IPSET restore -! < /home/chuck/ipset/ipset.restore
$IPTABLES --new-chain bad_packets
$IPTABLES --new-chain bad_tcp_packets
$IPTABLES --new-chain icmp_packets
$IPTABLES --new-chain udp_inbound
$IPTABLES --new-chain udp_outbound
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

echo "* * allow OpenVPN"
table="--append udp_inbound --protocol udp --source 0/0"
rule="--in-interface eth0 --dport 1194 -m conntrack --ctstate NEW"
iptables "$table" "$rule" "* allow INC OpenVPN *" "ACCEPT"

# Immediately ban and drop nerds attempting to access USP ports that should not be open
nerds="-m multiport ! --ports 1194"
iptables "$table" "$nerds" "$DONT_LOG" "SET --add-set blacklist src" "$REJECT"

# Not matched, so return for logging
iptables "--append udp_inbound --protocol udp" "" "$DONT_LOG" "RETURN"


# udp_outbound chain
#
echo " * * creating outbound UDP packet chain"

table="--append udp_outbound --protocol udp --destination 0/0"
rule="--out-interface eth0 --sport 1194 -m conntrack --ctstate ESTABLISHED,RELATED"
iptables "$table" "$rule" "* allow OUT OpenVPN *" "ACCEPT"


# OpenVPN Masquerade outgoing traffic
echo " * * masquarading OpenVPN"

table="-t nat"
rule="--append POSTROUTING -o eth0 --source 10.8.0.0/24"
iptables "$table" "$rule" "* masquerade OpenVPN *" "MASQUERADE"

# Forward everything
iptables -A FORWARD -j ACCEPT

# No match, so ACCEPT
iptables "--append udp_outbound --protocol udp" "" "$DONT_LOG" "ACCEPT"


# tcp_inbound chain
#
echo " * * creating inbound TCP packet chain"

table="--append tcp_inbound --protocol tcp --source 0/0"

# Web Server


# SSH
echo " * * * allowing ssh on port 4949"

subtable="$table --destination-port 4949"

rule="-m recent --name SSH --update --seconds 60 --hitcount 1"
iptables "$subtable" "$rule" "*** SSH over rate limit ***" "$REJECT"

rule="-m recent --name SSH --set"
iptables "$subtable" "$rule" "*** SSH connection attempt ***"

iptables "$subtable" "" "*** SSH connection accepted ***" "ACCEPT"


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
iptables "$table --protocol tcp" "-m multiport ! --ports 4949" "$DONT_LOG" "SET --add-set blacklist src" "$REJECT"

# Route the rest to the appropriate user chain
$IPTABLES $table --protocol tcp --jump tcp_inbound
$IPTABLES $table --protocol udp --jump udp_inbound
$IPTABLES $table --protocol icmp --jump icmp_packets

# Log packets that still don't match
iptables "$table" "-m limit --limit 3/minute --limit-burst 3" "Packet died"


# Save settings
#$(which ipset) save > $HOME/ipset/ipset.restore
$(which iptables-save) > /home/chuck/iptables_saved/firegual.rules

# Woraround cuz ipset restore ain't workin' for me
#for ip in `sed -i '1d;s/add\ blacklist\ //g' /home/chuck/ipset/ipset.restore`; do ipset add blacklist $ip ; done
