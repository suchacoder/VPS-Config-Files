#!/usr/bin/env bash

# This is my personal mofuken firegual that i ran onn UrT server (game server)
# I heavily rely on IPset and settled that monster up so that if a nerd drops
# a single packet that ain't goin' to an open port, the nerd gets wreked on ight

# Are you root ?
if [ $((UID)) != 0 ]; then
  echo -e "$RED ERROR: You need to run this script as ROOT user $NO_COLOR" >&2
  exit 2
fi

# Location of executables
IPTABLES=$(which iptables)
IPSET=$(which ipset)

# Define sysadmin's IP
ADMIN="181.191.143.0/32"

# In case you wanna whitelist a nerd or ban a nerd
# good nerd's hosts (array)
# ALLOW_HOSTS=(
#       "xxx.xxx.xxx.xxx"
#       "xxx.xxx.xxx.xxx"
#       "xxx.xxx.xxx.xxx"
# )

# ban list unconditional discard list (array)
# DENY_HOSTS=(
#       "xxx.xxx.xxx.xxx"
#       "xxx.xxx.xxx.xxx"
#       "xxx.xxx.xxx.xxx"
# )

# Define ports that shall be serving the outside world
SSH="44555"
URT="27960,27961,27962,27963,27964"
#TCP_SERVICES="xxx,xxx,xxx"
#UDP_SERVICES="xxx,xxx,xxx"

# Set default policies
echo " * setting default policies"
iptables --policy INPUT DROP
iptables --policy OUTPUT ACCEPT
iptables --policy FORWARD DROP

# Create IPSet white and black lists, and restore database
echo " * creating custom rule chains and IPSet"
ipset create whitelist hash:ip
ipset create blacklist hash:net family inet hashsize 16384 maxelem 500000
ipset restore -! < /home/chuck/ipset/ipset.restore

# Ok... lets add some bad nerds to IPSet's blacklist
# With this rule mofuken nerds gonna see the devil on earth
# This will ban nerds as soon as the packets enters the network
echo " * Dropping malicious nerds from IPSet's blacklist"
iptables --table raw --append PREROUTING -i eth0 --protocol ALL --match set --match-set blacklist src --jump DROP

# Create chains to reduce the number of rules each packet must traverse
echo " * creating bad packet chain"
iptables --new-chain bad_packets
echo " * creating bad TCP packet chain"
iptables --new-chain bad_tcp_packets
echo " * creating ICMP packet"
iptables --new-chain icmp_packets
echo " * creating UDP inbound"
iptables --new-chain udp_inbound
echo " * creating UDP outbound"
iptables --new-chain udp_outbound
echo " * creating TCP inbound"
iptables --new-chain tcp_inbound
echo " * creating TCP outbound"
iptables --new-chain tcp_outbound

#
# bad_packets chain
#

# Drop INVALID packets
iptables --append bad_packets --protocol ALL --match conntrack --ctstate INVALID --jump DROP --match comment --comment "* INVALID *"

#
# bad_tcp_packets chain
#

# All TCP sessions should begin with SYN
iptables --append bad_tcp_packets --protocol tcp ! --syn --match conntrack --ctstate NEW --jump DROP

# Stealth scans
iptables --append bad_tcp_packets --protocol tcp --tcp-flags SYN,ACK SYN,ACK --match conntrack --ctstate NEW --jump DROP --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags SYN,FIN SYN,FIN --jump DROP                                 --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags SYN,RST SYN,RST --jump DROP                                 --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ALL NONE --jump DROP                                        --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ALL ALL --jump DROP                                         --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ALL FIN,URG,PSH --jump DROP                                 --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP                             --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ACK,FIN FIN --jump DROP                                     --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ACK,PSH PSH --jump DROP                                     --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags ACK,URG URG --jump DROP                                     --match comment --comment "* STEALTH *"
iptables --append bad_tcp_packets --protocol tcp --tcp-flags FIN,RST FIN,RST --jump DROP                                 --match comment --comment "* STEALTH *"

#
# icmp_packets chain
#

# Stopping fragmented ICMP packets
iptables --append icmp_packets --protocol icmp --fragment --jump DROP --match comment --comment "* FRAGMENTED ICMP *"

# Stopping smurf attacks
iptables --append icmp_packets --protocol icmp --match icmp --icmp-type address-mask-request --jump DROP --match comment --comment "* SMURF ICMP *"
iptables --append icmp_packets --protocol icmp --match icmp --icmp-type timestamp-request --jump DROP --match comment --comment "* SMURF ICMP *"

# Time Exceeded
iptables --append icmp_packets --protocol icmp --match icmp --icmp-type time-exceeded --jump ACCEPT

# Echo Request
iptables --append icmp_packets --protocol icmp --match icmp --icmp-type echo-request --match limit --limit 1/second --jump ACCEPT

# Return if not matched
iptables --append icmp_packets --protocol icmp --jump RETURN --match comment --comment "* RETURN *"

#
# udp_inbound chain
#

# Add nerds to blacklist if they send packets to not listening UDP ports
iptables --append udp_inbound --protocol udp --source 0/0 --match multiport ! --destination-ports "$URT" --jump SET --add-set blacklist src --match comment --comment "* NONURT *"

# Accept UrT server connections
iptables --append udp_inbound --protocol udp --match multiport --destination-ports "$URT" --jump ACCEPT --match comment --comment "* ACCEPT URT *"

# Return if not matched
iptables --append udp_inbound --protocol udp --jump RETURN --match comment --comment "* RETURN *"

#
# udp_outbound chain
#

# Allow outgoin UDP packets
iptables --append udp_outbound --protocol udp --jump ACCEPT --match comment --comment "* ALLOW UDP OUT *"

#
# tcp_inbound chain
#

# Add nerds to blacklist if they send packets to not listening TCP ports
iptables --append tcp_inbound --protocol tcp --source 0/0 --match multiport ! --destination-ports "$SSH" --jump SET --add-set blacklist src --match comment --comment "* NONSSH *"

# Allow thyself to connect SSH
iptables --append tcp_inbound --protocol tcp --source "$ADMIN" --match multiport --destination-ports "$SSH" --jump ACCEPT --match comment --comment "* ACCEPT SSH *"

# Return if not matched
iptables --append tcp_inbound --protocol tcp --jump RETURN --match comment --comment "* RETURN *"

#
# tcp_outbound chain
#

# Allow outgoin TCP packets
iptables --append tcp_outbound --protocol tcp --jump ACCEPT --match comment --comment "* ALLOW TCP OUT  *"

###############
# INPUT Chain #
###############

# Allow localhost
iptables --append INPUT --in-interface lo --jump ACCEPT --match comment --comment "* ALLOW lo *"

# DROP nerds sending packets as if they come from 'lo'
iptables --append INPUT -s 127.0.0.0/8 ! --in-interface lo --jump DROP --match comment --comment "* DROP lo *"

# Send all inc to be inspected by the 'bad_packets' chain
iptables --append INPUT --protocol ALL --jump bad_packets --match comment --comment "* BAD_PACKETS JUMP *"

# Accept established connections
iptables --append INPUT --protocol tcp --match conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT --match comment --comment "* STATEFULL *"

# Allow whitelisted nerds
iptables --append INPUT --match set --match-set whitelist src -j ACCEPT --match comment --comment "* ACCEPT NERDS *"

# Route the rest of the packets
iptables --append INPUT --protocol tcp --jump tcp_inbound
iptables --append INPUT --protocol udp --jump udp_inbound
iptables --append INPUT --protocol icmp --jump icmp_packets

# Log smart nerds that gets through all my sh!t
iptables --append INPUT --match limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "NERD GOT THROUGH ALL MY SH!T!!!: "
iptables --append INPUT -j DROP
# Save settings
#$(which ipset) save > /home/chuck/ipset/ipset.restore
$(which iptables-save) > /home/chuck/iptables_saved/firegual.rules

## Uncomment to test new firewall rules
#sleep 360 && sh -c /home/chuck/bin/killgual.sh
