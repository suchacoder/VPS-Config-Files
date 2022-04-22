#!/usr/bin/env bash

# This is my personal mofuken firegual that i run on UrT servers (game servers)
# I heavily rely on IPset and settled that monster up so that if a nerd drops a single packet with bad intentions, the nerd gets wreked on sight
# Remember to whitelist your DNS resolvers @ /etc/resolv.conf it's VPS related # to do so type: 'sudo ipset add whitelist xxx.xxx.xxx.xxx'  <--- IPs @ /etc/resolv.conf
# and add in da INPUT chain after 'STATEFUL': iptables --append INPUT --in-interface eth0 --protocol udp --source 200.9.155.111,200.9.155.112 --source-port 53 -j ACCEPT
# Also, allow Canonical's NTP: iptables --append INPUT --in-interface eth0 --protocol udp --source 91.189.89.199,91.189.89.198 --source-port 123 -j ACCEPT
# INFO: UrT master server: 94.23.196.186:27900 198.20.216.53:27900 168.119.32.223:27900

# Are you root ?
if [ $((UID)) != 0 ]; then
  echo -e "ERROR: You need to run this script as ROOT user" >&2
  exit 2
fi

# Location of executables
#IPTABLES=$(which iptables)
#IPSET=$(which ipset)

# Define sysadmin's IP
ADMIN="181.191.143.179"

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

# Check if ipset is installed, if not, install it
if ! [ -x "$(command -v ipset)" ]; then
  echo "IPSet ain't installed, installing it now..." && apt install ipset -y
fi

# Create IPSet white and black lists, and restore database
echo " * creating custom rule chains and IPSet"
ipset create whitelist hash:ip
ipset create blacklist hash:net family inet hashsize 16384 maxelem 500000
ipset restore -! < /home/chuck/ipset/ipset.restore

# Ok... lets add some malicious nerds to IPSet's blacklist
# With this rule mofuken nerds gonna see the devil on earth
# This will ban nerds as soon as the packets enters the network
echo " * Dropping malicious nerds from IPSet's blacklist"
iptables --table raw --append PREROUTING --protocol ALL --match set --match-set blacklist src --jump DROP

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
echo " * creating smart nerds catching LOG chain"
iptables --new-chain z_smart_nerds

#
# bad_packets chain
#

# Drop INVALID packets
iptables --append bad_packets --protocol ALL --match conntrack --ctstate INVALID --jump DROP --match comment --comment "* INVALID *"

#
# bad_tcp_packets chain
#

# All TCP sessions should begin with SYN, if not add them nerds to blacklist
iptables --append bad_tcp_packets --in-interface eth0 --protocol tcp ! --syn --match conntrack --ctstate NEW --match limit --limit 3/minute --limit-burst 3 --jump LOG --log-prefix "NON SYN LOG: "
iptables --append bad_tcp_packets --in-interface eth0 --protocol tcp ! --syn --match conntrack --ctstate NEW --jump SET --add-set blacklist src
iptables --append bad_tcp_packets --in-interface eth0 --protocol tcp ! --syn --match conntrack --ctstate NEW --jump DROP --match comment --comment "* NON SYN *"

# Stealth scans
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

# LOG and stop fragmented ICMP packets, and add them nerds to blacklist
iptables --append icmp_packets --in-interface eth0 --protocol icmp --fragment --match limit --limit 3/minute --limit-burst 3 --jump LOG --log-prefix "FRAGMENTED LOG: "
iptables --append icmp_packets --in-interface eth0 --protocol icmp --fragment --jump SET --add-set blacklist src
iptables --append icmp_packets --in-interface eth0 --protocol icmp --fragment --jump DROP --match comment --comment "* FRAGMENTED ICMP *"

# LOG malicious nerds sending a non-echo request/replay ICMP packet, cannot add 'em to blacklist cuz sometimes UrT sends ICMP type 3 :(
iptables --append icmp_packets --in-interface eth0 --protocol icmp --match icmp ! --icmp-type 0/8 --match limit --limit 3/minute --limit-burst 3 --jump LOG --log-prefix "NON ECHO REQUEST: "
iptables --append icmp_packets --in-interface eth0 --protocol icmp --match icmp ! --icmp-type 0/8 --jump DROP --match comment --comment "* NON ECHO REQUEST *"

# Limit echo requests
iptables --append icmp_packets --protocol icmp --icmp-type 0/8 --match limit --limit 1/second --jump ACCEPT

# Return if not matched
iptables --append icmp_packets --protocol icmp --jump RETURN --match comment --comment "* RETURN *"

#
# udp_inbound chain
#

# Add malicious nerds to blacklist if they send packets to not listening UDP ports
iptables --append udp_inbound --in-interface eth0 --protocol udp --source 0/0 --match multiport ! --destination-ports "$URT" --jump SET --add-set blacklist src --match comment --comment "* NONURT *"

# Accept UrT server connections
iptables --append udp_inbound --in-interface eth0 --protocol udp --match multiport --destination-ports "$URT" --jump ACCEPT --match comment --comment "* ACCEPT URT *"

# Return if not matched
iptables --append udp_inbound --protocol udp --jump RETURN --match comment --comment "* RETURN *"

#
# udp_outbound chain
#

# Allow outgoin' UDP packets
iptables --append udp_outbound --out-interface eth0 --protocol udp --jump ACCEPT --match comment --comment "* ALLOW UDP OUT *"

#
# tcp_inbound chain
#

# Add malicious nerds to blacklist if they send packets to not listening TCP ports
iptables --append tcp_inbound --in-interface eth0 --protocol tcp --source 0/0 --match multiport ! --destination-ports "$SSH" --jump SET --add-set blacklist src --match comment --comment "* NONSSH *"

# Allow thyself to connect SSH
iptables --append tcp_inbound --in-interface eth0 --protocol tcp --source "$ADMIN" --destination-port "$SSH" --jump ACCEPT --match comment --comment "* ACCEPT SSH *"

# Return if not matched
iptables --append tcp_inbound --protocol tcp --jump RETURN --match comment --comment "* RETURN *"

#
# tcp_outbound chain
#

# Allow outgoin TCP packets
iptables --append tcp_outbound --out-interface eth0 --protocol tcp --jump ACCEPT --match comment --comment "* ALLOW TCP OUT  *"

###############
# INPUT Chain #
###############

# Allow localhost
iptables --append INPUT --in-interface lo --jump ACCEPT --match comment --comment "* ALLOW lo *"

# DROP malicious nerds sending packets as if they come from 'lo'
iptables --append INPUT -s 127.0.0.0/8 ! --in-interface lo --jump DROP --match comment --comment "* DROP lo *"

# Send all inc to be inspected by the 'bad_packets' chain
iptables --append INPUT --protocol ALL --jump bad_packets --match comment --comment "* BAD_PACKETS JUMP *"

# Accept established connections
iptables --append INPUT --protocol tcp --match conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT --match comment --comment "* STATEFULL *"

# Allow VPS's DNS resolver
iptables --append INPUT --in-interface eth0 --protocol udp --source 200.9.155.111,200.9.155.112 --source-port 53 -j ACCEPT --match comment --comment "* DNS INC *"

# Allow canonical NTP
iptables --append INPUT --in-interface eth0 --protocol udp --source 91.189.89.199,91.189.89.198 --source-port 123 -j ACCEPT --match comment --comment "* NTP INC *"

# Allow whitelisted nerds
iptables --append INPUT --match set --match-set whitelist src -j ACCEPT --match comment --comment "* ACCEPT NERDS *"

# Route the rest of the packets
iptables --append INPUT --in-interface eth0 --protocol tcp --jump tcp_inbound
iptables --append INPUT --in-interface eth0 --protocol udp --jump udp_inbound
iptables --append INPUT --in-interface eth0 --protocol icmp --jump icmp_packets

# Log smart nerds that gets through all my sh!t
iptables --append z_smart_nerds --match limit --limit 3/minute --limit-burst 3 -j LOG --log-prefix "NERD GOT THROUGH ALL MY SH!T!!!: "

# Save settings
# Check if direcotry '/home/chuck/ipset/' exists, if not create it
if [ ! -d "/home/chuck/ipset/" ]; then
  echo "'ipset' dir ain't exists, creating it now..." && mkdir "/home/chuck/ipset/"
fi

#$(which ipset) save > /home/chuck/ipset/ipset.restore

# Check if direcotry '/home/chuck/iptables_saved/' exists, if not create it
if [ ! -d "/home/chuck/iptables_saved/" ]; then
  "'iptables_saved' dir ain't exists, creating it now..." && mkdir "/home/chuck/iptables_saved/"
fi

$(which iptables-save) > /home/chuck/iptables_saved/firegual.rules

## Uncomment to test new firewall rules
#echo " * Rule tester = [ON]  'Press Ctrl + C' if everything's Ok" ; sleep 15 && sh -c /home/chuck/bin/killgual.sh
