#!/bin/sh

# Saving ipset bad bois IPs
$(which ipset) save > /home/chuck/ipset/ipset.restore

echo "Resseting iptables firewall to default and allowing everything..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables -t security -F
iptables -t security -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
#ipset -F
#ipset -X
