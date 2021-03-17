#!/bin/bash

WHITELIST=/whitelist.txt
BLACKLIST=/blacklist.txt

#THIS WILL CLEAR ALL EXISTING RULES!
echo 'Clearing all rules'
iptables -F

#
## Whitelist
#

for x in `grep -v ^# $WHITELIST | awk '{print $1}'`; do
        echo "Permitting $x..."
        $IPTABLES -A INPUT -t filter -s $x -j ACCEPT
done

#
## Blacklist
#

for x in `grep -v ^# $BLACKLIST | awk '{print $1}'`; do
        echo "Denying $x..."
        $IPTABLES -A INPUT -t filter -s $x -j DROP
done
