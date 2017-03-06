 file name: uptime.sh

 #!/bin/bash
 #service monitoring
 /bin/netstat -tulpn | awk '{print $4}' | awk -F: '{print $4}' | grep ^80$ > /dev/null   2>/dev/null
 a=$(echo $?)
 if test $a -ne 0
 then
 echo "http service down" | mail -s "HTTP Service DOWN and restarted now" root@localhost
 /etc/init.d/httpd start > /dev/null 2>/dev/null
 else
 sleep 0
 fi
 /bin/netstat -tulpn | awk '{print $4}' | awk -F: '{print $4}' | grep ^53$ > /dev/null   2>/dev/null
 b=$(echo $?)
 if test $b -ne 0
 then
 echo "named service down" | mail -s "DNS Service DOWN and restarted now" root@localhost
 /etc/init.d/named start > /dev/null 2>/dev/null
 else
 sleep 0
 fi

 Cron setup:
 */5 * * * * /root/uptime.sh > /dev/null 2>/dev/null
