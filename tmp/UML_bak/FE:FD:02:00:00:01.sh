ifconfig eth0 192.168.1.2 
route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.1.129
route add -net 192.168.3.0 netmask 255.255.255.0 gw 192.168.1.129
echo -ne "\033]0;UML_1\007"