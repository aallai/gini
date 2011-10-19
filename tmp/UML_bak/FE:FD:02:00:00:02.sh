ifconfig eth0 192.168.2.3 
route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.2.130
route add -net 192.168.3.0 netmask 255.255.255.0 gw 192.168.2.130
echo -ne "\033]0;UML_2\007"