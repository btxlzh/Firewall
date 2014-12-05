rmmod sniffer_mod 
insmod ./sniffer_mod.ko
./sniffer_control --mode Enable --src_ip 172.16.176.1
./sniffer_control --i rule.in
