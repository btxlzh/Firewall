rmmod sniffer_mod 
insmod ./sniffer_mod.ko
./sniffer_control --mode enable --src_ip 10.148.8.120
./sniffer_control --mode enable --dst_ip 10.148.8.120
./sniffer_control --mode enable --dst_ip 192.168.223.172

