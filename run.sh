rmmod sniffer_mod 
insmod ./sniffer_mod.ko
./sniffer_control --i rules.in
