Taken from Zaid Python Ethical Hacking Course.

To intercept on different local machines:
Enable ip forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`
Setup a queue for packets
`iptables -I FORWARD -j NFQUEUE queue-num 0`

I used a .gz file from the apache.org website as this was designed for http downloads


