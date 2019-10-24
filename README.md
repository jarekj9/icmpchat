Instructions:
1. Hosts need to have direct connectivity via their own IPs (for example 2 hosts on the same network)
1. Run it on both ends, as root
2. Specify destination ip address
3. Specify interface (default is eth0)

For example:

host A:
sudo ./icmpchat.py -d 192.168.31.27 -i wlan0

host B:
sudo ./icmpchat.py -d 192.168.31.26 -i wlan0

