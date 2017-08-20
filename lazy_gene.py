import os
import sys
try:
    import nmap
except:
    sys.exit("[!] Install the nmap library: pip install python-nmap")
import os
import sys

port_scan_list = []

nm = nmap.PortScanner()

print "[!] Please choose from the following options:\n"
print "[0] Host Discovery Scan\n"
print "[1] TCP Aggressive Scan Top 1000 Ports (93% coverage - Fyodor)\n"
print "[2] TCP Aggressive Scan Top 3674 Ports (100% coverage - Fyodor)\n"
print "[3] UDP Aggressive Scan Top 100 Ports (90% coverage - Fyodor)\n"
print "[4] UDP Aggressive Scan top 1017 Ports (100% coverage - Fyodor)\n"

user_input = input("Please make your selection ")


print "[*] Nmap Scan Running...Please Be Patient[*]"

if str(user_input) == '0':
    os.system('nmap -sn 192.168.1.0/24 |grep 192.* |cut -d " " -f 5 > alive.txt')
    print "Host Discovery Complete"
    sys.exit()
#Scans discovered hosts, tcp connect, Aggressive, Top 1000 ports
elif str(user_input) == '1':
    nm.scan(hosts='', arguments='-Pn -sT -T4 --top-ports 1000 -iL alive.txt')
    print "[!]Nmap Scan Complete."
#Scans discovered hosts, tcp connect, Aggressive, Top 3674 ports
elif str(user_input) == '2':
    nm.scan(hosts='', arguments='-Pn -sT -T4 --top-ports 3674 -iL alive.txt')
    print "[!]Nmap Scan Complete."
#Scans discovered hosts, udp, Aggressive, Top 100 ports

elif str(user_input) == '3':
    try:
        nm.scan(hosts='', arguments='-Pn -sU -T4 --top-ports 100 -iL alive.txt')
        print "[!]Nmap Scan Complete."
    except:
        print " Operation Failed - please re-run as root"
        sys.exit()

#Scans discovered hosts, udp, Aggressive, Top 1017 ports
elif str(user_input) == '4':
    try:
        nm.scan(hosts='', arguments='-Pn -sU -T4 --top-ports 1017 -iL alive.txt')
        print "[!]Nmap Scan Complete."
    except:
        print "Operation Failed - please re-run as root"
        sys.exit()

else:
    print "Invalid Option, please try again"
    sys.exit()

# Adds nmap scan to list, parses XML output, then converts to csv format
content = nm.get_nmap_last_output()
nm.analyse_nmap_xml_scan(content)
port_scan_list.append(nm.csv())

data = nm.csv()


if str(user_input) == '1':
    with open('./port_scan_TCP_TOP1000.csv','wb') as port_scan_file:
        for line in data.split("\r\n"):
            port_scan_file.write(line.replace(';', ',') + '\n')

if str(user_input) == '2':
    with open('./port_scan_TCP_Top3674.csv','wb') as port_scan_file:
        for line in data.split("\r\n"):
            port_scan_file.write(line.replace(';', ',') + '\n')

if str(user_input) == '3':
    with open('./port_scan_UDP_Top100.csv','wb') as port_scan_file:
        for line in data.split("\r\n"):
            port_scan_file.write(line.replace(';', ',') + '\n')

if str(user_input) == '4':
    with open('./port_scan_UDP_Top1017.csv','wb') as port_scan_file:
        for line in data.split("\r\n"):
            port_scan_file.write(line.replace(';', ',') + '\n')









