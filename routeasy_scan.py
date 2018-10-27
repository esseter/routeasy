#!/usr/bin/env python
#-*- coding: UTF-8 -*-

"""
The purpose of the script is to act as a proof of concept
that we can access scan the network using a python script and
identify a router's brand and OS version

Author : Louis Caudevilla

Anybody can use this script, all the credits go to the python-nmap developer

Version of nmap-python package is : 0.6.0
Version of nmap installed : 7.70 on OSX

To install the python-nmap library, you need to go to /library and type
python ./setup.py -install
"""
import sys
import nmap
import os
import time

try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print('Unexpected error:', sys.exc_info()[0])
    sys.exit(1)

print('----------------------------------------------------')
# Do a pingsweep on network 102.168.1.0/24
# -O argument is to detect the OS of the machines connected to the network


nma = nmap.PortScannerAsync()

routerIP = '192.168.1.1'
#routerIP = input('What is your router address ?: ')
print('Thank you I gonna scan ', routerIP,'...')
time.sleep(1)
while nma.still_scanning():
    print("Scanning ...\n")
    nma.wait(2)   # you can do whatever you want but I choose to wait after the end of the scan

if (os.getuid() == 0):
    # Os detection (need root privileges)
    nm.scan(routerIP, arguments="-O")
    if 'osmatch' in nm[routerIP]:
        for osmatch in nm[routerIP]['osmatch']:
            print('')
            print('OsMatch.name : {0}'.format(osmatch['name']))
            print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
            print('OsMatch.line : {0}'.format(osmatch['line']))
            print('')




    if 'fingerprint' in nm[routerIP]:
        print('Fingerprint : {0}'.format(nm[routerIP]['fingerprint']))


    # Vendor list for MAC address
    print('----------------------------')

    print('scanning localnet')
    nm.scan(routerIP, arguments='-O')
    for h in nm.all_hosts():
        print('Your router brand is: ')
        if 'mac' in nm[h]['addresses']:
            mac = nm[h]['addresses'].get('mac')
            print(nm[h]['vendor'].get(mac))

print('----------------------------------------------------')
