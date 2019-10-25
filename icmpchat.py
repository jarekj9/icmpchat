#!/usr/bin/env python3
from scapy.all import *
import codecs
from time import sleep 
from threading import Lock, Thread 
import sys
import argparse
import os

#handle listening and displaying messages
class CHAT():
  
  def __init__(self,dstip,interface):
    self.dstip=dstip
    self.interface=interface
  
  def display_msg(self,pkt):
    try:
        print('')
        print('Received message: '+(pkt.load).decode())  
    except:pass
  
  #sniffing for icmp packets  
  def listen(self):
    try:
        while 1: 
            sniff(iface=self.interface, prn=self.display_msg, filter="host "+self.dstip+" and icmp and icmp[0]=0", store=0, count=10)
    except:
        print('\r\nError: Could not start sniffing for icmp packets on interface: '+self.interface)
        os._exit(0)
        
  #accept input text and send it to peer 
  def receive_input(self): 
    while 1: 
      print('')
      text=input("Type to send: ")
      if text == 'exit()': os._exit(0)    
      MESSAGE(self.dstip).send_msg(text)
      sleep(0)
      
  #if interface is not specified, it tries to find it automatically  
  def get_interface(self):
    cmd = os.popen("ip r g "+self.dstip).read()
    try: 
        interface = cmd.split('dev ')[1].split(' ')[0]
    except:
        print('Failed to detect interface with command ip r g, using default eth0, maybe try to set it with -i flag')
        interface = 'eth0'

    return interface
  

#sending message
class MESSAGE():
  def __init__(self,dstip):
    self.ip_part=IP(dst=dstip)
    self.icmp_part=ICMP(type=0)
    
  def send_msg(self,text):
    packet=self.ip_part/self.icmp_part/text    #joining 2 parts into 1 packet
    sys.stdout = open(os.devnull, 'w') #blocks message 'Sent 1 packets.'
    send(packet)
    sys.stdout = sys.__stdout__


def main():
    parser = argparse.ArgumentParser(description='Please run as root and specify destination ip with -d flag')
    parser.add_argument('-d', type=str, help='Destination IP')
    parser.add_argument('-i', type=str, default=None, help='Local interface name to send and listen, by default it will try to find it automatically')
    args = parser.parse_args()
    
    if args.d == None: 
        print('Please check options with -h flag')
        exit(0)
    
    dstip = args.__dict__.get('d')
    if args.i: interface = args.__dict__.get('i')
    else:
        interface = CHAT(dstip,'').get_interface()
    
    
    
    print("Starting chat with "+dstip+' on '+interface+' ! Type exit() to exit')    
    
    #adding 2 threads: one for sniffing icmp, second for text input
    CHAT(dstip,interface).get_interface()
    threads = []
    for func in [CHAT(dstip,interface).listen,CHAT(dstip,interface).receive_input]: 
        threads.append(Thread(target=func)) 
        threads[-1].start()
       
if __name__== '__main__':
    main()