#!/usr/bin/env python3
from scapy.all import *
import codecs
from time import sleep 
from threading import Lock, Thread 
import sys
import argparse

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
  def listen(self): 
    while 1: 
      sniff(iface=self.interface, prn=self.display_msg, filter="icmp and icmp[0]=0", store=0, count=10)
      sleep(1)
      
  def receive_input(self): 
    while 1: 
      print('')
      text=input("Type to send: ")
      MESSAGE(self.dstip).send_msg(text)
      sleep(1)

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
    parser.add_argument('-i', type=str, default='eth0', help='Local interface name to send and listen')
    args = parser.parse_args()
    dstip = args.__dict__.get('d')
    interface = args.__dict__.get('i')
    print("Starting chat with "+dstip+' on '+interface+' !') 
    
    threads = []
    for func in [CHAT(dstip,interface).listen,CHAT(dstip,interface).receive_input]: 
        threads.append(Thread(target=func)) 
        threads[-1].start()
       
if __name__== '__main__':
    main()