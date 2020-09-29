#-*- coding: UTF-8 -*-
'''
    Universidade Federal do Rio Grande do Sul
    Instituto de Informática
    Pós Graduação em Computação

    Marcus Vinicius Brito da Silva

    Implementação do sniffer de interface entre switches e controlador.

'''
#!/usr/bin/env python
#https://www.materialui.co/colors

import argparse
import sys
import socket
import random
import struct
from controller import Fluxo
from updateThreshold import UpdateThreshold
from learning import Learn

import numpy as np 
import math
import pylab as pl
from scipy import stats
import time

from scapy.all import sniff, sendp
from scapy.all import Packet, IPOption
# from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether,IP, UDP, TCP, Raw, ICMP, Padding
#from scapy.layers.inet import _IPOption_HDR
#import subprocess

import  thread, select, string

TIME_OUT    = 15    #Segundos
LIMIAR_TIME = 6     #Segundos
LIMIAR_SIZE = 1000000    #Bytes

#TCP FLAGS:
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


list_ther = []

def handle_pkt(pkt, flow, learn, iface, ipController):
    print("got a packet")
    #pkt.show()
    #e =  pkt.summary()
    #print e
    tos = 0
    flagFim = 0

    if(pkt[0][Ether].type == 0x800):
        tos = pkt[0][IP].tos
        if(pkt[0][IP].dst == ipController and (tos == 20 or tos == 32)):
            #print ('Ipv4')
            
            if(pkt[0][IP].proto == 0x20):
                #print('UDP')
                #pkt2 =Ether(pkt[0][Raw].load)
                # print pkt.summary()
                #print pkt[0][Raw].load[:18]
                #pkt.show()
                #print pkt[0][Raw].load
                udpSS = pkt[0][Raw].load[0:2]
                udpDD = pkt[0][Raw].load[2:4]
                tamPP = pkt[0][Raw].load[4:6]
                
                testP  = pkt[0][Raw].load[8:10]
                

                time = pkt[0][Raw].load[10:16]

                testPP = pkt[0][Raw].load[16:18]
                #time = int(time,16)
                size = pkt[0][Raw].load[18:22]

                # print 'MetaData..'
                # print int( udpSS.encode('hex'), 16)
                # print int( udpDD.encode('hex'), 16)
                # print int( tamPP.encode('hex'), 16)
                
                #print int( testP.encode('hex'), 16)
                #print int( testPP.encode('hex'), 16)

                timeFLOW = int( time.encode('hex'), 16)/(10**6)
                sizeFLOW = int( size.encode('hex'), 16)

                #print timeFLOW
                #print sizeFLOW
                #size = int(size,16)
                #print time
                #print size




                #print time, size, 'Aquiiiiiii'

                if (Padding in pkt[0]):
                    pkt2 =Ether(pkt[0][Raw].load[22:]+pkt[0][Padding].load)
                else:
                    pkt2 =Ether(pkt[0][Raw].load[22:])
                #pkt2.show()
                # print pkt2.summary()
                
                #e =  pkt2.summary()
                #print e
                ipSrc  = pkt2[0][IP].src
                ipDst  = pkt2[0][IP].dst
                proto  = pkt2[0][IP].proto
                if(proto == 0x1): #Protocolo ICMP
                    ident  = pkt2[0][ICMP].id
                    tupla = (ipSrc, ipDst, proto, ident)
                elif(proto == 0x11): #Protocolo UDP
                    srcPort = pkt2[0][UDP].sport
                    dstPort = pkt2[0][UDP].dport
                    tupla = (ipSrc, ipDst, proto, srcPort, dstPort)
                elif(proto == 0x6): #Protocolo TCP
                    srcPort = pkt2[0][TCP].sport
                    dstPort = pkt2[0][TCP].dport
                    tupla = (ipSrc, ipDst, proto, srcPort, dstPort)
                    #Se for um pacote de finalizacao:
                    F = pkt2[0][TCP].flags
                    #print "flags...",F
                    if F & FIN:
                        flagFim = 1

                #print tos,tupla

                if tos == 20: #Indica novo fluxo
                    #print("\nNewFlow"),tupla
                    #pkt.show()
                    #flow.imprime_grafo()
                    #print tupla
                    resul = flow.newFlow(ipSrc, ipDst, proto, tupla)

                    srcMac = pkt[0][Ether].src
                    pkt[0][Ether].src = pkt[0][Ether].dst
                    pkt[0][Ether].dst = srcMac

                    src= pkt[0][IP].src
                    pkt[0][IP].src = pkt[0][IP].dst
                    pkt[0][IP].dst = src
                    pkt[0][IP].tll = 64
                    pkt[0][IP].chksum = 0

                    sendp(pkt, iface=iface)

                    if resul:
                        #del pkt[0][IP].chksum
                        resul = flow.upFlow(ipSrc, ipDst, proto, tupla)
                        #print"...Processado com sucesso!"
                
                #Sinaliza o final de um fluxo
                if flagFim == 1:
                    flagEF = flow.getEF_List(tupla)
                    learn.setFlow(tupla, time, size, flagEF) #insere um fluxo na base de dados
                    print "END of FLOW!\n", tupla, timeFLOW, sizeFLOW

                elif tos == 32: #Indica EF.
                    #print("EF")
                    if(flow.getEF_List(tupla)):
                        print'\nEF ja identificado!'
                        
                    else:
                        #resul = flow.upFlow(ipSrc, ipDst, proto, tupla)
                        flow.insertEF(tupla)
                        print"\nEF NOVA IDENTIFICACAO!\n", tupla, timeFLOW, sizeFLOW
                        # for i in tupla:
                        #     arq.write(str(i)+' ')
                        # arq.write('\n')
                    #else:

                        #resul = flow.upFlow(ipSrc, ipDst, proto, tupla)
                        #if resul:
                        #    print("Processado com sucesso!")
                        # else:
                        #     print("FALHA no processamento!")


    sys.stdout.flush()



def sniffing_start(iface, flow, learn, ipController):
    #iface = 's1-eth1'
    # file = 'log-EF-%s.txt'%(1)
    # arq = open(file, 'w')
    # print ("sniffing on %s" % iface)

    sys.stdout.flush()
    #sniff(filter="udp and port 4321", iface = iface,
    sniff(filter="ip proto 32", iface = iface,
      prn = lambda x: handle_pkt(x, flow, learn, iface, ipController))
    print('end %s'%(iface))

    #print 'aajahaha'
    list_ther.remove(iface)
    #arq.close()


def main():
    
    hostController = 'h9'
    flow  = Fluxo(hostController)
    learn = Learn()
    #iface = flow.setController(hostController)
    #flow.calcRoutes()
    #flow.set_edge()
    switches     = flow.getSwitches()
    edge         = flow.getEdge()
    ipController = flow.getIpCpntroller()


    #print switches
    print edge
    print ipController
    #print iface 

    #flow.imprime_grafo()  
    
    for h,dic  in flow.routes.items():
        for h2, rota in dic.items():
            print h,h2, rota
            print h,h2, flow.routesEF[h][h2],"\n"



    if switches is not None:
        print("SET_TABLES....")
        obj = UpdateThreshold(switches, edge.keys(), LIMIAR_TIME, LIMIAR_SIZE, TIME_OUT) #cria o objeto
        obj.update()
        print("SET_TABLES....COMPLETE!")
    else:
        print("ERROR: SWITCHES IDENTIFICATION!") 

    try:
        threads_sniff = []
        for s, iface in edge.items():
            print 'Sniffing %s'%(iface)
            list_ther.append(iface)
            threads_sniff.append( thread.start_new_thread(sniffing_start, (iface, flow, learn, ipController)))
            #sniffing_start(iface, flow, ipController)

        while list_ther:
            pass
 
    except KeyboardInterrupt:
        print "End!"


if __name__ == '__main__':
    main()
