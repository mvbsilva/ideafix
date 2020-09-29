#-*- coding: UTF-8 -*-
#Gerador de fluxos por iPerf 3

import subprocess
from datetime import datetime
from time     import time
import numpy as np
import os

import signal

controller = "h9"

l = 400
b = 2240
niceFlow = 4
t = 13

M_PATH = '/home/sdn/mininet/util/m'

PRE_NUM_PORT = 570

N_RODADAS = 2

TIME  =  100

perct_EF = 1

list_hosts = []

#Função para aprender a topologia da rede
def parser_topology():
    arq = open('topology_net.py')
    data = None
    list_ifaces = []
    if arq:
        data = arq.readlines()
    arq.close()
    if data is not None:
        for line in data:
            n1, n2 = line.split('<->') #Separa o node1 do node2: "h1-eth0<->s1-eth1 (OK OK)"
            n2 = n2.split()[0] #Separa apenas a pate "s1-eth1'' de "s1-eth1 (OK OK)"
            n1, port1 = n1.split('-eth') #Separa o nome do  node: s1; e o numero da porta: 1
            n2, port2 = n2.split('-eth')

            if n1[0] == 'h' and n1 != controller:
               list_hosts.append(n1)

            if n2[0] == 'h' and n2 != controller:
                list_hosts.append(n2)
    return list_hosts


if __name__ == '__main__':


    hosts = parser_topology()
    arq = open('./flows.txt', 'w')

    pList = []

    nHosts  = len(hosts)
    qFlows  = nHosts*(nHosts-1)
    qtdFlowTotal = qFlows * N_RODADAS
    qtdFlowHost = (nHosts-1)* N_RODADAS
    rodada = N_RODADAS
    qtdEF   = int(qtdFlowHost*perct_EF)
    qtdEF = 7
    timeS  = t
    print("totalFlows: %d, Rodadas: %s, qtdHost: %d, qtdEF: %d"%(qtdFlowTotal, rodada, qtdFlowHost, qtdEF))
    contFlow = 0
    for h in hosts:
        contFlow = 0
        for j in range(0, rodada):
            for h2 in hosts:
                if h2 != h:
                    if contFlow < qtdEF:
                        timeS =  t
                    else:
                        timeS = niceFlow
                    start = np.random.randint(0,(TIME-t))
                    porta = "%d%s%s"%(PRE_NUM_PORT+j,h[1:],h2[1:])
                    print( h, h2, porta, timeS, start)
                    dado = "%s %s %s %d %d\n"%(h, h2, porta, timeS, start)
                    arq.write(dado)
                    command = str('m %s iperf3 -c %s -u -l%d -b%d -t%d '%(h,h2,l,b,timeS))
                    arg = command.split()
                    #print command
                    contFlow = contFlow + 1
        #break


