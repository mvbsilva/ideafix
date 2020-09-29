#-*- coding: UTF-8 -*-
'''
    Universidade Federal do Rio Grande do Sul
    Instituto de Informática
    Pós Graduação em Computação

    Marcus Vinicius Brito da Silva

    Implementação de Algoritmo para Gerenciamento de Tráfego na Rede IXP

    Class Fluxo
'''
import sys
import subprocess
path = 'topology_net.py'

HOP_VALUE = 1
FLAG_EF    = 32

class Fluxo():

    def __init__(self, node=None):
        self.G = {} #Grafo
        self.switch = None
        self.mac_to_port = None
        self.EF = {}
        self.flows = {}
        self.table_switch = {}
        self.switchs_edge = {}
        self.hosts = {}
        self.routes = {}
        self.routesEF = {}

        self.controller = node

        self.D = {} #vetor para as distâncias
        self.Pi = {} #dicionário para o antecessor.
        #self.dst_ip = {'h1': '10.0.0.1', 'h2':'10.0.0.2'}#'00:00:00:00:00:01', 'h2':'00:00:00:00:00:02'}
        #self.ip_mac = {'10.0.0.1': '00:00:00:00:00:01', '10.0.0.2': '00:00:00:00:00:02'}

        self.arq_flow = open('./logs/log_flow.csv', 'w')
        self.arq_flowEF = open('./logs/log_flowEF.csv', 'w')
        
        self.parser_topology(path)
        self.imprime_grafo()

        self.set_edge()

        self.setController(self.controller)
        self.calcRoutes()
        #self.calcRoutes()



    #Função para aprender a topologia da rede
    def parser_topology(self, path, flagRoutes=False):
        arq = open(path)
        data = None

        if arq:
            data = arq.readlines()

        if data is not None:
            for line in data:
                n1, n2 = line.split('<->')   #Separa o node1 do node2: "h1-eth0<->s1-eth1 (OK OK)"
                n2 = n2.split()[0]               #Separa apenas a pate "s1-eth1'' de "s1-eth1 (OK OK)"
                n1, port1 = n1.split('-eth') #Separa o nome do  node: s1; e o numero da porta: 1
                n2, port2 = n2.split('-eth')
                #print n1,n2, nodeController
                if (n1 == self.controller or n2 == self.controller) == False:
                    #print 'aaa'
                    if n1[0] == 'h' and flagRoutes == False:
                        
                        self.add_host(n1)
                        #self.switchs_edge.append(n2)

                    if n2[0] == 'h' and flagRoutes == False:
                        self.add_host(n2)
                        #self.switchs_edge.append(n1)

                    self.add_link(n1, int(port1), n2, int(port2)) #Função para inserir no grafo o link e as portas conectadas em cada node
            if flagRoutes == False:
                self.add_switchs() #Função para adicionar todos os switchs no dicionário que formará a tabela de roteamento.


    #função para conhecer os hosts e seu endereço ip e mac
    def add_host(self, host):
        if host not in self.hosts.keys():
            host_ip = '10.0.%s.10'%(host[1:])
            host_mac = '00:04:00:00:00:%02x'%(int(host[1:]))

            self.hosts[host] = {'ip': host_ip, 'mac':host_mac, 'D':{}, 'Pi':{}}

    def getIpCpntroller(self):
        if(self.controller):
            host_ip = '10.0.%s.10'%(self.controller[1:])
            return host_ip
        else:
            return None
            

    #Função para inserir os switch no grafo e seus links
    def add_switchs(self):
        nodes = self.G.keys()
        nodes.sort()
        for s in nodes:
            if s[0] == 's':
                cont = len(self.table_switch)
                self.table_switch[s] = (9090+int(s[1:]) -1) #Talvez trocar para lista, no lugar de usar dicionario.

    #Função para aprender a topologia da rede
    def set_edge(self):
        arq = open(path)
        data = None

        if arq:
            data = arq.readlines()

        if data is not None:
            for line in data:
                n1, n2 = line.split('<->')   #Separa o node1 do node2: "h1-eth0<->s1-eth1 (OK OK)"
                n2 = n2.split()[0]           #Separa apenas a pate "s1-eth1'' de "s1-eth1 (OK OK)"
                port1 = n1 
                port2 = n2
                n1, a = n1.split('-eth') #Separa o nome do  node: s1; e o numero da porta: 1
                n2, b = n2.split('-eth')
                #print n1,n2, nodeController
                if (n1 == self.controller or n2 == self.controller):
                    #print 'aaa'
                    if n1[0] == 'h':
                        self.switchs_edge[n2] = port2

                    if n2[0] == 'h':
                        self.switchs_edge[n1] = port1

    #Retorna a lista com switchs em ordem
    def list_switchs(self):
        list_s = self.table_switch.keys()
        list_s.sort()
        return list_s

    def getSwitches(self):
        if len(self.table_switch.keys()) > 0:
            return self.table_switch
        return None

    def getEdge(self):
        if(len(self.switchs_edge.keys()) > 0):
            return self.switchs_edge
        return None


   

    def add_link(self, node1, port1, node2, port2):
        #Insere  a aresta a -> b
        if (node1 not in self.G):
            self.G[node1] = {}  #Insere o nó no grafo e um dicionário para suas arestas com outros nodes.
        self.G[node1][node2] = port1    #Insere  a aresta a->b referenciada pela porta 1

        #Insere  a aresta a <- b
        if (node2 not in self.G):
            self.G[node2] = {}
        self.G[node2][node1] = port2
    

    #função para imprimir o grafo.
    def imprime_grafo(self):
        print("")
        nodes = self.G.keys()
        nodes.sort()
        for k in nodes:
            print (k, '->',self.G[k])


    def setController(self, host):
        if self.controller:
            print '\nSet Controller..'
            print '... set route controller switches...'
            for s in self.table_switch.keys():
                if s in self.switchs_edge.keys():
                    port = self.switchs_edge[s]
                    port = port.split('-eth')[1]
                    self.set_default(self.controller, s, int(port))
            print '...Done!'
            

    def set_default(self, host, switch, out_port):
        udp_port = 4321
        ipHost = '10.0.%s.10'%(host[1:])
        mac_dst = '00:04:00:00:00:%02x'%(int(host[1:]))

        mac_src  = "00:aa:00:%02x:00:%02x"%(int(switch[1:]),int(host[1:]))
        ipSwitch = '10.0.%d.9'%(int(switch[1:]))

        port_switch = self.table_switch[switch] #recupera a porta para o referido switch.
        arg = ['simple_switch_CLI', '--thrift-port', str(port_switch) ]

        tupla = (mac_src, mac_dst, ipSwitch, ipHost, udp_port, udp_port, out_port)

        p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = 'table_set_default ipv4_lpm send_controller %s %s %s %s %d %d %d'%tupla
        command = command + '\ntable_set_default ipv4_lpm_EF send_controller %s %s %s %s %d %d %d'%tupla
        #command = command + '\ntable_set_default ipv4_lpm_EF noPathEF'

        command = command + '\ntable_set_default icmp_lpm send_controller %s %s %s %s %d %d %d'%tupla
        command = command + '\ntable_set_default icmp_lpm_EF send_controller %s %s %s %s %d %d %d'%tupla

        command = command + '\ntable_set_default map_controller send_controller_EF %s %s %s %s %d %d \nmirroring_add 42 %d'%tupla

        out, error = p.communicate(command)


    ###########################################
    ### #          CONTROLE DE FLUXOS, ALGORITMO DE ROTAS          ####
    ###########################################

    def calcRoutes(self):
        for host in self.hosts:
            self.routes[host]   = {}
            self.routesEF[host] = {}
            self.D = {}
            self.Pi = {}
            #self.imprime_grafo()
            flagHost = None

            self.dijkstra(host)
            for h in self.hosts.keys():         #Recupera alista de cada host
                if h is not host  and h in self.D.keys():          #Veifica se existe um alcanse da origem para o host destino.
                    self.routes[host][h] = self.BPP(host, h)     #Rertorna a lista com o melhor caminha primario
                    #print self.routes[host][h], self.hostController
                    if h != self.controller:
                        s1 = self.routes[host][h][len(self.routes[host][h])-2]
                        s2 = self.routes[host][h][len(self.routes[host][h])-3]
                        #print s1,s2
                        del self.G[s1][s2]
                        del self.G[s2][s1]
                        if flagHost is None:
                            flagHost = h

            if  flagHost:
                s1 = self.routes[host][flagHost][1]
                s2 = self.routes[host][flagHost][2]
                #print s1,s2
                del self.G[s1][s2]
                del self.G[s2][s1]


            #Calcula o   caminho alternativo
            #self.imprime_grafo()
            self.D = {}
            self.Pi = {}
            self.dijkstra(host)

            for h in self.hosts.keys():         #Recupera alista de cada host
                if h is not host  and h in self.D.keys():          #Veifica se existe um alcanse da origem para o host destino.
                    self.routesEF[host][h] = self.BPP(host, h)     #Retorna a lista com o caminho alternativo,

            self.G = {}
            self.parser_topology(path, True)


    def newFlow(self, ipSrc, ipDst,  proto, tupla):
        #tupla = (ipSrc, ipDst, proto, ident)
        if tupla not in self.flows.keys():
            src = self.getHost_IP(ipSrc)
            dst = self.getHost_IP(ipDst)

            route = self.getRoute(src, dst)  #Verifica se existe uma rota calculada entre src-dst.
            #print self.routes
            print src,'->',dst
            #print route
            if(route is not None):
                self.flows[tupla] = list(route)
                switch = route[1]
                h2  = route[2]
                n1  = route.pop()
                n2  = route.pop()
                self.insere_fluxo_A(dst, src, n1, n2, tupla, route)

                data = ''
                for i in tupla:
                    data =  data + '%s,'%(str(i))
                data =  data + '%s-eth%d,%s-eth%d\n'%(switch, self.G[switch][src], switch, self.G[switch][h2])
                self.arq_flow.write(data)

                return True
            else:
                # if(src != None and dst != None):
                #     self.D = {}
                #     self.Pi = {}
                #     #self.imprime_grafo()
                #     self.dijkstra(src)
                #     #print('')
                #     if dst in self.D.keys():
                #         min_key  = min(self.D[dst].keys())
                #         n2 = self.D[dst][min_key][0]    #primeiro alcanse para 'h'
                #         if n2 != dst: #Verifica se o elemento não aponta para si próprio.
                #             #print ('\nFluxo: ', h)
                #             self.flows[tupla] = []
                #             self.insere_fluxo_A(dst, src, dst, n2, tupla)
                #             return True
                return False
        else:
            print('Fluxo ja calculado')
        return False

    def upFlow(self, ipSrc, ipDst, proto, tupla):
        #tupla = (ipSrc, ipDst, proto, ident)

        if tupla not in self.EF.keys():
            src = self.getHost_IP(ipSrc)
            dst = self.getHost_IP(ipDst)

            #route = self.getRouteEF(src, dst)  #Verifica se existe uma rota calculada entre src-dst.
            route = self.getRouteEF(src, dst)  #Verifica se existe uma rota calculada entre src-dst.
            if(route is not None):
                #print 'listaaaa[', route,']'
                n1  = route.pop()
                n2  = route.pop()
                self.insere_fluxo_A(dst, src, n1, n2, tupla, route, flag_EF = True)
                #self.EF[tupla] = list(route)
                return True
            else:
                if(src != None and dst != None):
                    self.D = {}
                    self.Pi = {}
                    self.imprime_grafo()
                    self.dijkstra(src)
                    #print tupla
                    if dst in self.D.keys():
                        route = self.BSP(src, dst)
                        #print(route)
                        n1  = route.pop()
                        n2  = route.pop()
                        self.insere_fluxo_A(dst, src, n1, n2, tupla,  route, flag_EF = True)
                        #self.EF[tupla] = route
                        return True
        return False

    def getRoute(self, src, dst):
        if( src in self.routes.keys()):
            if(dst in self.routes[src].keys()):
                return list(self.routes[src][dst])
        return None




    def getRouteEF(self, src, dst):
        if( src in self.routesEF.keys()):
            if(dst in self.routesEF[src].keys()):
                return list(self.routesEF[src][dst])
        return None


    def insertEF(self, tupla):
        #insere o fluxo identificado na lista.
        self.EF[tupla] = []

        src = self.getHost_IP(tupla[0])
        dst = self.getHost_IP(tupla[1])
        route = self.getRouteEF(src, dst)  #Verifica se existe uma rota calculada entre src-dst.
        switch = route[1]
        #h1  = route[0]
        h2  = route[2]
        data = ''
        for i in tupla:
            data =  data + '%s,'%(str(i))
        data =  data + '%s-eth%d,%s-eth%d\n'%(switch, self.G[switch][src], switch, self.G[switch][h2])
        self.arq_flowEF.write(data)


    def getEF_List(self, tupla):
        if tupla in self.EF.keys():
            return True
        else:
            return False
    

    def getHost_IP(self, ipv4):
        for k in self.hosts.keys():
            if(self.hosts[k]['ip'] == ipv4):
                return k
        return None


    #Função para Algoritmo de Dijkstra
    def dijkstra(self, node):

        nodes = self.G.keys()
        nodes.sort()
        visit = nodes   #Lista de visitados


        #Laço para o processamento de cada nó.
        while True:
            #Verifica se o nó já foi visitado.
            if (node in self.D.keys()) == False:
                self.D[node] = {}  #Inicia o 'vetor' distância
                self.D[node][0] = [node]

            min_node = min(self.D[node].keys()) #Menor distância atribuida ao node
            #laço para percorrer cade visinho do nó atual
            for v in self.G[node].keys():
                #verifica se o  visinho já possui alguma distância atribuida.
                if  v in self.D.keys():
                    #Atribui uma nova distância, e seu respectivo nó de chegada.
                    if v in visit: #Verifica se o visinho ainda não foi processado, caso tenha sido, ignora a rota.
                        cust = min_node + HOP_VALUE #+ self.calc_cust_table(node, v)
                        if cust in self.D[v].keys():
                            self.D[v][cust].append(node)
                        else:
                             self.D[v][cust] = [node]
                    else:
                        pass
                else:
                    #estabelce uma nova distância para o visinho visitado.
                    self.D[v] = {}
                    cust = min_node + HOP_VALUE #+ self.calc_cust_table(node, v)
                    self.D[v][cust] = [node]

            #Procura do nó com menor distância para a ser processado.
            aux_dist = None
            aux_node = None
            visit.remove(node) #Remove o nó atual da lista de processamento.
            for i in visit:
                if i in self.D.keys():
                    min_node  = min(self.D[i].keys())
                    if aux_dist == None or aux_dist > min_node:
                        aux_dist = min_node
                        aux_node = i

            if aux_node == None:
                break

            node = aux_node


        self.imprime_dijkstra()


    #retorna uma lista com os nodes que compoem o caminho  caminho alternativo (src->dst)
    def BSP(self, src, dst):
        bapList = [dst]
        while  True:
            nodes = self.D[dst].keys()
            nodes.sort()
            if len(nodes) > 1:
                nodes = self.D[dst][nodes[1]]
            else:
                nodes = self.D[dst][nodes[0]]
            if len(nodes) > 1:
                node = nodes[1]
            else:
                node = nodes[0]
            bapList.insert(0,node)
            if node == src:
                break
            else:
                dst = node
        return bapList

    #retorna uma lista com os nodes que compoem o primeiro melhor caminho (src->dst)
    def BPP(self, src, dst):
        bapList = [dst]
        while  True:
            ind = min(self.D[dst].keys())
            node = self.D[dst][ind][0]
            bapList.insert(0,node)
            if node == src:
                break
            else:
                dst = node
        return bapList






    #função para imprimir o resultado do algoritmo de Dijkstra
    def imprime_dijkstra(self):
        nodes = self.D.keys()
        nodes.sort()
        print ('\nDijkstra\n')
        for k in nodes:
            print (k, self.D[k])


    #Função para inserir o fluxo e a tabela para um enlace.
    def insere_fluxo_A(self, dst, src, n1, n2, tupla, bap = None, flag_set_controller=False, flag_invert_direct=False, flag_EF=False):
        #Verifica se o host é um switch, se for um switch, chama a função para inserir a flow.
        #Caso seja um host, agnora, pois nao ha o que setar no host.
        if(flag_EF == True):
            difServ = FLAG_EF
        else:
            difServ = 0
        

        if(flag_set_controller == True):
            difServ = 50       

        if n2 in self.table_switch.keys():
            #print ('\nSrc= %s Dst= %s In: %s Out_port: %d  Pdst: %s'%(src,dst, n2,self.G[n2][n1], n1))

            #Seleciona a porta de saida e o mac do destino
            out_port  = self.G[n2][n1] #retorna o valor associado a porta para 'n1' na lista de 'n'

            #Verifica se o destino é um host ou um switch
            if n1 in self.hosts.keys():
                #Realiza uma busca pelo endereço MAC na tabela de host's.
                mac_src = "00:aa:00:%02x:00:%02x"%(int(n2[1:]),int(n1[1:]))
                mac_dst = self.hosts[n1]['mac'] #'n1' é o endereço que irá receber o pacote. Neste caso, um host: 'h1', 'h2'......
                
                if flag_set_controller is False: #ARRUMAR ISSO
                    difServ = 0  #indica que o identificador é o host.
            else:
                #Recupera o MAC da pota que irá receber o pacote.
                mac_src = "00:aa:00:%02x:%02x:00"%(int(n2[1:]),int(n1[1:]))
                mac_dst = "00:aa:00:%02x:%02x:00"%(int(n1[1:]),int(n2[1:]))

            ##Chamada da função para inserir a regra.
            #print( n2, tupla,  mac_dst, out_port)
            self.add_flow( n2, tupla, mac_src, mac_dst, out_port, difServ, flag_set_controller,flag_EF)

            #Verifica se existe uma rota secundaria estabelecida.
            if(flag_set_controller is True):
                if(flag_invert_direct == True):
                    min_key  = min(self.D[n1].keys())
                    n2 = self.D[n1][min_key][0]    #primeiro alcanse para 'n1'
                    self.insere_fluxo_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)
                else: 
                    min_key  = min(self.D[n2].keys())
                    n1 = self.D[n2][min_key][0]    #primeiro alcanse para 'n2'
                    self.insere_fluxo_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)
            else:
                if bap:
                    n1 = bap.pop()
                else:
                    min_key  = min(self.D[n2].keys())
                    n1 = self.D[n2][min_key][0]    #primeiro alcanse para 'n2'
                self.insere_fluxo_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)


    #Função para adicionar o flow no switch
    def add_flow(self, switch, tupla, mac_src, mac_dst, out_port, flag_ToS, flag_set_controller=False, flag_EF=False):
        port_switch = self.table_switch[switch] #recupera a porta para o referido switch.
        match = ""
        arg = ['simple_switch_CLI', '--thrift-port', str(port_switch) ]
        #print(arg)
        #if(flag_set_controller is False):

        p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #Comando para inserir uma nova regra de repasse.
        if tupla:
            for data in tupla:
                if data is not None:
                    match = match + " " + str(data)
            if(len(tupla) == 5):
                table = 'ipv4_lpm'
            if(len(tupla) == 4):
                table = 'icmp_lpm'
        if(flag_EF is True):
            table = table+'_EF'
        #print table
        command = 'table_add %s ipv4_forward %s  => %s %s %d %d'%(table, match, mac_src, mac_dst, out_port, flag_ToS)
        out, error = p.communicate(command)
        



#Inicio do programa.
if __name__ == '__main__':

    print ('Inicio')
    F = Fluxo()
    F.setController("h9")
    F.calcRoutes()
    print(F.hosts)
    #print(F.table_switch)
    F.dijkstra('h1')
    print('\n')
    print(F.routes)
    print(F.routesEF)
   

    for h,dic  in F.routes.items():
        for h2, rota in dic.items():
            print h,h2, rota
            print h,h2, F.routesEF[h][h2],"\n"


    print "\nRouta EF"

    for h,dic  in F.routesEF.items():
        for h2, rota in dic.items():
            print h,h2, rota

    
