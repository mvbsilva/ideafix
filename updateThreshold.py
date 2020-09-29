#-*- coding: UTF-8 -*-
'''
    Universidade Federal do Rio Grande do Sul
    Instituto de Informática
    Pós Graduação em Computação

    Marcus Vinicius Brito da Silva

    Classe para atualização dos limiares em tempo de execução.

'''


import subprocess

#Valores Iniciais
LIMIAR_TIME = 15       #Segundos
TIME_OUT     = 5     #Segundos
LIMIAR_SIZE =  15*(10**6)    #Bytes

class UpdateThreshold():

    def __init__(self, switches, edge, time, size, timeOut):
        self.switches = switches
        self.switches_edge = edge
        self.time  = time*(10**6)
        self.size  = size
        self.timeOut = timeOut*(10**6)


    def update(self):
        print("UPDATE_SWITCHES")

        for s in self.switches:
            pid = self.switches[s]
            if s in self.switches_edge:
                flagEdge = 2    #Indica que eh uma borda.
            else:
                flagEdge = 1    #india que nao eh borda.

            arg = ['simple_switch_CLI', '--thrift-port', '%d'%(pid) ]
            print(arg)
            #command = 'table_set_default limiar_time add_limiar_time %s'%(time)
            #print(command)
            ipSwitch = '10.0.%d.9'%(int(s[1:]))

            p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            command = 'table_set_default get_features set_features %s %d'%(ipSwitch, flagEdge)
            command = command +'\n'+ 'table_set_default get_limiar set_limiar %d %d %d'%(self.timeOut, self.time, self.size)
         
            command = command +'\n'+ 'table_set_default get_flag_white set_flag_white 0'
            command = command +'\n'+ 'table_add get_flag_white set_flag_white  0x00000009&&&0x0000000f 0x00000000&&&0x00000000 => 1 1'
            command = command +'\n'+ 'table_add get_flag_white set_flag_white  0x00000000&&&0x00000000 0x00000009&&&0x0000000f => 1 1'
           
            command = command +'\n'+ 'table_set_default get_flag_host set_flag_host 0'
            command = command +'\n'+ 'table_add get_flag_host set_flag_host 0x000400000000&&&0xffff00000000 => 1 1'

            out, error = p.communicate(command)
            #print(out)




#Begin.
if __name__ == '__main__':

    print ('Realizando Updates')
    switches = {}
    obj = UpdateThreshold(switches, LIMIAR_TIME, LIMIAR_SIZE, TIME_OUT) #cria o objeto
    obj.update()
