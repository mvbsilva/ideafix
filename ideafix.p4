/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_CONTROLLER = 0x20;
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  TCP_PROTOCOL = 0x6;
const bit<16> TYPE_IPV4 = 0x800;
//const bit<5>  IPV4_OPTION_MRI = 31;
const bit<32> ID_CLONE = 42;
//const bit<16> PORT_CONTROLLER = 4302;


      /*  Define the useful global constants for your program */
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  FLAG_EF        = 32; //00100000  //Fluxo Elefante.
const bit<8>  FLAG_NF        = 20; //00100000  //Fluxo de Controle.
//const bit<32> LimiarBytes    = 512;
//Time em microsegundos
//const bit<48> TIME_OUT       = 15000000; //15 segundos.
//const bit<48> LimiarTime     = 5000000;  //5 segundos.

const bit<16> REG_SIZE        = 0xffff;   // Tamanho dos registradores.

#define T  32   //Valor para o tamanho das celulas do registrador.

#define MAX_HOPS 9


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<48> timer_t;
typedef bit<32> size_tt;
typedef bit<8>  protocol_t;
typedef bit<16> port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>    diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>    flags;
    bit<13>  fragOffset;
    bit<8>    ttl;
    protocol_t  protocol;
    bit<16>    hdrChecksum;
    ip4Addr_t  srcAddr;
    ip4Addr_t  dstAddr;
}

header udp_t{
    port_t srcPort;
    port_t dstPort;
    bit<16> length;
    bit<16> checksumUdp;
}

header udp_tc{
    port_t srcPort;
    port_t dstPort;
    bit<16> length;
    bit<16> checksumUdp;
    port_t  testeP;
    timer_t timeFlowUDP;
    port_t  testePP;
    size_tt sizeFlowUDP;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<5>  ctrl;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> identif;
}

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;


struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}


struct intrinsic_metadata_t {
    //bit<16>   recirculate_flag;
    bit<1>  recirculate_flag;
    //bit<16>   modify_and_resubmit_flag;
}

struct metadata {
    @metadata @name("intrinsic_metadata")
    intrinsic_metadata_t intrinsic_metadata;
    
    size_tt limiarBytes;
    timer_t timeOut;
    timer_t limiarTime;
    size_tt flowSize;
    timer_t flowTime;

    ip4Addr_t ipSwitch;
    ip4Addr_t ipvAddr;
    port_t srcPort;
    port_t dstPort;
    bit<8> flagWhite;
    //bit<8> flagEnvioEF;
    bit<8> flagEdge;
    bit<8> flagHost;
    bit<1> flagRecirculate;
    bit<1> flagFin;

    
}

struct headers {
    ethernet_t   ethernetController;
    ipv4_t       ipv4Controller;
    udp_t        updController;

    udp_tc       updNewController;

    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    udp_t        udp;
    tcp_t        tcp;
}


error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
out headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            //ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
   

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //meta.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP   : parse_icmp;
            UDP_CONTROLLER : parse_udp_controller; 
            UDP_PROTOCOL   : parse_udp;
            TCP_PROTOCOL   : parse_tcp;
            default        : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }


    state parse_udp_controller {
        packet.extract(hdr.updNewController);
        transition accept;
    }


    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    

      state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
        
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop();
    }

    // action noPathEF(){
    //     meta.flagEnvioEF = 0;
    // }


    action send_controller(macAddr_t srcAddr, macAddr_t dstAddr, ip4Addr_t ipSrc, ip4Addr_t ipDst,
                            port_t srcPort, port_t dstPort,  egressSpec_t port){

        hdr.ethernetController.setValid();
        hdr.ipv4Controller.setValid();
        hdr.updNewController.setValid();

        standard_metadata.egress_spec    = port;
        hdr.ethernetController.srcAddr   = srcAddr;
        hdr.ethernetController.dstAddr   = dstAddr;
        hdr.ethernetController.etherType = TYPE_IPV4;


        hdr.ipv4Controller.version        = hdr.ipv4.version;
        hdr.ipv4Controller.ihl            = hdr.ipv4.ihl;
        hdr.ipv4Controller.diffserv       = FLAG_NF; //Flag Elephant FLow
        hdr.ipv4Controller.totalLen       = ((bit<16>)standard_metadata.packet_length) + 20+ 8;
        hdr.ipv4Controller.identification = 0;
        hdr.ipv4Controller.flags          = 0;
        hdr.ipv4Controller.fragOffset    = hdr.ipv4.fragOffset;
        hdr.ipv4Controller.ttl            = 64;
        hdr.ipv4Controller.srcAddr        = ipSrc;
        hdr.ipv4Controller.dstAddr        = ipDst;
        hdr.ipv4Controller.protocol       = UDP_CONTROLLER;

        /*
        hdr.updController.srcPort       = srcPort;
        hdr.updController.dstPort       = dstPort;
        hdr.updController.length        = ((bit<16>)standard_metadata.packet_length);
        hdr.updController.checksumUdp   = 0x0000;
        */
        hdr.updNewController.srcPort       = srcPort;
        hdr.updNewController.dstPort       = dstPort;
        //hdr.updNewController.length        = ((bit<16>)standard_metadata.packet_length)+8+10; //Packet + ipH + udpH + time + size
        hdr.updNewController.length        = 8+10; //Packet + ipH + udpH + time + size
        hdr.updNewController.checksumUdp   = 0x0000;
        
        hdr.updNewController.testeP    = 0x15b3;
        

        hdr.updNewController.timeFlowUDP   = meta.flowTime;
        hdr.updNewController.testePP   = 0x1e61;
        hdr.updNewController.sizeFlowUDP   = meta.flowSize;

        //truncate(0);

    }

    action ipv4_forward(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port, bit<8> tos) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if(tos != 50){
            hdr.ipv4.diffserv = tos; //Seta o tipo de fluxo.
        }
        //meta.flagEnvioEF = 1; //Flag para marcar que o caminho foi encontrado.
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            meta.srcPort     : exact;
            meta.dstPort     : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm_EF {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            meta.srcPort     : exact;
            meta.dstPort     : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            //noPathEF;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table icmp_lpm {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.icmp.identif : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table icmp_lpm_EF {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.icmp.identif : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    action set_features(ip4Addr_t ipSwitch, bit<8> flag){
        meta.ipSwitch = ipSwitch;
        meta.flagEdge = flag;
    }

    table get_features {
        actions        = { set_features; NoAction; }
        default_action =  NoAction();
    }


    action set_limiar(timer_t timeOut, timer_t time, size_tt size){
        meta.timeOut     = timeOut;
        meta.limiarTime  = time;
        meta.limiarBytes = size;
    }

    table get_limiar {
        actions        = { set_limiar; NoAction; }
        default_action =  NoAction();
    }


    action set_flag_white(bit<8> flag){
        meta.flagWhite = flag;
    }

    table get_flag_white{
        key = {
            //meta.ipvAddr : exact;
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions        = { set_flag_white; NoAction; }
        default_action =  NoAction();
        // const entries = {
        //     ( 0x0a00010a  ): set_flag_white(1);
        // }
    }

    action set_flag_host(bit<8> flag){
        meta.flagHost = flag;
    }

    table get_flag_host{
        key = {
            //meta.ipvAddr : exact;
            hdr.ethernet.srcAddr: ternary;
            //hdr.ethernet.dstAddr: ternary;
        }
        actions        = { set_flag_host; NoAction; }
        default_action =  NoAction();
        // const entries = {
        //     ( 0x0a00010a  ): set_flag_white(1);
        // }
    }


    /****************************
            Analise EF.
    ****************************/

    //*** REGISTRADORES
    register<bit<32>>(0xffff) regsSizeFlow;     //Registrador para armazenar o volume de trafego do fluxo.
    register<bit<48>>(0xffff) regsTimeFirst;    //Registrador para armazenar o tempo de chegada do primeiro pacote.
    register<bit<48>>(0xffff) regsTimeLast;     //Registrador para armazenar o tempo de chegada do ultimo pacote.
    register<bit<1>> (0xffff) regsEF;           //Registrador para armazenar o tempo de chegada do ultimo pacote.

    register<bit<32>>(0xffff) regsSizeFlow_2;   //Registrador para armazenar o volume de trafego do fluxo.
    register<bit<48>>(0xffff) regsTimeFirst_2;  //Registrador para armazenar o tempo de chegada do primeiro pacote.
    register<bit<48>>(0xffff) regsTimeLast_2;   //Registrador para armazenar o tempo de chegada do ultimo pacote.
    register<bit<1>> (0xffff) regsEF_2;         //Registrador para armazenar o tempo de chegada do ultimo pacote.

    register<ip4Addr_t>(1) regsIpSwitch;      //Registrador para armazenar o endereco do switch.
    register<bit<8>>(1) regsFlagEdge;         //Flag para indicar se eh um switch de borda.

    //Variavel auxiliares para os features do switch.
    ip4Addr_t ipSwitch;
    bit<8> flagEdge;


    //Variaveis auxiliares para cahves hash.
    bit<32> keyCRC;
    bit<32> keyCSUM;
    bit<32> index;
    bit<1>  flagEF;
    bit<1>  flagEF_2;
    bit<1>  flagNF;
    bit<1>  flagNF_2;

    //variaveis para volume em bytes
    bit<32> cont;
    bit<32> contSum;
    bit<32> cont_2;
    bit<32> contSum_2;
    
    //Variaveis para time, microsegundos.
    bit<48> timeF;
    bit<48> timeL;
    bit<48> timeC;
    bit<48> timeF_2;
    bit<48> timeL_2;
    bit<48> timeC_2;
    

    apply {

        regsFlagEdge.read(flagEdge, 0);
        if(flagEdge == 0){
            //Realiza a atualizacao dos registradores.
            get_features.apply();
            regsIpSwitch.write(0, meta.ipSwitch);
            regsFlagEdge.write(0, meta.flagEdge);
            flagEdge = meta.flagEdge;
        }

        if(hdr.ipv4.isValid()){

            //Verifica se o endereco do pacote e o endereco do switch atual.
            regsIpSwitch.read(ipSwitch, 0);
            if(hdr.ipv4.dstAddr == ipSwitch){
                //Realiza o desencapsulamento do pacote original.
                hdr.ethernet.setInvalid();
                hdr.ipv4.setInvalid();                        
                hdr.udp.setInvalid();
                
                standard_metadata.recirculate_flag = 1;
                
            }else{

                get_limiar.apply();
                get_flag_host.apply();
                flagNF   = 0;
                flagNF_2 = 0;
                meta.flowTime = 0;
                meta.flowSize = 0;
                //Pacote para repasse.
                if(hdr.icmp.isValid()){
                    //Processamento ICMP
                    //flagHost: 1-indica que é um fluxo de entrada pelo mac do host.
                    //flagHost: 0-indica que é um fluxo vindo de switch. nao calcula EF. pois ja foi calculado por outro switch.
                    if(flagEdge == 2 && meta.flagHost == 1 && standard_metadata.instance_type == 0){
                        //***Processamento da chave hash***//
                        // hash(keyCRC, HashAlgorithm.crc16, 16w0,
                        //     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                        //     , 16w0xffff); //Recupera o index chave a partir da funcao hash_CRC16.

                        // hash(keyCSUM, HashAlgorithm.csum16, 16w0,
                        //     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                        //     , 16w0xffff); //Recupera o index chave a partir da funcao hash_CSUM16.
						
						hash(keyCRC, HashAlgorithm.crc16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                            , (bit<16>)28); //Recupera o index chave a partir da funcao hash_CRC16.

                        hash(keyCSUM, HashAlgorithm.csum16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                            , (bit<16>)28); //Recupera o index chave a partir da funcao hash_CSUM16.



                        //Tempo atual.
                        timeC = standard_metadata.ingress_global_timestamp; //Recupera o time do pacote atual.
                        
                        //Recupera os tempo do ultimo pacote, para cada mapeamento.
                        regsTimeLast.read(timeL, keyCRC);       //Recupera o time do ultimo pacote do fluxo.
                        regsTimeLast.write(keyCRC, timeC);      //Atualiza o time do ultimo pacote para o atual.
                        
                        regsTimeLast_2.read(timeL_2, keyCSUM);  //Recupera o time do ultimo pacote do fluxo.
                        regsTimeLast_2.write(keyCSUM, timeC);   //Atualiza o time do ultimo pacote para o atual.

                        
                        
                        //**Verificacao para a chave hash 1**//
                        if(timeL == 0 || ((timeC-timeL) > meta.timeOut)){
                            //Fluxo novo, ou Reiniciado.
                            //Nao existe entrada para tupla desejada, indica que eh um fluxo novo.
                            regsTimeFirst.write(keyCRC, timeC); //Atribui ao registrador o tempo de chegada do pacote.
                            flagNF = 1;   //Seta a flag para indicar que e um  novo fluxo.
                            hdr.ipv4.diffserv = 0;
                        }
                        regsTimeFirst.read(timeF, keyCRC);   //Recupera o time do primeiro pacote do fluxo.

                        //Hash2
                        if(timeL_2 == 0 || ((timeC-timeL_2) > meta.timeOut)){
                            //Fluxo novo, ou Reiniciado.
                            //Nao existe entrada para tupla desejada, indica que eh um fluxo novo.
                            regsTimeFirst_2.write(keyCSUM, timeC); //Atribui ao registrador o tempo de chegada do pacote.
                            flagNF_2 = 1;  //Seta a flag para indicar que e um  novo fluxo.
                            hdr.ipv4.diffserv = 0;
                        }
                        regsTimeFirst_2.read(timeF_2, keyCSUM);   //Recupera o time do primeiro pacote do fluxo.

                        //***Contagem de volume do fluxo.***//
                        if(flagNF == 1){
                            cont = 0;
                        }else{
                            regsSizeFlow.read(cont, keyCRC);     //Ler o valor artual do registrador para aquela chave h1.
                        }
                        contSum  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont; //Incrementa ao valor do pacote atual.
                        //***Atualizacao do volume do fluxo h1.***//
                        regsSizeFlow.write(keyCRC, contSum);     //Armazena o valor atualizado para a chave no registrador.
                        
                        //Hash2
                        if(flagNF_2 == 1){
                            cont_2 = 0;
                        }else{
                            regsSizeFlow_2.read(cont_2, keyCSUM);   //Ler o valor artual do registrador para aquela chave h2.
                        }
                        contSum_2  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont_2; //Incrementa ao valor do pacote atual.
                        //***Atualizacao do volume do fluxo.***//
                        regsSizeFlow_2.write(keyCSUM, contSum_2);   //Armazena o valor atualizado para a chave no registrador.

                         
                        //**Verificacao dos valores.
                        //Para o volume, escolhe o menor.
                        if(contSum_2 < contSum){  //Se _2 for menor, realiza a troca.
                            contSum = contSum_2;  //Realiza a troca.
                        }

                        //Para o tempo inicial, seleciona o mais recente,
                        //Essa escolha garante que no pior caso ocorrerao Falsos positivos em detrimento de falsos negativos.
                        //Caso a preferencia seja por falsos negativos em detrimento de falsos positivos, deve-se escolher o menor.
                        if(timeF_2 > timeF){
                            timeF = timeF_2;      //Realiza a troca.
                        }

                        //Chamada da funcao para calcular o fluxo
                        //Leitura das flag que indicam um fluxo como EF.
                        if(flagNF == 1){
                            flagEF = 0;
                            regsEF.write(keyCRC, 0);
                        }else{
                            regsEF.read(flagEF, keyCRC);
                        }

                        //Hash2
                        if(flagNF_2 == 1){
                            flagEF_2 = 0;
                            regsEF_2.write(keyCSUM, 0);
                        }else{
                            regsEF_2.read(flagEF_2, keyCSUM);
                        }
                        

                        //Para a flag que indica se o fluxo ja foi identificado.. escolhe o menor.
                        if(flagEF_2 < flagEF){
                            flagEF = flagEF_2;
                        }

                        //Verifica se o fluxo ja foi identificado como EF.
                        if(flagEF == 0){ //Caso seja um fluxo normal, verifica se pode ser um novo EF
                            //if((timeC-timeF) > meta.limiarTime){  //Comparacao apenas de tempo.
                            //Comparacao de tempo e tamanho.
                            if((timeC-timeF) > meta.limiarTime && contSum > meta.limiarBytes){
                                //******* Identificado EF*********//
                                //table_EF.apply();
                                clone(CloneType.I2E, ID_CLONE);
                                regsEF.write(keyCRC, 1);
                                regsEF_2.write(keyCSUM, 1);
                                hdr.ipv4.diffserv = FLAG_EF;
                            }
                        }else{
                            hdr.ipv4.diffserv = FLAG_EF;
                        }

                        
                    }
                    if(hdr.ipv4.diffserv == 0 ){
                        icmp_lpm.apply();  //Tabela para realizar o repasse ICMP.
                    }else{
                        icmp_lpm_EF.apply();  //Tabela para realizar o repasse ICMP EF
                    }
                }else{
                    //Trata o fluxo UDP ou TCP
                    if(hdr.udp.isValid()){
                        meta.srcPort = hdr.udp.srcPort;
                        meta.dstPort = hdr.udp.dstPort;
                        meta.flagFin = 0;
                    }else{
                        if(hdr.updNewController.isValid()){
                            meta.srcPort = hdr.updNewController.srcPort;
                            meta.dstPort = hdr.updNewController.dstPort;
                            meta.flagFin = 0;
                        }else{
                            if(hdr.tcp.isValid()){
                                meta.srcPort = hdr.tcp.srcPort;
                                meta.dstPort = hdr.tcp.dstPort;
                                meta.flagFin = hdr.tcp.fin;
                            }
                        }
                    }
                    //Verifica se é um fluxo de controle indicado por uma flagWhite.
                    get_flag_white.apply();
                    //meta.flagEnvioEF = 0;
                    if(flagEdge == 2 &&  meta.flagHost == 1 && meta.flagWhite == 0 && standard_metadata.instance_type == 0){ //Indica que nao eh um fluxo de controle.
                        //Processo de calculo EF.
                        //Chamada para leitura dos limiares.
                        
                        //Processamento da chave hash***
                        hash(keyCRC, HashAlgorithm.crc16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.srcPort, meta.dstPort}
                            , (bit<16>)112); //Recupera o index chave a partir da funcao hash_CRC16.

                        hash(keyCSUM, HashAlgorithm.csum16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.srcPort, meta.dstPort}
                            , (bit<16>)112); //Recupera o index chave a partir da funcao hash_CSUM16.

                        //Tempo atual.
                        timeC = standard_metadata.ingress_global_timestamp; //Recupera o time do pacote atual.
                        
                        //Recupera os tempo do ultimo pacote, para cada mapeamento.
                        regsTimeLast.read(timeL, keyCRC);       //Recupera o time do ultimo pacote do fluxo.
                        regsTimeLast.write(keyCRC, timeC);      //Atualiza o time do ultimo pacote para o atual.
                        
                        regsTimeLast_2.read(timeL_2, keyCSUM);  //Recupera o time do ultimo pacote do fluxo.
                        regsTimeLast_2.write(keyCSUM, timeC);   //Atualiza o time do ultimo pacote para o atual.

                        
                        
                        //**Verificacao para a chave hash 1**//
                        if(timeL == 0 || ((timeC-timeL) > meta.timeOut)){
                            //Fluxo novo, ou Reiniciado.
                            //Nao existe entrada para tupla desejada, indica que eh um fluxo novo.
                            regsTimeFirst.write(keyCRC, timeC); //Atribui ao registrador o tempo de chegada do pacote.
                            flagNF = 1;   //Seta a flag para indicar que e um  novo fluxo.
                            hdr.ipv4.diffserv = 0;
                        }
                        regsTimeFirst.read(timeF, keyCRC);   //Recupera o time do primeiro pacote do fluxo.

                        //Hash2
                        if(timeL_2 == 0 || ((timeC-timeL_2) > meta.timeOut)){
                            //Fluxo novo, ou Reiniciado.
                            //Nao existe entrada para tupla desejada, indica que eh um fluxo novo.
                            regsTimeFirst_2.write(keyCSUM, timeC); //Atribui ao registrador o tempo de chegada do pacote.
                            flagNF_2 = 1;  //Seta a flag para indicar que e um  novo fluxo.
                            hdr.ipv4.diffserv = 0;
                        }
                        regsTimeFirst_2.read(timeF_2, keyCSUM);   //Recupera o time do primeiro pacote do fluxo.

                        //***Contagem de volume do fluxo.***//
                        if(flagNF == 1){
                            cont = 0;
                        }else{
                            regsSizeFlow.read(cont, keyCRC);     //Ler o valor artual do registrador para aquela chave h1.
                        }
                        contSum  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont; //Incrementa ao valor do pacote atual.
                        //***Atualizacao do volume do fluxo h1.***//
                        regsSizeFlow.write(keyCRC, contSum);     //Armazena o valor atualizado para a chave no registrador.
                        
                        //Hash2
                        if(flagNF_2 == 1){
                            cont_2 = 0;
                        }else{
                            regsSizeFlow_2.read(cont_2, keyCSUM);   //Ler o valor artual do registrador para aquela chave h2.
                        }
                        contSum_2  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont_2; //Incrementa ao valor do pacote atual.
                        //***Atualizacao do volume do fluxo.***//
                        regsSizeFlow_2.write(keyCSUM, contSum_2);   //Armazena o valor atualizado para a chave no registrador.

                         
                        //**Verificacao dos valores.
                        //Para o volume, escolhe o menor.
                        if(contSum_2 < contSum){  //Se _2 for menor, realiza a troca.
                            contSum = contSum_2;  //Realiza a troca.
                        }

                        //Para o tempo inicial, seleciona o mais recente,
                        //Essa escolha garante que no pior caso ocorrerao Falsos positivos em detrimento de falsos negativos.
                        //Caso a preferencia seja por falsos negativos em detrimento de falsos positivos, deve-se escolher o menor.
                        if(timeF_2 > timeF){
                            timeF = timeF_2;      //Realiza a troca.
                        }

                        //Chamada da funcao para calcular o fluxo
                        //Leitura das flag que indicam um fluxo como EF.
                        if(flagNF == 1){
                            flagEF = 0;
                            regsEF.write(keyCRC, 0);
                        }else{
                            regsEF.read(flagEF, keyCRC);
                        }

                        //Hash2
                        if(flagNF_2 == 1){
                            flagEF_2 = 0;
                            regsEF_2.write(keyCSUM, 0);
                        }else{
                            regsEF_2.read(flagEF_2, keyCSUM);
                        }

                        //Para a flag que indica se o fluxo ja foi identificado.. escolhe o menor.
                        if(flagEF_2 < flagEF){
                            flagEF = flagEF_2;
                        }
                        
                        meta.flowTime = (timeC-timeF);
                        meta.flowSize = contSum;
                        //Verifica se o fluxo ja foi identificado como EF.
                        if(flagEF == 0){ //Caso seja um fluxo normal, verifica se pode ser um novo EF
                            //if((timeC-timeF) > meta.limiarTime){  //Comparacao apenas de tempo.
                            //Comparacao de tempo e tamanho.
                            if((timeC-timeF) > meta.limiarTime && contSum > meta.limiarBytes){
                                //******* Identificado EF*********//
                                //table_EF.apply();
                                //clone(CloneType.I2E, ID_CLONE);
                                clone3(CloneType.I2E, ID_CLONE, {meta});
                                regsEF.write(keyCRC, 1);
                                regsEF_2.write(keyCSUM, 1);
                                hdr.ipv4.diffserv = FLAG_EF;
                            }
                        }else{
                            hdr.ipv4.diffserv = FLAG_EF;
                        }

                        //Caso seja um pacote de fim de conexao, 
                        //envia ao controlador e reinicializa os registradores.
                        if(meta.flagFin == 1){
                            clone3(CloneType.I2E, ID_CLONE, {meta});
                            //Reiniciar os registradores...
                        }
                    }

                    if(hdr.ipv4.diffserv == 0 || meta.flagWhite == 1){
                        //Se for fluxo normal, ou fluxo de controle (flagWhite ==1), roteia pela tabela normal.
                        ipv4_lpm.apply();  //Tabela para realizar o repasse.
                    }else{
                        //No caso de ser fluxo elefante.
                        ipv4_lpm_EF.apply();  //Tabela para repasse EF.
                    }

                    // if(hdr.ipv4.diffserv == FLAG_EF && meta.flagWhite != 1){
                    //     //No caso de ser fluxo elefante.
                    //     ipv4_lpm_EF.apply();  //Tabela para repasse EF.
                    // }

                    // if(meta.flagEnvioEF == 0){
                    //     ipv4_lpm.apply();  //Tabela para realizar o repasse.
                    // }
                }
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action send_controller_EF(macAddr_t srcAddr, macAddr_t dstAddr, ip4Addr_t ipSrc, ip4Addr_t ipDst,
                            port_t srcPort, port_t dstPort){
        hdr.ethernetController.setValid();
        hdr.ipv4Controller.setValid();
        hdr.updNewController.setValid();

        //standard_metadata.egress_spec    = port;
        hdr.ethernetController.srcAddr   = srcAddr;
        hdr.ethernetController.dstAddr   = dstAddr;
        hdr.ethernetController.etherType = TYPE_IPV4;

        hdr.ipv4Controller.version        = hdr.ipv4.version;
        hdr.ipv4Controller.ihl            = hdr.ipv4.ihl;
        hdr.ipv4Controller.diffserv       = FLAG_EF; //Flag fluxo de controle.
        hdr.ipv4Controller.totalLen       = ((bit<16>)standard_metadata.packet_length) + 20+8; //Packet + ipvH + udpH
        hdr.ipv4Controller.identification = 0;
        hdr.ipv4Controller.flags          = 0;
        hdr.ipv4Controller.fragOffset     = hdr.ipv4.fragOffset;
        hdr.ipv4Controller.ttl            = 64;
        hdr.ipv4Controller.srcAddr        = ipSrc;
        hdr.ipv4Controller.dstAddr        = ipDst;
        hdr.ipv4Controller.protocol       = UDP_CONTROLLER;

        /*
        hdr.updController.srcPort       = srcPort;
        hdr.updController.dstPort       = dstPort;
        hdr.updController.length        = ((bit<16>)standard_metadata.packet_length);
        hdr.updController.checksumUdp   = 0x0000;
        */

        hdr.updNewController.srcPort       = srcPort;
        hdr.updNewController.dstPort       = dstPort;
        //hdr.updNewController.length        = ((bit<16>)standard_metadata.packet_length)+8+10; //Packet + ipH + udpH + time + size
        hdr.updNewController.length        = 18+10; //Packet + ipH + udpH + time + size
        hdr.updNewController.checksumUdp   = 0x0000;

        hdr.updNewController.testeP    = 0x115c;
        

        hdr.updNewController.timeFlowUDP   = meta.flowTime;
        hdr.updNewController.testePP   = 0x22b8;
        hdr.updNewController.sizeFlowUDP   = meta.flowSize;
        
        //truncate(0);

    }


    table map_controller{
        actions        = { send_controller_EF;  NoAction; }
        default_action =  NoAction();

    }

    apply {
        if(standard_metadata.instance_type == 1){
            map_controller.apply();


        }
        // if (meta.flagRecirculate == 1){
            //meta.intrinsic_metadata.recirculate_flag = 1;
            //recirculate({meta.intrinsic_metadata, standard_metadata});
            //standard_metadata.recirculate_flag = 1;
        //     recirculate({meta, standard_metadata});
        // }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/


control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    /*
    * Ignore checksum for now. The reference solution contains a checksum
    * implementation.
    */
    apply {
        
            update_checksum(hdr.ipv4Controller.isValid(),
            {  hdr.ipv4Controller.version,
                hdr.ipv4Controller.ihl,
                hdr.ipv4Controller.diffserv,
                hdr.ipv4Controller.totalLen,
                hdr.ipv4Controller.identification,
                hdr.ipv4Controller.flags,
                hdr.ipv4Controller.fragOffset,
                hdr.ipv4Controller.ttl,
                hdr.ipv4Controller.protocol,
                hdr.ipv4Controller.srcAddr,
                hdr.ipv4Controller.dstAddr
            },
            hdr.ipv4Controller.hdrChecksum, HashAlgorithm.csum16);
        

            update_checksum(
                hdr.ipv4.isValid(),
                    { hdr.ipv4.version,
                      hdr.ipv4.ihl,
                      hdr.ipv4.diffserv,
                      hdr.ipv4.totalLen,
                      hdr.ipv4.identification,
                      hdr.ipv4.flags,
                      hdr.ipv4.fragOffset,
                      hdr.ipv4.ttl,
                      hdr.ipv4.protocol,
                      hdr.ipv4.srcAddr,
                      hdr.ipv4.dstAddr },
                    hdr.ipv4.hdrChecksum,
                    HashAlgorithm.csum16);       
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernetController);
        packet.emit(hdr.ipv4Controller);
        packet.emit(hdr.updController);
        packet.emit(hdr.updNewController);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp); 
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;


