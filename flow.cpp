#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <list>
#include <cmath>
#include <netdb.h>

///CFLOW PACKET CONSTANTS
#define HEADER_LENGHT 24
#define FLOW_LENGHT 48
#define MAX_FLOWS_IN_PACKET 30

///STRUCTURES
typedef struct NetFlowHeader NetFlowHeader;
typedef struct NetFlowRecord NetFlowRecord;
typedef struct NetFlowGlobalVariables NetFlowGlobalVariables;


///NET FLOW RECORD - STORES FLOW RECORD INFORMATIONS
struct NetFlowRecord{
    uint32_t srcaddr, dstaddr = 0;
    uint32_t nexthop = 0; 
    uint16_t input = 0;
    uint16_t output = 0; 
    uint32_t dPkts = 1; 
    uint32_t dOctets = 0; 
    uint32_t First = 0; 
    uint32_t Last = 0; 
    uint16_t srcport, dstport; 
    uint8_t pad1 = 0; 
    uint8_t tcp_flags = 0; 
    uint8_t prot = 0; 
    uint8_t tos = 0;
    uint16_t src_as = 0; 
    uint16_t dest_as = 0; 
    uint8_t src_mask = 0; 
    uint8_t dst_mask = 0; 
    uint16_t pad2 = 0; 
};

///NET FLOW HEADER - STORES HEADER INFORMATIONS
struct NetFlowHeader{
    uint16_t version = 5;
    uint16_t count = 0;
    uint32_t SysUptime = 0;
    uint32_t unix_secs = 0;
    uint32_t unix_nsecs = 0;
    uint32_t flow_sequence = 0;
    uint8_t engine_type = 0;
    uint8_t engine_id = 0;
    uint16_t sampling_interval = 0;
};

///GLOBAL VARIABLES 
struct NetFlowGlobalVariables{
    uint32_t firstPacketTime;
    uint32_t active_timer;
    uint32_t inactive_timer;
    size_t flow_cache;
    char* buffer;
    sockaddr_in servaddr;
    NetFlowHeader header;
    std::list<NetFlowRecord> listOfFlows;
};

/**
 * @brief Fill first 24 bytes of buffer with net flow header
 * 
 * @param global access to global variables
 */
void addHeaderToPacket(NetFlowGlobalVariables &global){

    *(uint16_t*)global.buffer = htons(5);
    *(uint16_t*)(global.buffer + 2) = htons(global.header.count);
    *(uint32_t*)(global.buffer + 4) = htonl(global.header.SysUptime);
    *(uint32_t*)(global.buffer + 8) = htonl(global.header.unix_secs);
    *(uint32_t*)(global.buffer + 12) = htonl(global.header.unix_nsecs);
    *(uint32_t*)(global.buffer + 16) = htonl(global.header.flow_sequence);
    *(uint8_t*)(global.buffer + 20) = global.header.engine_type;
    *(uint8_t*)(global.buffer + 21) = global.header.engine_id;
    *(uint16_t*)(global.buffer + 22) = htons(global.header.sampling_interval);
}

/**
 * @brief Add flow record (48 bytes) to the buffer
 * 
 * @param global access to global variables
 * @param r flow record
 * @param offset offset (how many flows shifting)
 */
void addFlowToPacket(NetFlowGlobalVariables &global, NetFlowRecord &r, int offset){
    *(uint32_t*)(global.buffer + HEADER_LENGHT + offset*FLOW_LENGHT)= htonl(r.srcaddr);
    *(uint32_t*)(global.buffer + 4 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.dstaddr);
    *(uint32_t*)(global.buffer + 8 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.nexthop);
    *(uint16_t*)(global.buffer + 12 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.input);
    *(uint16_t*)(global.buffer + 14 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.output);
    *(uint32_t*)(global.buffer + 16 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.dPkts);
    *(uint32_t*)(global.buffer + 20 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.dOctets);
    *(uint32_t*)(global.buffer + 24 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.First);
    *(uint32_t*)(global.buffer + 28 + HEADER_LENGHT + offset*FLOW_LENGHT) = htonl(r.Last);
    *(uint16_t*)(global.buffer + 32 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.srcport);
    *(uint16_t*)(global.buffer + 34 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.dstport);
    *(uint8_t*)(global.buffer + 36 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.pad1;
    *(uint8_t*)(global.buffer + 37 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.tcp_flags;
    *(uint8_t*)(global.buffer + 38 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.prot;
    *(uint8_t*)(global.buffer + 39 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.tos;
    *(uint16_t*)(global.buffer + 40 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.src_as);
    *(uint16_t*)(global.buffer + 42 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.dest_as);
    *(uint8_t*)(global.buffer + 44 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.src_mask;
    *(uint8_t*)(global.buffer + 45 + HEADER_LENGHT + offset*FLOW_LENGHT) = r.dst_mask;
    *(uint16_t*)(global.buffer + 46 + HEADER_LENGHT + offset*FLOW_LENGHT) = htons(r.pad2);
}

/**
 * @brief Sending CFLOW packet to collector
 * 
 * @param address collector address
 * @param buffer buffer with packet data
 * @param bytes number of bytes 
 */
void sendUDPPacket(sockaddr_in address, char *buffer, unsigned short bytes)
{
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        fprintf(stderr, "Socket failed!\n");
        exit(EXIT_FAILURE);
    }
    if (sendto(sock, buffer, bytes, 0, (const struct sockaddr*)&address, sizeof(ip)) == -1)
    {
        fprintf(stderr, "Send to failed!\n");
        exit(EXIT_FAILURE);
    }
    close(sock);
}

/**
 * @brief Clears buffer. Fills buffer with net flow header and one flow record then sending packet to the collector
 * 
 * @param global access to global variables
 * @param flow flow record to be send
 */
void exportFlow(NetFlowGlobalVariables &global, NetFlowRecord &flow){
    memset(global.buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);
    uint32_t addOne = 1;
    global.header.flow_sequence = global.header.flow_sequence + addOne;
    addHeaderToPacket(global);
    addFlowToPacket(global, flow, 0);
    sendUDPPacket(global.servaddr, global.buffer, HEADER_LENGHT + FLOW_LENGHT);
    memset(global.buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);

}

/**
 * @brief Store new flow record in the memory.
 * 
 * @param global access to global variables
 * @param srcaddr source IP address 
 * @param dstaddr destination IP address
 * @param srcport source port
 * @param dstport destination port
 * @param tcp_flags tcp flags
 * @param prot protocol
 * @param tos type of service
 * @param dOctets total bytes 
 */
void createNewFlow(NetFlowGlobalVariables &global, uint32_t srcaddr, uint32_t dstaddr, uint16_t srcport, uint16_t dstport, uint8_t tcp_flags, uint8_t prot, uint8_t tos, uint16_t dOctets){
    ///ALLOCATE NEW RECORD
    NetFlowRecord* newRecord = new NetFlowRecord;

    ///INITIALIZE VARIABLES
    newRecord->srcaddr = srcaddr;
    newRecord->dstaddr = dstaddr;
    newRecord->srcport = srcport;
    newRecord->dstport = dstport;
    newRecord->tcp_flags = tcp_flags;
    newRecord->prot = prot;
    newRecord->tos = tos;
    newRecord->First = global.header.SysUptime;
    newRecord->Last = newRecord->First;
    newRecord->dOctets = dOctets;

    ///IF FLOW CACHE IS FULL 
    if(global.listOfFlows.size() == global.flow_cache){
        ///TAKE THE OLDEST FLOW FROM LIST OF FLOWS
        std::list<NetFlowRecord>::iterator it;
        for(it = global.listOfFlows.begin(); it != global.listOfFlows.end(); ++it){
            ///SEND PACKET WITH THIS FLOW RECORD TO THE COLLECTOR
            uint16_t incOne = 1;
            global.header.count = incOne;
            exportFlow(global, *it);

            ///REMOVE FLOW FROM THE LSIT OF THE FLOWS
            it = global.listOfFlows.erase(it);
            --it;
            break;
        }
    }

    ///IF PACKET IS TCP PACKET AND ITS FLAGS ARE FIN OR RST. 
    if(prot == IPPROTO_TCP && ((tcp_flags & TH_FIN) || (tcp_flags & TH_RST))){
        ///SEND PACKET WITH THIS FLOW RECORD TO THE COLLECTOR WITHOUT STORING IT IN MEMORY
        uint16_t incOne = 1;
        global.header.count = incOne;
        exportFlow(global, *newRecord);

        ///DELETE ALREADY ALLOCATED NEW RECORD
        delete(newRecord);
    }else{
        ///ELSE STORE IT IN MEMORY
        global.listOfFlows.push_back(*newRecord);
    }
}

/**
 * @brief Create or aggregate flow record
 * 
 * @param global access to global variables
 * @param srcaddr source IP address 
 * @param dstaddr destination IP address
 * @param srcport source port
 * @param dstport destination port
 * @param tcp_flags tcp flags
 * @param prot protocol
 * @param tos type of service
 * @param dOctets total bytes
 */
void createOrAggregateFlow(NetFlowGlobalVariables &global, uint32_t srcaddr, uint32_t dstaddr, uint16_t srcport, uint16_t  dstport, uint8_t tcp_flags, uint8_t prot, uint8_t tos, uint16_t dOctets){
    ///BOOL FLOW EXIST
    bool exist = false;

    ///STARTS ITERATION THROUGH THE LIST OF FLOW TO CHECK IF FLOW ALREADY EXIST FOR THIS PACKET
    ///ALSO CHECKS EVERY FLOW IF IT IS ACTIVE OR INACTIVE 
    std::list<NetFlowRecord>::iterator it;
    for(it = global.listOfFlows.begin(); it != global.listOfFlows.end(); it++){

        uint32_t incOne = 1;

        ///IF FLOW IS ACTIVE TOO LONG OR FLOW IS INACTIVE TOO LONG
        if(((global.header.SysUptime - it->First) > global.active_timer*1000) || ((global.header.SysUptime - it->Last) > global.inactive_timer*1000)){
            ///SEND PACKET WITH THIS FLOW RECORD TO THE COLLECTOR
            global.header.count = incOne;
            exportFlow(global, *it);

            ///REMOVE FLOW FROM THE LIST OF THE FLOWS
            it = global.listOfFlows.erase(it); 
            --it;
        }else{
            ///ELSE CHCECK IF KEYES OF THE PACKETS ARE MATCHING
            if(it->srcaddr == srcaddr && it->dstaddr == dstaddr && it->prot == prot && it->srcport == srcport && it->dstport == dstport){

                ///SET EXIST TO TRUE
                exist = true;
                
                ///UPDATE (AGGREGATE) FLOW RECORD
                it->dPkts = it->dPkts + incOne;
                it->Last = global.header.SysUptime;
                it->dOctets = it->dOctets + dOctets;
                it->tcp_flags = it->tcp_flags | tcp_flags;

                ///IF PACKET IS TCP PACKET AND ITS FLAGS ARE FIN OR RST
                if(it->prot == IPPROTO_TCP && ((it->tcp_flags & TH_FIN) || (it->tcp_flags & TH_RST))){
                    ///SEND PACKET WITH THIS FLOW RECORD TO THE COLLECTOR
                    global.header.count = incOne;
                    exportFlow(global, *it);

                    ///REMOVE FLOW FROM THE LIST OF FLOWS
                    it = global.listOfFlows.erase(it);
                }
            }   
        }
    }

    ///FLOW FOR THIS PACKET DOESN'T EXISTS (NOTHING TO AGGREGATE)
    if(!exist){
        ///CREATE NEW FLOW RECORD
        createNewFlow(global, srcaddr, dstaddr, srcport, dstport, tcp_flags, prot, tos, dOctets);
    }
}

/**
 * @brief Callback function for pcap_live(). 
 * 
 * @param userData passing global variables
 * @param pkthdr packet header
 * @param packet packet
 */
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet );


///MAIN
int main(int argc, char* argv[]) {
    ///ARGUMENTS INITIALIZATION 
    std::string file_name;
    std::string ip = "127.0.0.1";
    std::string port = "2055";
    std::string collector;
    int active_timer = 60;
    int inactive_timer = 10;
    int flow_cache = 1024;
    bool file_flag = false;
    bool collector_flag = false;

    ///GET ARGUMENTS
    int opt;
    while ((opt = getopt(argc, argv, "hf:c:a:i:m:")) != -1) {
        switch (opt) {
            case 'f':
                file_name = optarg;
                file_flag = true;
                break;
            case 'c':
                collector = optarg;
                collector_flag = true;
                break;
            case 'a':
                try
                {
                    active_timer = std::stoi(optarg);
                }
                catch(const std::exception& e)
                {
                    fprintf(stderr, "Argument [-a <active_timer>] has to be an Integer value!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                try
                {
                    inactive_timer = std::stoi(optarg);
                }
                catch(const std::exception& e)
                {
                    fprintf(stderr, "Argument [-i <inactive_timer>] has to be an Integer value!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'm':
                try
                {
                    flow_cache = std::stoi(optarg);
                }
                catch(const std::exception& e)
                {
                    fprintf(stderr, "Argument [-m <count>] has to be an Integer value!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
            default: 
                fprintf(stderr, "Usage: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
                exit(EXIT_FAILURE);
        }
    }
    
    ///COLLECTOR ARGUMENT HANDLING (GET IP AND PORT TO SEPARATE VARIABLES)
    if(collector_flag){
        std::size_t pos = collector.find(":");
        if(pos != std::string::npos){
            port = collector.substr(pos+1);
            ip = collector.substr(0,pos);
        }else{
            ip = collector;
            port = "2055";
            
        }
    }
    
    const char* c_port = port.c_str();
    const char* c_ip = ip.c_str();

    /*///UDP KLIENT (SOCKET)
    int sock;
    struct sockaddr_in servaddr;
    struct hostent *servent;

    memset(&servaddr, 0 , sizeof(servaddr));

    ///GET HOST BY NAME
    if ((servent = gethostbyname(c_ip)) == NULL){
        fprintf(stderr, "Gethostbyname() failed!\n");
        exit(EXIT_FAILURE);
    }

    ///CREATE SOCKET
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1){

    }
    
    ///FILL SERVER INFO (IP AND PORT)
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(c_port));
    memcpy(&servaddr.sin_addr,servent->h_addr,servent->h_length); 

    ///CONNECT TO SERVER
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr))  == -1){
        fprintf(stderr, "Connection failed!\n");
        exit(EXIT_FAILURE);
    }
*/
    struct sockaddr_in servaddr;
    struct hostent *servent;

    memset(&servaddr, 0 , sizeof(servaddr));

    ///GET HOST BY NAME
    if ((servent = gethostbyname(c_ip)) == NULL){
        fprintf(stderr, "Gethostbyname() failed!\n");
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(c_port));
    memcpy(&servaddr.sin_addr,servent->h_addr,servent->h_length); 


    ///BUFFER ALLOCATION
    char* buffer = new char[HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1];
    memset(buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);


    ///GLOBAL STRUCTURE INITIALIZATION
    NetFlowGlobalVariables *global = new NetFlowGlobalVariables;
    global->flow_cache = (size_t)flow_cache;
    global->buffer = buffer;
    global->servaddr = servaddr;
    uint32_t active_timerMs = (uint32_t)active_timer*1000;
    uint32_t inactive_timerMs = (uint32_t)inactive_timer*1000;
    global->active_timer = active_timerMs;
    global->inactive_timer = inactive_timerMs;

    ///LIBPCAP LOGIC
    pcap_t *descr;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    ///IF FILE FLAG IS TRUE OPEN FILE WITH GIVEN NAME 
    if(file_flag){
        descr = pcap_open_offline(file_name.c_str(), errorBuffer);

        if(descr == NULL){
        fprintf(stderr, "Something went wrong with the file \"%s\".\nError: %s\nExiting...\n", file_name.c_str(), errorBuffer);
        exit(EXIT_FAILURE);
        }
    
    }else{
        ///ELSE OPEN STDIN AND READ PACKETS FROM THERE
        descr = pcap_fopen_offline(stdin, errorBuffer);

        if(descr == NULL){
        fprintf(stderr,"Something went wrong with reading standard input\nError: %s\nExiting...\n", errorBuffer);
        exit(EXIT_FAILURE);
        }
    }

    ///START READING PACKETS FROM FILE/STDIN
    if(pcap_loop(descr, 0, packetHandler, (u_char*)global) < 0 ){
        fprintf(stderr, "Live capture failed!\nError: %s\nExiting...\n", pcap_geterr(descr));
        exit(EXIT_FAILURE);
    }
    ///READ ALL PACKETS FROM INPUT///

    ///CLEAR BUFFER
    memset(global->buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);

    ///FLOWS THAT ARE STILL ACTIVE WILL BE SEND TO THE COLLECTOR BECAUSE THERE IS NO PACKET LEFT FOR US TO READ FROM INPUT
    ///ITERATION THROUGH STILL ACTIVE FLOWS
    int i = 0;
    std::list<NetFlowRecord>::iterator it;
    for(it = global->listOfFlows.begin(); it != global->listOfFlows.end(); ++it){
        
        ///GET FLOW AND ADD IT TO THE BUFFER
        addFlowToPacket(*global, *it, i);
        uint32_t addOne = 1;
        global->header.flow_sequence = global->header.flow_sequence + addOne;
        ///REMOVE FLOW FROM LIST OF FLOWS
        it = global->listOfFlows.erase(it);
        --it;
        
        ///IF THERE IS 30 FLOWS IN BUFFER ALREADY
        if(i == 29){
            ///MAKE HEADER FOR 30 FLOWS
            uint16_t maxFlows = 30;
            global->header.count = maxFlows;

            ///SEND PACKET WITH 30 FLOW RECORDS TO THE COLLECTOR
            addHeaderToPacket(*global);
            sendUDPPacket(global->servaddr, global->buffer, HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET));
            ///CLEAR BUFFER
            memset(global->buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);

            ///RESET COUNTER (AFTER THIS SCOPE i WILL BY INCREASED BY 1 TO START FROM 0 AGAIN)
            i = -1;
        }
        i++;  
    }
    
    ///i REPRESENTS FLOWS THAT LEFT IN FLOW CACHE (LIST OF FLOWS)
    if(i > 0){
        ///MAKE HEADER FOR i FLOWS
        uint16_t leftovers = i;
        global->header.count = leftovers;
        addHeaderToPacket(*global);

        ///SEND PACKET WITH i FLOW RECORDS TO THE COLLECTOR
        sendUDPPacket(global->servaddr, global->buffer, HEADER_LENGHT + (FLOW_LENGHT * leftovers));
        ///CLEAR BUFFER
        memset(global->buffer, '\0', HEADER_LENGHT + (FLOW_LENGHT * MAX_FLOWS_IN_PACKET) + 1);
    }

    ///DELETE OBJECTS AND CLOSE SOCKET
    delete(global);
    delete(buffer);
    
    ///EXIT SUCCESS
    exit(EXIT_SUCCESS);
}

/**
 * @brief Callback function for handling packets.
 * 
 * @param userData passing global variables
 * @param pkthdr paket header
 * @param packet paket
 */
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    ///DECLARATION HEADERS VARIABLES
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;

    ///GET GLOBAL VARIABLES FROM USER DATA
    NetFlowGlobalVariables* global = (NetFlowGlobalVariables*) userData;

    ///DECLARATION OF PACKET INFROMATIONS
    uint32_t srcaddr, dstaddr; 

    uint16_t srcport, dstport; 

    uint8_t tcp_flags; 
    uint8_t prot; 
    uint8_t tos; 
    uint16_t dOctets;

    ///GET ETHERNET HEADER
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ///GET IP HEADER, IP ADDRESS, DESTINATION ADDRESS AND TOS
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        srcaddr = ntohl(ipHeader->ip_src.s_addr);
        dstaddr = ntohl(ipHeader->ip_dst.s_addr);
        tos = ipHeader->ip_tos;

        ///IF PROTOCOL IS TCP
        if (ipHeader->ip_p == IPPROTO_TCP) {
            ///GET TCP HEADER, SOURCE PORT, DESTINATION PORT, SET PROTOCOL TO TCP, TCP FLAGS
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            srcport = ntohs(tcpHeader->th_sport);
            dstport = ntohs(tcpHeader->th_dport);
            prot = IPPROTO_TCP;
            tcp_flags = tcpHeader->th_flags;

        ///IF PROTOCOL IS UDP
        }else if (ipHeader->ip_p == IPPROTO_UDP) {
            ///GET UDP HEADER, SOURCE PORT, DESTINATION PORT, SET PROTOCOL TO UDP
            udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            srcport = ntohs(udpHeader->uh_sport);
            dstport = ntohs(udpHeader->uh_dport);
            prot = IPPROTO_UDP;

        ///IF PROTOCOL IS ICMP
        }else if (ipHeader->ip_p == IPPROTO_ICMP) {
            ///SET SOURCE PORT AND DESTINATION PORT TO 0 AND SET PROTOCOL TO ICMP
            srcport = 0;
            dstport = 0;
            prot = IPPROTO_ICMP;
        }else{
            return;
        }

        ///GET TOTAL BYTES OF PACKET
        dOctets = ntohs(ipHeader->ip_len);

        ///IF THERE IS NO FLOW RECORD IN FLOW CACHE (LIST OF FLOWS) YET
        if(global->header.flow_sequence == 0){
            ///SET HEADER SYSUPTIME TO 0, STORE FIRST PACKET TIME 
            global->header.SysUptime = 0;
            global->firstPacketTime = (pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000);

            ///STORE HEADER UNIX SECS AND UNIX NSECS
            global->header.unix_secs = (pkthdr->ts.tv_sec);
            global->header.unix_nsecs = (pkthdr->ts.tv_usec)* 1000;
        
        }else{
            ///THERE IS AT LEATS ONE FLOW RECORD IN FLOW CACHE (LIST OF FLOWS)

            ///CALCULATE NEW HEADER SYSUPTIME AND STORE UNIX SECS AND UNIX NSECS
            global->header.SysUptime = ((pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000)) - global->firstPacketTime; 
            global->header.unix_secs = (pkthdr->ts.tv_sec);
            global->header.unix_nsecs = (pkthdr->ts.tv_usec)* 1000;
        }
        
        ///EITHER CREATE OR AGGREGATE FLOW
        createOrAggregateFlow(*global, srcaddr, dstaddr, srcport, dstport, tcp_flags, prot, tos, dOctets);
    }
}