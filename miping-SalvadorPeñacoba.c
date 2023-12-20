// Practica Tema 8: Salvador Peñacoba, Javier
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "ip-icmp-ping.h"

#define ASSERT(_bool, ...) do{if (!(_bool)){ fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE);}}while(0);

#define VERBOSE_MSG(_msg,...) do{if(verbose_flag) fprintf(stdout,_msg,__VA_ARGS__);}while(0);

unsigned short create_checksum(unsigned char* addr, size_t size);
ICMPHeader createICMP_header();
void createICMP_request(EchoRequest* request);
void print_info_msg(unsigned char type, unsigned char code);

char verbose_flag = 0;

int main(int argc, char** argv){

    int aux;
    int sockfd;
    struct in_addr addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in my_addr = {.sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = INADDR_ANY};
    EchoRequest* request;
    EchoReply* reply;
    socklen_t addr_size;

    memset(&addr, 0, sizeof(addr));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&my_addr, 0, sizeof(my_addr));

    ASSERT(argc == 2 || argc == 3,"Uso: %s direccion_ip [-v]\n",argv[0]);

    if(argc == 3){
        ASSERT(strcmp(argv[2],"-v") == 0,"Uso: %s direccion_ip [-v]\n",argv[0]);
        verbose_flag = 1;
    }

    ASSERT((inet_aton(argv[1], &addr) == 1), "Uso: %s direccion_ip [-v]\n",argv[0]);

    server_addr.sin_port = 0;
    server_addr.sin_addr = addr;
    server_addr.sin_family = AF_INET;

    addr_size = sizeof(server_addr);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT(sockfd !=-1, "Error creando socket: %s\n",strerror(errno));

    aux = bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    ASSERT(aux == 0, "Error vinculando socket: %s\n", strerror(errno));

    request = (EchoRequest*) calloc(1,sizeof(EchoRequest));
    createICMP_request(request);

    VERBOSE_MSG("-> Generando cabecera ICMP...\n"
                "-> Type: %hhu\n"
                "-> Code: %hhu\n"
                "-> PID: %hu\n"
                "-> Sequence Number: %hu\n"
                "-> Cadena a enviar: %s\n"
                "-> Checksum: %hx\n"
                "-> Tamaño total del datagrama: %lu\n",request->icmpHdr.type, request->icmpHdr.code, request->pid, request->sequence, request->payload, request->icmpHdr.checksum, sizeof(*request));
    

    aux = sendto(sockfd,request,sizeof(*request),0,(struct sockaddr*) &server_addr, addr_size);
    ASSERT(aux != -1,"Error enviando mensaje: %s\n",strerror(errno));

    printf("Mensaje ICPM enviado al host: %s\n\n",inet_ntoa(server_addr.sin_addr));

    reply = (EchoReply*)calloc(1, sizeof(EchoReply));

    aux = recvfrom(sockfd,reply, sizeof(*reply),0, (struct sockaddr*) &server_addr, &addr_size);
    ASSERT(aux != -1, "Error recibiendo mensaje: %s\n",strerror(errno));

    //ASSERT(!create_checksum((unsigned char*)&reply->icmpMsg, sizeof(EchoRequest)), "Error, mensaje de respuesta corrupto. Checksum: %hx\n",reply->icmpMsg.icmpHdr.checksum);

    printf("Respuesta recibida desde: %s\n", inet_ntoa(server_addr.sin_addr));

    VERBOSE_MSG("-> Tamaño de la respuesta: %lu\n"
                "-> Cadena recibida: %s\n"
                "-> PID: %hu\n"
                "-> TTL: %hhu\n", sizeof(*reply), reply->icmpMsg.payload, reply->icmpMsg.pid, reply->ipHdr.TTL);

    print_info_msg(reply->icmpMsg.icmpHdr.type, reply->icmpMsg.icmpHdr.code);

    free(request);
    free(reply);
    close(sockfd);

    return EXIT_SUCCESS;
}

//Genera una cabecera ICMP tipo Request (Type 8, Code 0).
ICMPHeader createICMP_header(){
    ICMPHeader header = {.type = (unsigned char)8 , .code = (unsigned char) 0 , .checksum = (unsigned char) 0};
    return header;
}

unsigned short create_checksum(unsigned char* addr, size_t size ){
    unsigned int checksum = 0;

    //Sumamos palabras de 16 bits.
    while(size > 1){
        checksum = checksum + *((unsigned short*) addr);
        addr+=2;
        size = size - 2;
    }
    //Si quedan bytes sueltos, los sumamos también
    if(size > 0)
        checksum = checksum + *((unsigned char*) addr);

    //El checksum debe caber en 16 bits. Apilamos todo en 16 bits.
    while(checksum>>16){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    //Devolvemos el Complemento a 1.
    return (~checksum);
}

void createICMP_request(EchoRequest* request){
    request->icmpHdr = createICMP_header();
    request->pid = (unsigned short) getpid();
    request->sequence = 0;
    char* cadena = "Este es el payload son 64 bytes y los voy a usarlos todos vale?";
    strncpy(request->payload,cadena,SIZE);
    request->icmpHdr.checksum = create_checksum((unsigned char*)request, sizeof(*request));
    //ASSERT(!create_checksum((unsigned char*)request, sizeof(*request)), "ERROR generando checksum del paquete\n");

}

void print_info_msg(unsigned char type, unsigned char code)
{

    const char *def_erorr_msg = "Unknown error code.";

    const char *msg_dest_unreach[] = {
        "Net Unreachable.",
        "Host Unreachable.",
        "Protocol Unreachable.",
        "Port Unreachable.",
        "Fragmentation Needed.",
        "Source Route Failed.",
        "Destination Network Unknown.",
        "Destination Host Unknown.",
        "Source Host Isolated.",
        "Unknown error code.",
        "Unknown error code.",
        "Destination Network Unreachable for Type of Service.",
        "Destination Host Unreachable for Type of Service.",
        "Communication Administratively Prohibited.",
        "Host Precedence Violation.",
        "Precedence Cutoff in Effect."};

    const char *msg_redirect[] = {
        "Unknown error code.",
        "Redirect for Destination Host.",
        "Unknown error code.",
        "Redirect for Destination Host Based on Type-of-Service."};

    const char *msg_time_exceeded[] = {
        "Time-to-Live Exceeded in Transit.",
        "Fragment Reassembly Time Exceeded."};

    const char *msg_parameter_problem[] = {
        "Pointer indicates the error.",
        "Missing a Required Option.",
        "Bad Length."};

    switch (type)
    {
    case 0:
        printf("%s", (code == 0) ? "Respuesta correcta." : def_erorr_msg);
        break;
    case 3:
        printf("Destination Unreachable: %s", msg_dest_unreach[code]);
        break;
    case 5:
        printf("Redirect: %s", msg_redirect[code]);
        break;
    case 11:
        printf("Time Exceeded: %s", msg_time_exceeded[code]);
        break;
    case 12:
        printf("Parameter Problem: %s", msg_parameter_problem[code]);
        break;
    default:
        printf("%s", def_erorr_msg);
    }

    printf(" (Type %hhu, Code %hhu)\n", type, code);
}
