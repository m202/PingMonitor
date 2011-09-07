/* 
 * File:   main.c
 * Author: cking
 *
 * Created on April 23, 2010, 9:01 PM
 */

#define DESTINATION "192.168.0.1"
#define SOURCE "192.168.0.2"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#ifdef BSD
#define I_ICMPHDR icmp
#define I_TYPE icmp_type
#define I_CODE icmp_code
#define I_UN icmp_hun
#define I_ECHO ih_idseq
#define I_ID icd_id
#define I_SEQUENCE icd_seq
#define I_CHECKSUM icmp_cksum
#define IP_IPHDR ip
#define IP_PROTOCOL ip_p
#define IP_IHL ip_hl
#else
#define I_ICMPHDR icmphdr
#define I_TYPE type
#define I_CODE code
#define I_UN un
#define I_ECHO echo
#define I_ID id
#define I_SEQUENCE sequence
#define I_CHECKSUM checksum
#define IP_IPHDR iphdr
#define IP_PROTOCOL protocol
#define IP_IHL ihl
#endif

#define PAYLOAD "ALIVE?ALIVE?ALIVE?ALIVE?"
#define HDR_SIZE sizeof(struct I_ICMPHDR)
#define RECV_MAX 65535

typedef struct I_ICMPHDR icmphdr_t;
typedef struct IP_IPHDR iphdr_t;
void *recv_buf;
FILE *led_file;

void *init_ping_packet(const char *payload, const size_t len) {
    void *output = malloc(len);
    icmphdr_t *header = (icmphdr_t*) output;
    memset(output, 0, len);
    header->I_TYPE = ICMP_ECHO;
    header->I_CODE = 0;
    header->I_UN.I_ECHO.I_ID = htons(getpid());
    header->I_UN.I_ECHO.I_SEQUENCE = 0;
    memcpy(output + HDR_SIZE, payload, len - HDR_SIZE);

    return output;
}

void checksum_packet(void *packet, size_t len) {
    icmphdr_t *header = (icmphdr_t*) packet;
    header->I_CHECKSUM = 0;
    register long sum = 0;
    unsigned short *addr = (unsigned short*) packet;


    while (len > 1) {
        /*  This is the inner loop */
        sum += *(unsigned short *) addr++;
        len -= 2;
    }

    /*  Add left-over byte, if any */
    if (len > 0)
        sum += *(unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    header->I_CHECKSUM = ~sum;
}

void incr_packet(icmphdr_t *packet) {
    packet->I_UN.I_ECHO.I_SEQUENCE = htons((ntohs(packet->I_UN.I_ECHO.I_SEQUENCE) + 1) % 10);
}

void print_packet(void *packet, size_t len) {
    char *hex = "0123456789ABCDEF";
    unsigned char *data = (char*) packet;
    int i;
    printf("len=%d ", len);
    for (i = 0; i < len; i++) {
        putchar(*(hex + ((data[i] & 0xF0) >> 4)));
        putchar(*(hex + (data[i] & 0x0F)));
        putchar(i < len - 1 ? ' ' : '\0');
    }
    putchar('\n');
}

int ping(int sock, void *packet, socklen_t packet_size, struct sockaddr *sdest) {

    // Declarations
    socklen_t recv_size;
    size_t received;

    // Send outgoing ICMP packet
    sendto(sock, packet, packet_size, 0, sdest, (socklen_t) sizeof (*sdest));
    // print_packet(packet, packet_size);

    // printf("Reading messages\n");
    // Loop and receive every packet
    while (1) {
        // Wait for activity on the socket
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        if (select(sock + 1, &fds, NULL, NULL, &timeout) == -1) {
            perror("select");
            return 0;
        }

        if (!FD_ISSET(sock, &fds)) {
            // printf("TIMEOUT\n");
            return 0;
        }


        socklen_t recv_size;
        received = recvfrom(sock, recv_buf, RECV_MAX, 0, sdest, & recv_size);

        // print_packet(packet, received);
        iphdr_t *ip_header = (iphdr_t*) recv_buf;

        if (ip_header->IP_PROTOCOL == IPPROTO_ICMP) {
            icmphdr_t *icmp_header = (icmphdr_t*) (ip_header + ntohs(ip_header->IP_IHL));
            if (icmp_header->I_TYPE == ICMP_ECHOREPLY) {
                // printf("SUCCESS\n");
                return 1;
            } else {
                // printf("Unknown ? = %x\n", icmp_header->type);
            }
        } else {
            // printf("NONICMP\n");
        }
    }
}

void fail(int flag) {
    static int prev_flag = -1;

    led_file = fopen("/dev/led/error", "w");

    if (led_file == NULL)
        return;

    if (prev_flag != flag) {
        printf("fail flag = %d\n", flag);
        if (flag == 0) {
            fprintf(led_file, "0\n");
        } else if (flag == 1) {
            fprintf(led_file, "f5\n");
        } else if (flag == 2) {
            fprintf(led_file, "1\n");
        }
        prev_flag = flag;
    }
    fclose(led_file);
}

void sighandler(int sig) {
    if (sig == SIGINT) {
        fail(0);
        exit(0);
    } else if (sig == SIGSEGV) {
        fail(2);
        exit(1);
    }
}

/*
 * 
 */
int main(int argc, char **argv) {

    // Declarations
    struct timeval tv, tv2;
    long double msec;

    // Initialize outgoing ICMP packet
    size_t packet_size = sizeof (icmphdr_t) + strlen(PAYLOAD);
    icmphdr_t *packet = (icmphdr_t*) init_ping_packet(PAYLOAD, packet_size);
    checksum_packet(packet, packet_size);

    // Allocate space for incoming packet
    recv_buf = malloc(RECV_MAX);

    // Initialize socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    // Initialize signal handlers
    signal(SIGINT, &sighandler);
    signal(SIGSEGV, &sighandler);

    // Get destination address
    in_addr_t dest;
    dest = inet_addr(DESTINATION);
    // dest = inet_addr("75.14.202.186");
    struct sockaddr_in sdest;
    sdest.sin_addr.s_addr = dest;
    sdest.sin_family = AF_INET;
    sdest.sin_port = htons(0);
    memset(&(sdest.sin_zero), 0, sizeof (sdest.sin_zero));

    // Get source address
    in_addr_t source;
    source = inet_addr(SOURCE);
    struct sockaddr_in ssource;
    ssource.sin_addr.s_addr = source;
    ssource.sin_family = AF_INET;
    ssource.sin_port = htons(0);
    memset(&(ssource.sin_zero), 0, sizeof (ssource.sin_zero));

    // Bind source
    if (bind(sock, (struct sockaddr*) & ssource, sizeof (ssource)) == -1) {
        perror("bind");
        exit(0);
    }

    while (1) {
        gettimeofday(&tv, NULL);
        int result = ping(sock, packet, packet_size, (struct sockaddr*) & sdest);
        if (result == 0) {
            fail(1);
        } else {
            fail(0);
        }
        incr_packet(packet);
        checksum_packet(packet, packet_size);
        gettimeofday(&tv2, NULL);
        double msec = ((tv2.tv_sec * 1000000.0 + tv2.tv_usec) - (tv.tv_sec * 1000000.0 + tv.tv_usec)) / 1000;
        printf("msec = %f\n", msec);
        if (msec < 1000) {
            usleep((1000 - msec) * 1000);
        }
    }
    return (EXIT_SUCCESS);
}
