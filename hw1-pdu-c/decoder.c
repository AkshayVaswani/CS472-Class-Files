#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "packet.h"
#include "nethelper.h"
#include "decoder.h"
#include "testframes.h"

test_packet_t TEST_CASES[] = {
    MAKE_PACKET(raw_packet_icmp_frame198),
    MAKE_PACKET(raw_packet_icmp_frame362),
    MAKE_PACKET(raw_packet_arp_frame78)
};

int main(int argc, char **argv) {
    int num_test_cases = sizeof(TEST_CASES) / sizeof(test_packet_t);
    printf("STARTING...");
    for (int i = 0; i < num_test_cases; i++) {
        printf("\n--------------------------------------------------\n");
        printf("TESTING A NEW PACKET\n");
        printf("--------------------------------------------------\n");
        test_packet_t test_case = TEST_CASES[i];
        decode_raw_packet(test_case.raw_packet, test_case.packet_len);
    }
    printf("\nDONE\n");
}

void decode_raw_packet(uint8_t *packet, uint64_t packet_len){
    printf("Packet length = %ld bytes\n", packet_len);
    struct ether_pdu *p = (struct ether_pdu *)packet;
    uint16_t ft = ntohs(p->frame_type);
    printf("Detected raw frame type from ethernet header: 0x%x\n", ft);
    switch(ft) {
        case ARP_PTYPE:
            printf("Packet type = ARP\n");
            arp_packet_t *arp = process_arp(packet);
            print_arp(arp);
            break;
        case IP4_PTYPE:
            printf("Frame type = IPv4, now lets check for ICMP...\n");
            ip_packet_t *ip = (ip_packet_t *)packet;
            bool isICMP = check_ip_for_icmp(ip);
            if (!isICMP) {
                printf("ERROR: IP Packet is not ICMP\n");
                break;
            }
            icmp_packet_t *icmp = process_icmp(ip);
            bool is_echo = is_icmp_echo(icmp);
            if (!is_echo) {
                printf("ERROR: We have an ICMP packet, but it is not of type echo\n");
                break;
            }
            icmp_echo_packet_t *icmp_echo_packet = process_icmp_echo(icmp);
            print_icmp_echo(icmp_echo_packet);
            break;
    default:
        printf("UNKNOWN Frame type?\n");
    }
}

arp_packet_t *process_arp(raw_packet_t raw_packet) {
    return (arp_packet_t *)raw_packet;
}

void print_arp(arp_packet_t *arp){
 printf("remove this, for now just printing hello from ARP\n");
}

bool check_ip_for_icmp(ip_packet_t *ip){
    return (ip->protocol == ICMP_PTYPE);
}

icmp_packet_t *process_icmp(ip_packet_t *ip){
    return (icmp_packet_t *)((uint8_t *)ip + ip->ihl * 4);
}

bool is_icmp_echo(icmp_packet_t *icmp) {
    return (icmp->type == ICMP_ECHO_REQUEST || icmp->type == ICMP_ECHO_RESPONSE);
}

icmp_echo_packet_t *process_icmp_echo(icmp_packet_t *icmp){
    icmp_echo_packet_t *icmp_echo = (icmp_echo_packet_t *)icmp;
    icmp_echo->id = ntohs(icmp_echo->id);
    icmp_echo->sequence = ntohs(icmp_echo->sequence);
    icmp_echo->timestamp = ntohl(icmp_echo->timestamp);
    return icmp_echo;
}

void print_icmp_echo(icmp_echo_packet_t *icmp_packet){
    uint16_t payload_size = ICMP_Payload_Size(icmp_packet);
    print_icmp_payload(icmp_packet->icmp_payload, payload_size);
}

void print_icmp_payload(uint8_t *payload, uint16_t payload_size) {
    for (uint16_t i = 0; i < payload_size; i++) {
        if (i % 16 == 0)
            printf("0x%04x | ", i);
        printf("%02x  ", payload[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}
