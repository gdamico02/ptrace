#include "header.h"

void die() {
	fprintf(stderr, "Exiting...\n");
	exit(1);
}

void printUsage(char *myname) {
	printf("\nUsage: %s <host> [-<options>]\n", myname);
	puts("\nRequired:");
	puts("<host>\tthe host to traceroute (either hostname or ip address)");
	puts("\nOptions:");
	puts("-h <hops>\tMaximum hops (TTL value) for the trace. Default is 30.");
	puts("-c <number>\tProbe packets to send to each hop. Default is 3.");
	puts("-t <timeout>\tTimeout value in milliseconds. Default is 4000.");
	printf("\n");
	exit(0);
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}