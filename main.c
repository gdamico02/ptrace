#include "header.h"
#define BUFFER 4096
#define MAXHOPS 30
#define PROBECOUNT 3
#define TIMEOUT 4000
#define IP_HEADER_LEN 20

int main(int argc, char *argv[]) {

	int uid, sd, bytesent, byterecvd, ttl, max_hops, count, timeout, tmp;
	double rtt;
	char sendbuff[BUFFER], recvbuff[BUFFER], host_ip[INET6_ADDRSTRLEN];
	bool dns_required, destination_reached;
	struct sockaddr_in client_socket, remote_socket;
	socklen_t client_socket_length, remote_socket_length;
	struct hostent *host_data;
	struct icmphdr *icmph_src;
	struct icmphdr *icmph_dst;
	struct timeval timeout_time, sent_time, recvd_time;
    fd_set readfds;

	// Root check
	uid = getuid();
	if (uid != 0) {
		fprintf(stderr, "Root privileges required.\n");
		die();
	}

	// Args check
	if (argc < 2) {
		printUsage(argv[0]);
	}

	// Variables initialization
	max_hops = MAXHOPS;
	count = PROBECOUNT;
	timeout = TIMEOUT;
	ttl = 1;
	dns_required = false;
	destination_reached = false;
	client_socket_length = sizeof(client_socket);
	remote_socket_length = sizeof(remote_socket);
	memset(sendbuff, 0, BUFFER);
	memset(recvbuff, 0, BUFFER);

	// Host check
	host_data = gethostbyname(argv[1]);
	if (host_data == NULL) {
		fprintf(stderr, "Usage error: invalid host specified\n");
		die();
	}
	inet_ntop(AF_INET, host_data->h_addr_list[0], host_ip, INET_ADDRSTRLEN);
	if (strcmp(host_data->h_name,host_ip) != 0) {
		dns_required = true;
	}

	// Flags check
	if (argc > 2) {
		int i;
		for (i=2; i<argc; i++) {
			// Set max hops
			if (strcmp(argv[i], "-h") == 0) {
				if (!argv[i+1]) {
					fprintf(stderr, "Usage error: missing value for '-h' option\n");
					die();
				}
				max_hops = atoi(argv[i+1]);
				if (max_hops <= 0) {
					fprintf(stderr, "Usage error: '-h' option value must be an integer\n");
					die();
				}
				i++;
			}
			// Set timeout
			else if (strcmp(argv[i], "-t") == 0) {
				if (!argv[i+1]) {
					fprintf(stderr, "Usage error: missing value for '-t' option\n");
					die();
				}
				timeout = atoi(argv[i+1]);
				if (timeout <= 0) {
					fprintf(stderr, "Usage error: '-t' option value must be an integer\n");
					die();
				}
				i++;
			}
			// Set probe packets number
			else if (strcmp(argv[i], "-c") == 0) {
				if (!argv[i+1]) {
					fprintf(stderr, "Usage error: missing value for '-c' option\n");
					die();
				}
				count = atoi(argv[i+1]);
				if (count <= 0) {
					fprintf(stderr, "Usage error: '-c' option value must be an integer\n");
					die();
				}
				i++;
			}
			// Invalid argument
			else {
				fprintf(stderr, "Usage error: invalid option '%s'\n",argv[i]);
				die();
			}
		}
	}

	// Socket
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0) {
		fprintf(stderr, "socket() error\n");
		die();
	}

	// Client socket parameters
	client_socket.sin_family = AF_INET;
	client_socket.sin_addr.s_addr = inet_addr(host_ip);

	if (dns_required) {	// DNS translation required
		printf("Attempting to traceroute %s (%s) ...\n", host_data->h_name, host_ip);
	}
	else { // Host IP specified
		printf("Attempting to traceroute %s ...\n", host_ip);
	}
	printf("Max hops: %d\n", max_hops);
	printf("Probe packets: %d\n", count);
	printf("Timeout: %d ms\n", timeout);
	printf("Protocol: ICMP\n");
	puts("\nhop\thost\t\trtt (round trip time)");

	// Loop until max hops
	while(destination_reached == false && ttl <= max_hops) {
		
		// Set probe packets count
		tmp = count;
		
		// Set TTL
        if (setsockopt(sd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            fprintf(stderr, "setsockopt() error\n");
            die();
        }

		// Fill ICMP header
		icmph_src = (struct icmphdr*) sendbuff;
		icmph_src->type = ICMP_ECHO;
		icmph_src->code = 0;
		icmph_src->checksum = 0;
		icmph_src->un.echo.id = htons(getpid());
      	icmph_src->un.echo.sequence = htons(ttl);
		icmph_src->checksum = csum ((unsigned short *) icmph_src, sizeof(struct icmphdr));

		// Until probe packets count is reached
		while (tmp > 0) {
			
			// Record sending time
			gettimeofday(&sent_time, NULL);

			// Send ICMP ECHO message
			bytesent = sendto(sd, sendbuff, sizeof(struct icmphdr), 0, (struct sockaddr*)&client_socket, client_socket_length);
			if (bytesent < 0) {
				fprintf(stderr, "sendto() error\n");
				die();
			}

			// Set timeout for recvfrom
			FD_ZERO(&readfds);
			FD_SET(sd, &readfds);
			timeout_time.tv_sec = timeout/1000;
			timeout_time.tv_usec = (timeout % 1000)*1000;

			// ICMP reply arrived
			if (select(sd + 1, &readfds, NULL, NULL, &timeout_time) > 0) {
				
				// Receive ICMP ECHO reply message
				byterecvd = recvfrom(sd, recvbuff, BUFFER, 0, (struct sockaddr*)&remote_socket, &remote_socket_length);
				if (byterecvd < 0) {
					fprintf(stderr, "recvfrom() error\n");
					die();
				}

				// Record receiving time
				gettimeofday(&recvd_time, NULL);
				
				// Calculate rtt (round trip time)
				rtt = (recvd_time.tv_sec - sent_time.tv_sec)*1000.0;      // sec to ms
				rtt += (recvd_time.tv_usec - sent_time.tv_usec)/1000.0;   // us to ms

				// Process ICMP reply
				icmph_dst = (struct icmphdr *) (recvbuff + IP_HEADER_LEN);	// icmp header starts from 21° byte
				if (tmp == count) {
					printf("%d\t", ttl);
				}

				// Time exceeded message (TTL expired)
				if (icmph_dst->type == ICMP_TIME_EXCEEDED) {
					if (tmp == count) {
						printf("%s\t", inet_ntoa(remote_socket.sin_addr));
					}
					printf("%.3fms ", rtt);
				}
				// Destination reached message
				else if (icmph_dst->type == ICMP_ECHOREPLY) {
					if (tmp == count) {
						printf("%s\t", inet_ntoa(remote_socket.sin_addr));
					}
					printf("%.3fms ", rtt);
					destination_reached = true;
				}
				// Unknown message
				else {
					if (tmp == count) {
						printf("%d\t", ttl);
						printf("*\t\t");
					}
					printf("*\t");
				}
			}
			// Timed out
			else {
				if (tmp == count) {
					printf("%d\t", ttl);
					printf("*\t\t");
				}
				printf("*\t");
			}
			// Decrease probe packets count
			tmp--;
		}
		
		printf("\n");
        ttl++;
    }

	if (!destination_reached) {
		puts("\nDestination unreachable.\n");
	}
	else {
		puts("\nTrace completed.\n");
	}

	close(sd);	

	return 0;

}
