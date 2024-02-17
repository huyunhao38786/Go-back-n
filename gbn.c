#include "gbn.h"

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	printf("gbn_close\n");
	int flags = 0;
	int status = 0;
	int fin_count = 0;
	gbnhdr ack_packet;
	if (s.is_sender){
		while (fin_count < MAX_FIN) {
			printf("gbn_close: sending FIN\n");
			if (maybe_send(sockfd, FIN, s.seqnum, NULL, 0, flags) < 0){
				return -1;
			}
			fin_count ++;
			printf("gbn_close: receiving FINACK\n");
			status = recv_ack(sockfd, &ack_packet, flags);
			if (status == ACK_STATUS_TIMEOUT || ACK_STATUS_TIMEOUT || ACK_STATUS_BADSEQ) {
				continue;
			} else if (status <= 0){
				return -1;
			} else if (ack_packet.type != FINACK){
				printf("gbn_close: expecting FINACK packet\n");
				return -1;
			} else {
				break;
			}
		}
	}
	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	int flags = 0;
	int ack_status = 0;
	gbnhdr ack_packet;
	gbn_init();

	memcpy(&s.sockaddr, server, socklen);
	memcpy(&s.socklen, &socklen, sizeof(socklen_t));

	while (1) {
		if (maybe_sendto(sockfd, SYN, s.seqnum, NULL, 0, flags) < 0) {
			return -1;
		}

		ack_status = recv_ack(sockfd, &ack_packet, flags);
		if (ack_status == ACK_STATUS_TIMEOUT || ack_status == ACK_STATUS_CORRUPT || ack_status == ACK_STATUS_BADSEQ) {
			continue;
		} else if (ack_status <= 0) {
			return -1;
		} else {
			break;
		}
	}
	if (ack_packet.type != SYNACK) {
		printf("connect: SYNACK expected");
		return -1;
	} else if (ack_packet.type == RST) {
		printf("connect: RST packet");
		return -1;
	} else if (ack_packet.seqnum != s.seqnum) {
		printf("connect: wrong sequence number");
	}
	s.active_connection = 1;
	s.is_sender = 1;
	return sockfd;
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */

	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	return socket(domain, type, protocol);
}

void signal_handler(){
	
}

void gbn_init() {
	struct sigaction sact = {
		.sa_handler = signal_handler,
		.sa_flags = 0,
	};

	sigaction(SIGALRM, &sact, NULL);

	s.seqnum = 0;
	s.active_connection = 0;
}

uint8_t validate_packet(gbnhdr *packet)
{
	uint16_t received_checksum = packet->checksum;
	packet->checksum = 0;
	uint16_t calculated_checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

	if (received_checksum == calculated_checksum){
		printf("validate_packet: success, checksum %d\n", received_checksum);
		return 1;
	}
	printf("*********************************************************\n");
	printf("validate_packet: mismatch, received: %d, calculated: %d\n", received_checksum, calculated_checksum);
	printf("*********************************************************\n");
	return 0;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	printf("gbn_accept:\n");
	int flags = 0;
	gbnhdr packet;
	gbn_init();
	while (1){
		printf("gbn_accept: receiving SYN\n");
		gbnhdr_clear(&packet);
		if (recvfrom(sockfd, &packet, sizeof(gbnhdr), flags, client, socklen) < 0){
			printf("gbn_accept: failed receiving SYN packet\n");
			return -1;
		}
		uint8_t packet_valid = validate_packet(&packet);
		if (!packet_valid){
			continue;
		}
		break;
	}
	printf("gbn_accept: sequence number: %d\n", packet.seqnum);
	if (packet.type != SYN) {
		printf("gbn_accept: expecting SYN packet\n");
		return -1;
	}
	if (packet.seqnum != s.seqnum){
		printf("gbn_accept: wrong sequence number\n");
		return -1;
	}

	memcpy(&s.sockaddr, client, *socklen);
	memcpy(&s.socklen, socklen, sizeof(socklen_t));

	if (s.active_connection){
		printf("gbn_accept: sending RST\n");
		if (maybe_send(sockfd, RST, s.seqnum, NULL, 0, 0) < 0){
			return -1;
		}
		return sockfd;
	}

	if (s.seqnum == (SEQNUM - 1)) {
		s.seqnum = 0;
	} else {
		++s.seqnum;
	}

	printf("gbn_accept: sending SYNACK\n");
	if(maybe_send(sockfd, SYNACK, s.seqnum, NULL, 0, 0) < 0){
		return -1;
	}

	s.active_connection = 1;
	s.is_sender = 0;

	return sockfd;
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
