#include "gbn.h"

state_t s;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

void signal_handler(){}

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
	uint16_t recv_checksum = packet->checksum;
	packet->checksum = 0;
	uint16_t expected_checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

	if (recv_checksum == expected_checksum){
		printf("validate_packet: success, checksum %d\n", recv_checksum);
		return 1;
	}
	printf("validate_packet: mismatch, received: %d, calculated: %d\n", recv_checksum, expected_checksum);
	return 0;
}

size_t build_packet(gbnhdr *packet, uint8_t type, uint8_t seqnum, const void *buf, size_t len){
	if(len > DATALEN){
		printf("build_packet: the expected packet length exceeds the max length ");
		return -1;
	}
	memset(packet, 0, sizeof(*packet));
	packet -> type = type;
	packet -> seqnum = seqnum;
	if(buf != NULL && len > 0){
		memcpy(packet->data, buf, len);
	}
	packet -> checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));
	printf("build_packet: get checksum: %d\n", packet -> checksum);
	size_t tot_size = sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->checksum) + sizeof(uint8_t) * len;
	return tot_size;
}

void store_packet(uint8_t type, uint8_t seqnum, const void* buf, size_t len){
	printf("store_packet: seqnum = %d\n", seqnum);
	gbnhdr packet;
	size_t packet_size = build_packet(&packet, type, seqnum, buf, len);
	memcpy(&s.packet_buf[seqnum], &packet, sizeof(gbnhdr));
	s.packet_size[seqnum] = packet_size;
}

ssize_t maybe_send_packet(int sockfd, uint8_t seqnum, int flags){
	printf("maybe_sent_packet: seqnum=%d\n", seqnum);
	return maybe_sendto(sockfd, &s.packet_buf[seqnum], s.packet_size[seqnum], flags, (struct sockaddr *)&s.sockaddr, s.socklen);
}

ssize_t maybe_send(int sockfd, uint8_t type, uint8_t seqnum, const void *buf, size_t len, int flags) {
	printf("call maybe_send()\n");

	gbnhdr packet;
	size_t packet_size = build_packet(&packet, type, seqnum, buf, len);

	return maybe_sendto(sockfd, &packet, packet_size, flags, (struct sockaddr *)&s.sockaddr, s.socklen);
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	printf("call gbn_send()\n");
	gbnhdr packet;

	printf("set window_size = %d\n", WINDOW_SIZE_SLOW);
	s.windowsize = WINDOW_SIZE_SLOW;
	
	size_t offset = 0;

	while(offset < len){
		printf("--------------------------------------\n");
		printf("gbn_send: offset / length : (%lu / %lu)\n", offset, len);
		printf("gbn_send: window size = %d\n", s.windowsize);
		
		size_t tmp_offset = offset;
		int cnt_packet;
		for(cnt_packet = 0; cnt_packet < s.windowsize; cnt_packet++){
			size_t tmp_seqnum = get_nth_seq_num(s.seqnum, cnt_packet);
			size_t data_size = MIN(DATALEN, len - tmp_offset);
			if(data_size <= 0) break;
			store_packet(DATA, tmp_seqnum, buf + tmp_offset, data_size);
			tmp_offset += data_size;
		}
		printf("bug_send: create %d packet(s)\n", cnt_packet);

		printf("-------------------\n");
		int sent_packet;
		for(sent_packet = 0; sent_packet < cnt_packet; sent_packet++){
			size_t tmp_seqnum = get_nth_seq_num(s.seqnum, sent_packet);
			printf("gbn_send: send DATA packet, seqnum=%lu\n", tmp_seqnum);
			if(maybe_send_packet(sockfd, tmp_seqnum, flags) < 0)
				return -1;
		}

		printf("-------------------\n");
		size_t error_detected = FALSE;
		int acked_packet;
		for(acked_packet = 0; acked_packet < cnt_packet; acked_packet++){
			size_t ack_status = recv_ack(sockfd, &packet, flags);
			if(ack_status == ACK_STATUS_TIMEOUT || ack_status == ACK_STATUS_CORRUPT || ack_status == ACK_STATUS_BADSEQ){
				printf("gbn_send: detect error when receiving ACK\n");
				error_detected = TRUE;
			}
			else if(ack_status <= 0){
				return -1;
			}
			else{
				printf("gbn_send: receive ack, update offset\n");
				offset += MIN(DATALEN, len - offset);
				error_detected = FALSE;
			}
		}
		if(error_detected){
			printf("set window_size = %d\n", WINDOW_SIZE_SLOW);
			s.windowsize = WINDOW_SIZE_SLOW;
		}
		else{
			if(s.windowsize == WINDOW_SIZE_SLOW){
				s.windowsize = WINDOW_SIZE_MID;
			}
			else if(s.windowsize == WINDOW_SIZE_MID){
				s.windowsize = WINDOW_SIZE_FAST;
			}
			printf("set window_size = %d\n", s.windowsize);
		}
	}
	return 0;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	printf("call gbn_recv()\n");
	gbnhdr packet;
	size_t packet_len_bytes;
	while(TRUE){
		printf("--------------------------------------\n");
		printf("gbn_recv: receiv DATA\n");
		gbnhdr_clear(&packet);
		packet_len_bytes = maybe_recvfrom(sockfd, &packet, sizeof(gbnhdr), flags, (struct sockaddr *)&s.sockaddr, &s.socklen);
		if(packet_len_bytes <= 0){
			return packet_len_bytes;
		}
		uint8_t packet_valid = validate_packet(&packet);
		if(packet_valid == FALSE){
			continue;
		}
		printf("gbn_recv: receive packet with sequence number: %d\n", packet.seqnum);
		if(packet.seqnum != s.seqnum){
			if(packet.type == DATA){
				printf("gbn_recv: send DATAACK\n");
				if(maybe_send(sockfd, DATAACK, s.seqnum, NULL, 0, flags) < 0){
					return -1;
				}
			}
			else if(packet.type == SYN){
				printf("gbn_recv: send SYNACK\n");
				if(maybe_send(sockfd, SYNACK, s.seqnum, NULL, 0, flags) < 0){
					return -1;
				}
			}
			else{
				return -1;
			}
			continue;
		}
		break;
	}

	increment_seq_num();

	if(packet.type == DATA){
		printf("gbn_recv: receive DATA packet\n");
		size_t data_len_bytes = packet_len_bytes - (sizeof(packet.type) + sizeof(packet.seqnum) + sizeof(packet.checksum));
		memcpy(buf, packet.data, data_len_bytes);
		printf("gbn_recv: send DATAACK\n");
		if (maybe_send(sockfd, DATAACK, s.seqnum, NULL, 0, flags) < 0){
			return -1;
		}
		return data_len_bytes;
	}
	else if(packet.type == FIN){
		printf("gbn_recv: redeive FINACK\n");
		printf("gbn_recv: send FINACK\n");
		if(maybe_send(sockfd, FINACK, s.seqnum, NULL, 0, flags) < 0){
			return -1;
		}
		return 0;
	}
	printf("gbn_recv: waiting for DATA or FIN packet\n");
	return -1;
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	printf("call gbn_close()\n");
	int flags = 0;
	ssize_t status = 0;
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
			if (status == ACK_STATUS_TIMEOUT || status == ACK_STATUS_TIMEOUT || status == ACK_STATUS_BADSEQ) {
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
	printf("call gbn_connect()\n");
	int flags = 0;
	int ack_status = 0;
	gbnhdr ack_packet;
	gbn_init();

	memcpy(&s.sockaddr, server, socklen);
	memcpy(&s.socklen, &socklen, sizeof(socklen_t));

	while (1) {
		if (maybe_send(sockfd, SYN, s.seqnum, NULL, 0, flags) < 0) {
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
	printf("call gbn_listen()\n");
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	printf("call gbn_bind()\n");
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	printf("call gbn_socket()\n");
	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	printf("call gbn_accept()\n");
	int flags = 0;
	gbnhdr packet;
	gbn_init();
	while (1){
		printf("gbn_accept: receiving SYN\n");
		gbnhdr_clear(&packet);
		if (maybe_recvfrom(sockfd, &packet, sizeof(gbnhdr), flags, client, socklen) < 0){
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

	if (s.seqnum == (MAX_SEQ_NUM - 1)) {
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


ssize_t recv_ack(int sockfd, gbnhdr *packet, int flags) {
	printf("call recv_ack()\n");
	gbnhdr_clear(packet);
	alarm(TIMEOUT);
	ssize_t result = maybe_recvfrom(sockfd, packet, sizeof(gbnhdr), flags, (struct sockaddr *)&s.sockaddr, &s.socklen);
	alarm(INT_MAX);
	if (result == 0) {
		return 0;
	}
	if (result == -1) {
		if (errno == EINTR){
			printf("recv_ack: ACK TIMEOUT\n");
			return ACK_STATUS_TIMEOUT;
		}
		return -1;
	}
	uint8_t packet_valid = validate_packet(packet);
	if (!packet_valid) {
		printf("recv_ack: ACK CORRUPT\n");
		return ACK_STATUS_CORRUPT;
	}
	printf("recv_ack: seqnum %d\n", packet->seqnum);
	if (packet->seqnum != get_nth_seq_num(s.seqnum, 1) &&
		  packet->seqnum != get_nth_seq_num(s.seqnum, 2)) {

		printf("recv_ack: ACK BAD SEQ NUM\n");
		return ACK_STATUS_BADSEQ;
	}
	increment_seq_num();
	return result;
}

uint8_t get_next_seq_num(uint8_t seq_num) {
	if (seq_num == (MAX_SEQ_NUM - 1)) {
		return 0;
	}
	seq_num++;
	return seq_num;
}

uint8_t get_nth_seq_num(uint8_t seqnum, int n) {
	uint8_t tmp_seqnum = seqnum;
	int i;
	for (i = 0; i < n; i++){
		tmp_seqnum = get_next_seq_num(tmp_seqnum);
	}

	return tmp_seqnum;
}

void increment_seq_num() {
	s.seqnum = get_next_seq_num(s.seqnum);
}

void gbnhdr_clear(gbnhdr *packet) {
	memset(packet, 0, sizeof(*packet));
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
