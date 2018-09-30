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

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){


    /* TODO: Your code here. */

    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */
    printf("In Send() len: %d, flags: %d", (int)len, flags);
    return(0);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    /* TODO: Your code here. */

    return(-1);
}

int gbn_close(int sockfd){

    /* TODO: Your code here. */

    return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    int numbytes;
    printf("In Connect() with socket: %d, server: %d, socklen: %d\n", sockfd, server->sa_family, socklen);

    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));
    SYN_packet->type = SYN;

    /* init the SYNACK packet to be sent */
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    memset(SYNACK_packet->data, 0, sizeof(SYNACK_packet->data));

    printf("SYN packet type: %d\n", SYN_packet->type);

    while(1) {
        if (s.curr_state == CLOSED) {

            if ((numbytes = sendto(sockfd, SYN_packet, sizeof(SYN_packet), 0, server, socklen)) == -1) {
                perror("Sendto error");
                exit(-1);
            }

            s.curr_state = SYN_SENT;

            printf("Current state: %d\n", s.curr_state);
        }

        if (s.curr_state == SYN_SENT) {

            recvfrom(sockfd, SYNACK_packet, sizeof(SYNACK_packet), 0, (struct sockaddr *)&server, &socklen);

            if (SYNACK_packet->type == SYNACK) {

                s.curr_state = ESTABLISHED;
                printf("Current state: %d\n", s.curr_state);

                return sockfd;
            }

        }
    }
    return(-1);
}

int gbn_listen(int sockfd, int backlog){

    /* ---- There is no need to listen. Using only UDP calls. ---- */

    printf("In Listen(), sockfd: %d, backlog: %d \n", sockfd, backlog);

    /* Setting the default to closed since there is no connection established yet */
    s.curr_state = CLOSED;

    return(0);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

    int status;

    printf("In bind(),  sockfd: %d\n", sockfd);

    if ((status = bind(sockfd, server, socklen)) == -1) {

        perror("Bind error");

        exit(-1);
    }

    return status;
}

int gbn_socket(int domain, int type, int protocol){

    /*----- Randomizing the seed. This is used by the rand() function -----*/
    srand((unsigned)time(0));

    printf("domain: %d, type %d, protocol %d\n", domain, type, protocol);

    /* Assign a random seq number used when sending or receiving packets */
    s.seq_num = (uint8_t)rand();

    /* Set the size to 1. This state will be modified according to the go-back-n protocol */
    s.window_size = 1;

    printf("Seq num: %d, Window size: %d\n", s.seq_num, s.window_size);

    int sockfd = socket(domain, type, protocol);

    printf("Socket created %d\n", sockfd);

    return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    /* char buf[DATALEN]; */

    printf("In Accept() socket: %d, client address: %d\n", sockfd, client->sa_family);

    /* init SYN_packet to be populated */
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));

    /* init the SYNACK packet to be sent */
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    memset(SYNACK_packet->data, 0, sizeof(SYNACK_packet->data));
    SYNACK_packet->type = SYNACK;


    while(1){
        printf("Accepting...\n");
        if (s.curr_state == CLOSED) {
            int byte_count = recvfrom(sockfd, SYN_packet, sizeof(SYN_packet), 0, client, socklen);
            printf("byte_count: %d\n", byte_count);

            printf("data: %d\n", SYN_packet->type);
        }

        if (SYN_packet->type == SYN) {
            s.curr_state = SYN_RCVD;
            printf("Current state: %d\n", s.curr_state);

            if (sendto(sockfd, SYNACK_packet, sizeof(SYNACK_packet), 0, client, *socklen) == -1) {
                perror("SYNACK send error");
                exit(-1); /* TODO retry sending SYNACK */
            }
            s.curr_state = ESTABLISHED;
            printf("Current state: %d\n", s.curr_state);
            return sockfd;
        }

        printf("\n");
    }



    return(0);
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
