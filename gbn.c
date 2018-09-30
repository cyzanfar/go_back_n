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


    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */
    /* create the data and data ack used to receive and respond to incoming packet */
    gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
    memset(DATA_packet->data, 0, sizeof(DATA_packet->data));
    DATA_packet->type = DATA;

    gbnhdr *DATAACK_packet = malloc(sizeof(*DATAACK_packet));
    memset(DATAACK_packet->data, 0, sizeof(DATAACK_packet->data));

    struct sockaddr server;
    socklen_t server_len = sizeof(server);



    printf("In Send() buf len: %d, flags: %d\n", (int)len, flags);

    if (len < 1029) {

        memcpy(DATA_packet->data, buf, len);

        printf("DATA packet size: %d\n", (int)sizeof(DATA_packet));

        printf("Sending DATA_packet to client...\n");

        if(sendto(sockfd, DATA_packet, sizeof(*DATA_packet), flags, &s.address, s.sock_len) == -1) {
            perror("Data packet send error");
            exit(-1);
        }

        printf("DATA packet content: %s\n", DATA_packet->data);

        printf("DATA_packet send successfully...\n");

        printf("Waiting for DATAACK packet...\n");
        if (recvfrom(sockfd,DATAACK_packet, sizeof(*DATAACK_packet), flags, &server, &server_len) == -1) {
            perror("Data ack packet recv error");
            exit(-1);
        }
        printf("DATAACK_packet received...\n");
    }

    printf("length: %d\n",(int)len);

    return(len);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    printf("In Recv()\n");

    /* create the data and data ack used to receive and respond to incoming packet */
    gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
    memset(DATA_packet->data, 0, sizeof(DATA_packet->data));

    gbnhdr *DATAACK_packet = malloc(sizeof(*DATAACK_packet));
    memset(DATAACK_packet->data, 0, sizeof(DATAACK_packet->data));
    DATAACK_packet->type = DATAACK;

    struct sockaddr client;
    socklen_t client_len = sizeof(client);

    ssize_t byte_length;

    while(s.curr_state == ESTABLISHED){

        printf("Connection is established. Waiting for packet...\n");


        if ((byte_length = recvfrom(sockfd,DATA_packet, sizeof(*DATA_packet), flags, &client, &client_len)) == -1) {
            perror("Data packet recv error");
            exit(-1);

        }
        printf("Data packet size: %d\n", (int)sizeof(DATA_packet));

        printf("Byte length upon receive: %d\n", (unsigned int)byte_length);

        if (DATA_packet->type == DATA) {

            printf("DATA_packet received. Sending DATACK_packet...\n");

            memcpy(buf, DATA_packet->data, byte_length);

            printf("Data packet content: %s\n", DATA_packet->data);

            printf("Buffer content: %s\n", buf);

            /* s.curr_state = CLOSED;  just a placeholder */
            printf("Sending DATAACK_packet...\n");

            if(sendto(sockfd, DATAACK_packet, sizeof(*DATAACK_packet), flags, &client, client_len) == -1) {
                perror("DATAACK packet error");
                exit(-1);
            }
        }


    }
    printf("returning len in gbn_recv\n");

    printf("DATA_packet->data length: %d\n", (int)sizeof(DATA_packet->data));

    return(len);
}

int gbn_close(int sockfd){

    /* TODO: Your code here. */

    return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

    printf("In Connect() with socket: %d, server: %d, socklen: %d\n", sockfd, server->sa_family, socklen);

    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));

    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seq_num;

    /* TODO add checksum to SYN packet */

    /* init the SYNACK packet to be sent */
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    memset(SYNACK_packet->data, 0, sizeof(SYNACK_packet->data));


    printf("SYN packet type: %d\n", SYN_packet->type);
    if (s.curr_state == CLOSED) {

        printf("Sending SYN_packet\n");

        if (sendto(sockfd, SYN_packet, sizeof(SYN_packet), 0, server, socklen) == -1) {
            perror("Sendto error");
            exit(-1);
        }

        s.curr_state = SYN_SENT;
        s.address = *server;

        s.sock_len = socklen;

        printf("Current state: %d\n", s.curr_state);
    }

    if (s.curr_state == SYN_SENT) {

        printf("Waiting for SYNACK_packet...\n");

        if(recvfrom(sockfd, SYNACK_packet, sizeof(SYNACK_packet), 0, (struct sockaddr *)&server, &socklen) == -1) {
            perror("Recvfrom error");
            exit(-1);
        }

        if (SYNACK_packet->type == SYNACK) { /* TODO check also for checksum */

            printf("SYNACK_packet received\n");

            s.curr_state = ESTABLISHED;

            /* TODO assign checksum here to the state */

            printf("Current state: %d\n", s.curr_state);
        }

    }
    return sockfd;
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

    /* Binding to the socket for further use */
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

    printf("In Accept() socket: %d, client address: %d\n", sockfd, client->sa_family);
    printf("Current state: %d\n", s.curr_state);

    /* init SYN_packet to be populated */
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));

    /* init the SYNACK packet to be sent after the SYN packet */
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    memset(SYNACK_packet->data, 0, sizeof(SYNACK_packet->data));
    SYNACK_packet->type = SYNACK;

    /* number of bytes received */
    ssize_t byte_count;

    if (s.curr_state == CLOSED) {

        printf("Waiting for SYN_packet...\n");

        /* Waiting for a SYN packet to establish connection */
        if ((byte_count = recvfrom(sockfd, SYN_packet, sizeof(SYN_packet), 0, client, socklen) == -1)) {
            perror("SYNACK send error");
            exit(-1);
        }

        printf("byte_count: %d, SYN type: %d\n", (int)byte_count, SYN_packet->type);
    }

    if (SYN_packet->type == SYN) {
        printf("SYN_packet received\n");

        s.curr_state = SYN_RCVD;

        printf("Current state: %d\n", s.curr_state);

        printf("Sending SYNACK_packet...\n");

        if (sendto(sockfd, SYNACK_packet, sizeof(SYNACK_packet), 0, client, *socklen) == -1) {
            perror("SYNACK send error");

            exit(-1); /* TODO retry sending SYNACK */
        }

        s.curr_state = ESTABLISHED;
        s.address = *client;
        s.sock_len = *socklen;

        printf("Current state: %d\n", s.curr_state);

        free(SYN_packet);
        free(SYNACK_packet);
        printf("socket: %d\n", sockfd);
    }

    if (s.curr_state == ESTABLISHED) {
        return sockfd;
    } else {
        printf("return -1");
        return(-1);
    }
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
