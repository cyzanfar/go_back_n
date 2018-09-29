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

    printf("In Connect() with socket: %d, server: %d, socklen: %d\n", sockfd, server->sa_family, socklen);
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));

    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));

    SYN_packet->type = SYN;
    /*
    char msg[2000] = "hello world";
    */

    sendto(sockfd, msg, sizeof(msg), 0,server,socklen);

    return(0);
}

int gbn_listen(int sockfd, int backlog){

    /* here just change the state and return 0 */
    printf("In Listen func with sockfd %d and backlog %d \n", sockfd, backlog);
    /* s.curr_state = */
    return(0);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
    int status;
    printf("In bind() func %d\n", sockfd);

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

    s.seq_num = (uint8_t)rand();
    s.window_size = 1;

    int sockfd = socket(domain, type, protocol);
    printf("Socket created %d\n", sockfd);
    return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    char buf[DATALEN];

    printf("In Accept() socket: %d, client address: %d\n", sockfd, client->sa_family);
    /*
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));

    memset(SYN_packet->data, 0, sizeof(SYN_packet->data));
    */
    while(1){
        printf("Accepting...\n");
        int byte_count = recvfrom(sockfd, buf, DATALEN, 0, client, socklen);
        printf("byte_count: %d\n", byte_count);

        printf("data: %s", buf);
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
