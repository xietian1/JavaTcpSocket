// raw_sock.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> 
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

#define DATAGRAM_LEN 65535
#define OPT_SIZE 0

unsigned short checksum(const char *buf, unsigned size)
{
  unsigned sum = 0, i;

  /* Accumulate checksum */
  for (i = 0; i < size - 1; i += 2)
  {
    unsigned short word16 = *(unsigned short *)&buf[i];
    sum += word16;
  }

  /* Handle odd-sized case */
  if (size & 1)
  {
    unsigned short word16 = (unsigned char)buf[i];
    sum += word16;
  }

  /* Fold to get the ones-complement result */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  /* Invert to get the negative in ones-complement arithmetic */
  return ~sum;
}

void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst, int32_t seq, int32_t ack_seq, char *data, int data_len, char **out_packet, int *out_packet_len)
{
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // set payload
  char *payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  memcpy(payload, data, data_len);

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 5+OPT_SIZE/4; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(65535); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE + data_len);

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}
void create_zero_packet(struct sockaddr_in *src, struct sockaddr_in *dst, int32_t seq, int32_t ack_seq, char *data, int data_len, char **out_packet, int *out_packet_len)
{
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // set payload
  char *payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  memcpy(payload, data, data_len);

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 5+OPT_SIZE/4; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = 0; // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE + data_len);

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst, int32_t seq, int32_t ack_seq, char **out_packet, int *out_packet_len)
{
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 5+OPT_SIZE/4; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(65535); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_syn_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst, int32_t seq, int32_t ack_seq, char **out_packet, int *out_packet_len)
{
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 5+OPT_SIZE/4; // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(65535); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(1380); // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // // ---- enable SACK ----
  // datagram[44] = 0x04;
  // datagram[45] = 0x02;

  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));

  // pseudogram[36] = 0x04;
  // pseudogram[37] = 0x02;

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack)
{
  // read sequence number
  uint32_t seq_num;
  memcpy(&seq_num, packet + 24, 4);
  // read acknowledgement number
  uint32_t ack_num;
  memcpy(&ack_num, packet + 28, 4);
  // convert network to host byte order
  *seq = ntohl(seq_num);
  *ack = ntohl(ack_num);

  printf("sequence number: %lu\n", (unsigned long)*seq);
  printf("acknowledgement number: %lu\n", (unsigned long)*seq);
}

//Input should start from ip layer, not ETH layer
void read_payload_len_backup(const char *packet, unsigned long *payload_len)
{
  //Get ip header length
  struct iphdr *ip = (struct iphdr*)(packet);
  struct tcphdr *tcp = (struct tcphdr*)(packet + ip->ihl*4);
  
  //printf("***Total Length: %d bytes\n", ntohs(ip->tot_len));
  //printf("Internet Header Length: %d bytes\n", ((unsigned int)(ip->ihl))*4);
  //printf("***TCP: %d bytes\n", ((unsigned int)(tcp->doff))*4);
  
  *payload_len = ntohs(ip->tot_len) - ((unsigned int)(ip->ihl))*4 - ((unsigned int)(tcp->doff))*4;
  //printf("Payload: %ld bytes\n", (unsigned long)(*payload_len));
  //unsigned short iphdrlen;
  //iphdrlen = ip->ihl*4;
  
  //Get tcp header length
  
}

unsigned long read_payload_len(const char *packet)
{
  //Get ip header length
  struct iphdr *ip = (struct iphdr*)(packet);
  struct tcphdr *tcp = (struct tcphdr*)(packet + ip->ihl*4);
  
  return ntohs(ip->tot_len) - ((unsigned int)(ip->ihl))*4 - ((unsigned int)(tcp->doff))*4;
}

int receive_from(int sock, char *buffer, size_t buffer_length, struct sockaddr_in *dst)
{

  unsigned short dst_port;
  int received;
  do
  {
    received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
    if (received < 0)
      break;
    memcpy(&dst_port, buffer + 22, sizeof(dst_port));
  } while (dst_port != dst->sin_port);
  printf("received bytes: %d\n", received);
  printf("destination port: %d\n", ntohs(dst->sin_port));

  return received;
}



void main()
{
  // Structs that contain source IP addresses
  struct sockaddr_in source_socket_address, dest_socket_address;

  int packet_size;

  // // Allocate string buffer to hold incoming packet data
  // unsigned char *buffer = (unsigned char *)malloc(65536);
  // Open the raw socket

  int sendbuff;
  socklen_t optlen;

  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock == -1)
  {
    //socket creation failed, may be because of non-root privileges
    perror("Failed to create socket");
    exit(1);
  }

  //configure server ip
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(6981);
  if (inet_pton(AF_INET, "192.168.1.30", &saddr.sin_addr) != 1)
  {
    printf("server IP configuration failed\n");
    return ;
  }

  int one = 1;
  const int *val = &one;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
  {
    printf("setsockopt(IP_HDRINCL, 1) failed\n");
    return ;
  }

  // Get buffer size
 optlen = sizeof(sendbuff);
 int res = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

 if(res == -1)
     printf("Error getsockopt one");
 else
     printf("send buffer size = %d\n", sendbuff);


  //**************TCP Handshake


  char recvbuf[DATAGRAM_LEN];
  int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
  if (received <= 0)
  {
    printf("receive_from() failed\n");
  }
  else
  {
    printf("successfully received %d bytes first SYN!\n", received);
  }

  //configure client ip
  unsigned short src_port;
  memcpy(&src_port, recvbuf + 20, sizeof(src_port));
  unsigned int src_addr;
  memcpy(&src_addr, recvbuf + 12, sizeof(src_addr));

  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = src_port;
  daddr.sin_addr.s_addr = src_addr;
  printf("client addr: %s, port: %d\n", inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));

  // read sequence number to acknowledge in next packet
  uint32_t seq_num, ack_num;
  read_seq_and_ack(recvbuf, &seq_num, &ack_num);
  int new_seq_num = seq_num + 1;


  // send SYN ACK
  char *packet;
  int packet_len;
  create_syn_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);

  usleep(10000);
   
  int sent;
  if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
  {
    printf("sendto() failed\n");
  }
  else
  {
    printf("successfully sent %d bytes SYN_ACK!\n", sent);
  }
  
  
  unsigned long received_byte = 0;
  unsigned long sent_byte = 0;
  bool received10KB = false;
  
  while(1){
    if(received10KB){
        break;
    }
    bzero(recvbuf, DATAGRAM_LEN);
    int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
    if (received < 0)
      {
        perror("receive_from() failed. Disconnted\n");
        exit(1);
      }
      else
      {
        unsigned long payload_len;
        //read_payload_len(recvbuf, &payload_len);
        payload_len = read_payload_len(recvbuf);
        received_byte += payload_len;
        if(received_byte >= 10000){
          received10KB = true;
        }

        if (payload_len > 0){
          read_seq_and_ack(recvbuf, &seq_num, &ack_num);
          int new_seq_num = seq_num + payload_len;
          char *packet;
          int packet_len;
          create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
          usleep(10000);
          int sent;
          if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
          {
            perror("sendto() failed\n");
            exit(1);
          }
          else
          {
            printf("****successfully sent %d bytes ACK!\n", sent);
          }
        } 

      }
  }


  char request[]="oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYF";

  //send 10kb
  if(received10KB){
      printf("****Start send 10KB bytes\n");
      create_data_packet(&saddr, &daddr, ack_num, new_seq_num, request, strlen(request), &packet, &packet_len);
      int sent;
          if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
          {
            perror("sendto() failed\n");
            exit(1);
          }
      sent_byte += strlen(request); 


      while(sent_byte < 10000){
          //bzero(recvbuf, DATAGRAM_LEN);
          int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
          if (received < 0)
            {
              perror("receive_from() failed. Disconnted\n");
              exit(1);
            }
          read_seq_and_ack(recvbuf, &seq_num, &ack_num);
          //int new_seq_num = seq_num + 1;

          create_data_packet(&saddr, &daddr, ack_num, new_seq_num, request, strlen(request), &packet, &packet_len);
          usleep(1000);
          int sent;
          if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
          {
            perror("sendto() failed\n");
            exit(1);
          }
          sent_byte += strlen(request); 

      }

      printf("Finished sending 10KB bytes\n");
  }




  //do nothing when recv handshake last ack
  //while(!(received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr)));

  //5000 bytes
  //char request[] = "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";
  //1300
  //char request[] ="oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugmjgSiUPKhcP0r8ieFRL7nVgaOYGMdbFWKE90LHAiKCEP13HcLPf4j4Vx57gjfp2K5hv08PfRBMRcAI593C6fMwJJiPdKnNEGWIf75hOTFxsmiL62DNZJqhKPyngubQOJ1apjr9nQyU6brOPjRgZFDg1GXb2zr3T0XcK3ArxfAKgqiXFCciO5OUMuRiac2Ui3NYJphboJBhotV0qmL5HZx3lB42QDkXieGg9tnaXMhbf3eNEzpDuKoD2C3jWJwpujfHoOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugoOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugmjgSiUPKhcP0r8ieFRL7nVgaOYGMdbFWKE90LHAiKCEP13HcLPf4j4Vx57gjfp2K5hv08PfRBMRcAI593C6fMwJJiPdKnNEGWIf75hOTFxsmiL62DNZJqhKPyngubQOJ1apjr9nQyU6brOPjRgZFDg1GXb2zr3T0XcK3ArxfAKgqiXFCciO5OUMuRiac2Ui3NYJphboJBhotV0qmL5HZx3lBZFDg1GXb2zr3T0XcK3ArxfAKgqiXFCciO5OUMuRiac2Ui3NYJphboJBhotV0qmL5HZx3lBboJBhotV0qmL5HZx3lB5HZx5HZx5HZ";  
  //500 bytes
  //char request[] = "oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugmjgSiUPKhcP0r8ieFRL7nVgaOYGMdbFWKE90LHAiKCEP13HcLPf4j4Vx57gjfp2K5hv08PfRBMRcAI593C6fMwJJiPdKnNEGWIf75hOTFxsmiL62DNZJqhKPyngubQOJ1apjr9nQyU6brOPjRgZFDg1GXb2zr3T0XcK3ArxfAKgqiXFCciO5OUMuRiac2Ui3NYJphboJBhotV0qmL5HZx3lB42QDkXieGg9tnaXMhbf3eNEzpDuKoD2C3jWJwpujfH";
  //400
  //char request[] ="oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugmjgSiUPKhcP0r8ieFRL7nVgaOYGMdbFWKE90LHAiKCEP13HcLPf4j4Vx57gjfp2K5hv08PfRBMRcAI593C6fMwJJiPdKnNEGWIf75hOTFxsmiL62DNZJqhKPyngubQOJ1apjr9nQyU6brOPjRgZFDg1GXb2zr3";
  //300
  //char request[]= "oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYFvCRhEy90mrSbJZOQa2CEXyPmOWjn0EZyv5j2VV9lugmjgSiUPKhcP0r8ieFRL7nVgaOYGMdbFWKE90LHAiKCEP13HcLPf4j4Vx57";
  //200
  //char request[]="oOVbDU1v62Ddb8yhlfh9f0GzjO4xY7QGxRX0LH3vjEjGuspHOZLZuRfa1OaPb3xKi6uCvvXrHSzge7oX7kKKLDPSiHW598pvtsh1hn4x47sIe0uCGiC8gAr586vkm7I07g9IclEEGnj0KqDvln7KT44CbN1MBMq9WhfCm56Y8R2Ci07eE5m1zJ7PzaPhJ5EgyuUwYIYF";
  //char request[] = "oo";


   //esstienal
   //read_seq_and_ack(recvbuf, &seq_num, &ack_num);
 
  //for 1st send&recv 
  // for (int i = 1; i < 100; ++i){
  
  //   new_seq_num = seq_num;
  //   create_data_packet(&saddr, &daddr, ack_num, new_seq_num, request, strlen(request), &packet, &packet_len);   
  //   if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
  //   {
  //     printf("send failed\n");
  //   }

  //   ack_num += 200;   
  //   usleep(1000000); //1s
  // }

  
  
  
  
  // //for 2nd probing
  // printf("Please press ENTER to start sleep phase\n"); 
  // getchar();
  // printf("sleep phase Started\n");

  // int sleep[5];
  // sleep[0]=15;
  // sleep[1]=30;
  // sleep[2]=60;
  // sleep[3]=180;
  // sleep[4]=300;

  // for (int i = 0; i < 6; i++){
    
  //   new_seq_num = seq_num + 50;
  //   ack_num -= 1; 
  //   create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
  //   if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
  //   {
  //     printf("send failed\n");
  //   }
  //     usleep(sleep[i]*1000000);  
  // }

}
