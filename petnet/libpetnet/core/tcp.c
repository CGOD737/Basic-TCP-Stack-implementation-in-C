/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>
#include <petlib/pet_ringbuffer.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

extern int petnet_errno;



struct tcp_state {
    struct tcp_con_map * con_map;
};


static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}
static inline uint32_t 
__get_payload_len(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload_len;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return -1;
    }

}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}
//private method to calculate checksum
static uint16_t 
__calculate_chksum(struct tcp_connection * con,
                   struct ipv4_addr    * remote_addr,
                   struct packet       * pkt)
{
    struct ipv4_pseudo_hdr hdr;
    uint16_t checksum = 0;

    memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

    ipv4_addr_to_octets(con->ipv4_tuple.local_ip,  hdr.src_ip);
    ipv4_addr_to_octets(remote_addr,                    hdr.dst_ip);

    hdr.proto  = IPV4_PROTO_TCP;
    hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);
    checksum = calculate_checksum_continue(checksum, pkt->payload,     pkt->payload_len     / 2);
    /* 
     * If there is an odd number of data bytes we have to include a 0-byte after the the last byte 
     */
    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);

        checksum = calculate_checksum_finalize(checksum, &tmp, 1);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }

    return checksum;
}

/*Private method that is called by tcp_send specifically. This method is responsible for sending actual data within the packet
along with the ACK'd header. */
int
__send_data_pkt(struct tcp_connection * con)
{
  //Variable Intialization
  struct tcp_raw_hdr    * tcp_hdr     = NULL;
  struct packet         * pkt         = NULL;

  uint32_t len;
  int recv_win;

  uint32_t data_capacity = petnet_state->device_mtu - (sizeof(struct eth_raw_hdr) + ipv4_expected_hdr_len() + sizeof(struct tcp_raw_hdr));

  //returns amount of data waiting in the socket's send_buffer
  len = pet_socket_send_capacity(con->sock);
  
  if (con== NULL) {
    pet_socket_error(con->sock, EAGAIN);
      goto err;
  }
  //checks if length is greater than the data capacity
  if (len > data_capacity) {
    pet_socket_error(con->sock, EMSGSIZE);
    goto err;
  }

  //calculates the recieve window.
  if ( pet_socket_recv_capacity(con->sock) > 65535 ){
    recv_win = 65535;
  }
  else {
    recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
  }
  //packet/header creation
  pkt = create_empty_packet();
  tcp_hdr = __make_tcp_hdr(pkt, 0);

  tcp_hdr->src_port   = htons(con->ipv4_tuple.local_port);
  tcp_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
  tcp_hdr->seq_num    = htonl(con->last_ack_num);
  tcp_hdr->ack_num    = htonl(con->last_seq_num + 1);
  tcp_hdr->flags.ACK  = 1;
  tcp_hdr->header_len = 5;
  tcp_hdr->checksum   = 0;
  tcp_hdr->recv_win   = recv_win;
  //sets the packet payload toa a preallocated amount of space and essentially creates the packet
  pkt->payload_len = len;
  pkt->payload = pet_malloc(len);
  //writes the data from the sock->send_buf into the pkt->payload
  if ( pet_socket_sending_data(con->sock, pkt->payload, pkt->payload_len) != 0 )
    goto err;

  tcp_hdr->checksum = __calculate_chksum(con,con->ipv4_tuple.remote_ip, pkt);
  ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);

  pet_printf("Successfully sent TCP packet with buffered data.\n");

  return 0;

    err:
       log_error("Failed to Send Data Packet\n");
        return -1; 
}

/*Private Method that sends a SYN when called.*/
static void 
__send_SYN(struct tcp_connection * con, uint16_t local_port, uint16_t remote_port, struct socket * sock){
  //variable intialization
  struct packet * pkt;
  struct tcp_raw_hdr    * header     = NULL;
  int recv_win;
 //creates packet/tcp header for sending the intial SYN to the server
  pkt    = create_empty_packet();
  header = __make_tcp_hdr(pkt, 0);
  //designates the recv window
  if ( pet_socket_recv_capacity(sock) > 65535 ){
    recv_win = 65535;
  }
  else {
    recv_win = 65535 - pet_socket_recv_capacity(sock); 
  }
  //header field designation
  header->src_port   = htons(local_port);
  header->dst_port   = htons(remote_port);
  header->seq_num    = htonl(0);
  header->flags.SYN  = 1;
  header->recv_win   = recv_win;
  header->header_len = 5;

  //actually sends the TCP Header
  header->checksum   = __calculate_chksum(con, con->ipv4_tuple.remote_ip, pkt);
  print_tcp_header(header);
  ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);
}


/*Private method for Sending a FIN response*/
static void 
__send_FIN(struct tcp_connection * con){
  //variable intialization
  struct packet * pkt;
  struct tcp_raw_hdr    * header     = NULL;
  int recv_win;
 //creates packet/tcp header for sending the intial SYN to the server
  pkt    = create_empty_packet();
  header = __make_tcp_hdr(pkt, 0);
  //designates the recv window
  if ( pet_socket_recv_capacity(con->sock) > 65535 ){
    recv_win = 65535;
  }
  else {
    recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
  }
  //header field designation
  header->src_port   = htons(con->ipv4_tuple.local_port);
  header->dst_port   = htons(con->ipv4_tuple.remote_port);
  //header->seq_num    = last_ack_num;
  //header->ack_num    = last_seq_num + sizeof(recv_win);
  header->flags.FIN  = 1;
  header->recv_win   = recv_win;
  header->header_len = 5;

  //actually sends the TCP Header
  header->checksum   = __calculate_chksum(con, con->ipv4_tuple.remote_ip, pkt);
  ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);

  //print TCP header for error checking
  print_tcp_header(header);

  con->con_state = SYN_SENT;
}
/*Pretty much passes in a sock, creates a new connection from that socket and the local_addr and local_port values
on an empty connection. It then adds the sock passed in to the new connection created which represents the listening
connection. Then on success it returns 0.*/
int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{   
  struct tcp_state      * tcp_state   = petnet_state->tcp_state;
  struct tcp_connection * con         = NULL;

  //creates the connection from the tcp_connection call create_ipv4_tcp_con
  con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, ipv4_addr_from_str("0.0.0.0") , local_port, 0 );
    
  if (con == NULL) {
    pet_socket_error(sock, EINVAL);
    goto err;
  }
  //adds the socket to the tcp_connection
  add_sock_to_tcp_con(tcp_state->con_map, con, sock);
  con->con_state = LISTEN;

  con->stop = 0;
      
  put_and_unlock_tcp_con(con);

  pet_printf("Successfully set up listening \n");

  return 0;

  //error handling
  err:
    log_error("Failed to Connect\n");
    if (con) put_and_unlock_tcp_con(con);
      return -1;   
}
/*Beginning of an Active Connection. Starts a Three Way by sending a SYN, then expecting a SYN-ACK response 
from the server followed by sending an ACK back to the client. Once that is done, the socket layer will be notified
that a connection has occured. */
int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
  //variable intilization for connection
  struct tcp_state      * tcp_state   = petnet_state->tcp_state;
  struct tcp_connection * con         = create_ipv4_tcp_con(tcp_state->con_map, ipv4_addr_from_str("192.168.201.12"), ipv4_addr_from_str("192.168.201.1") , local_port, remote_port );

  //error checking
  if ( con == NULL){
    pet_socket_error(sock, EAGAIN);
    goto err;
  }

  add_sock_to_tcp_con(tcp_state->con_map, con, sock);
  
  __send_SYN(con, local_port, remote_port, sock);

  con->con_state = SYN_SENT;
  con->stop = 0;
  
  put_and_unlock_tcp_con(con);
  return 0;

  //error handeling
  err:
    log_error("Failed to Establish TCP Connect\n");
    if (con) put_and_unlock_tcp_con(con);  
    return -1;   
}




/* This method is for sending any data over an established connection.
Any method however can call the private __send_data_pkt in which case,
that will be used for the three-way handshake when intializing a connection
and eventually the closing call method */
int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state   = petnet_state->tcp_state;
    struct tcp_connection * con         = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    //checks if the connection state is established

    if ( con->stop ){
      log_error("Waiting for an ACK response\n");
      goto err;
    }

    if (con->con_state != ESTABLISHED){
        log_error("TCP connection is not established\n");
        goto err;
    }

    if (__send_data_pkt(con) == -1) 
      goto err;

    put_and_unlock_tcp_con(con);

    return 0;

err:
    if (con) put_and_unlock_tcp_con(con);   
    return -1;
}




/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
  //gets the connection from the tcp_state using the socket
  struct tcp_state      * tcp_state   = petnet_state->tcp_state;
  struct tcp_connection * con         = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

  pet_printf("Closing TCP Connection");

  if (con == NULL){
    log_error("Cannot Close TCP connection that doesn't exist");
    goto err;
  }
  //sends the FIN response to 
  __send_FIN(con);

  con->con_state = FIN_WAIT1;
  put_and_unlock_tcp_con(con);

  return 0;
err:
  if (con) put_and_unlock_tcp_con(con);
  return -1;

}


/*Private method that deals with the pkt recieving for an ipv4 packet.
This function takes the data from the transport layer and passes it to socket layer
and then sets the ACK NUMBER in the TCP header*/
static int 
__tcp_pkt_rx_ipv4(struct packet * pkt)
{
  struct tcp_state * tcp_state = petnet_state->tcp_state;
  struct tcp_connection * con;
  //struct tcp_connection * new_con = NULL;
  struct tcp_connection * listen_con = NULL;
  struct ipv4_raw_hdr * ipv4_hdr  = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
  struct tcp_raw_hdr * tcp_hdr = NULL;
  struct tcp_raw_hdr * send_tcp_hdr = NULL;
  struct packet * send_pkt;
  //void * payload = NULL;
  struct socket * new_sock;

  struct ipv4_addr * src_ip = NULL;
  struct ipv4_addr * dst_ip = NULL;

  int ret = 0;
  int len;
  int recv_win;

  /// pet_printf("Entering rx2\n");
  tcp_hdr = __get_tcp_hdr(pkt);

  if (petnet_state->debug_enable) {
    pet_printf("Received TCP data\n");
    print_tcp_header(tcp_hdr);
  }

  //tcp_hdr->ack_num = last_seq_num + sizeof(struct packet);

  src_ip = ipv4_addr_from_octets(ipv4_hdr->src_ip);
  dst_ip = ipv4_addr_from_octets(ipv4_hdr->dst_ip);

  //if we recieve a SYN from the client, that means they want to connect to the server
  if (tcp_hdr->flags.SYN == 1 && tcp_hdr->flags.ACK == 0) {

    print_tcp_header(tcp_hdr);

    con = create_ipv4_tcp_con(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
    //gets the listening socket.
    listen_con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, ipv4_addr_from_str("0.0.0.0") , ntohs(tcp_hdr->dst_port), 0);
    
    new_sock = pet_socket_accepted(listen_con->sock, src_ip ,ntohs(tcp_hdr->src_port));

    put_and_unlock_tcp_con(listen_con);

    add_sock_to_tcp_con(tcp_state->con_map, con, new_sock);

    send_pkt = create_empty_packet();
    send_tcp_hdr = __make_tcp_hdr(send_pkt, 0);
    //designates the recv window
    if ( pet_socket_recv_capacity(con->sock) > 65535 ){
      recv_win = 65535;
    }
    else{
      recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
    }

    recv_win = 65535;

    len = sizeof(struct tcp_raw_hdr);
    // pet_printf("Seg Check\n");
    send_pkt->payload_len = len;
    send_pkt->payload = pet_malloc(len);

    send_tcp_hdr->src_port   = htons(con->ipv4_tuple.local_port);
    send_tcp_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
    send_tcp_hdr->seq_num    = htonl(1);
    send_tcp_hdr->ack_num    = htonl(ntohl(tcp_hdr->seq_num) + 1);
    send_tcp_hdr->header_len = 5;
    send_tcp_hdr->flags.SYN  = 1;
    send_tcp_hdr->flags.ACK  = 1;
    send_tcp_hdr->recv_win = recv_win;
  // pet_printf("Seg Check\n");
  //since we are only sending header, len = header_len;

    print_tcp_header(send_tcp_hdr);
    send_tcp_hdr->checksum = __calculate_chksum(con, con->ipv4_tuple.remote_ip, send_pkt);
    ipv4_pkt_tx(send_pkt, src_ip);

    con->con_state = SYN_RCVD;

    con->last_seq_num = ntohl(tcp_hdr->seq_num);
    con->last_ack_num = ntohl(tcp_hdr->ack_num);

    put_and_unlock_tcp_con(con);

  }
  //if a SYN-ACK is recieved from the server.
  else if ( tcp_hdr->flags.SYN && tcp_hdr->flags.ACK ){
  //creates packet/tcp header for sending the intial SYN to the server

    pet_printf("Recieved a SYN-ACK\n");

    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,  dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));

    send_pkt   = create_empty_packet();
    send_tcp_hdr = __make_tcp_hdr(send_pkt, 0);
      //designates the recv window
    if ( pet_socket_recv_capacity(con->sock) > 65535 ){
      recv_win = 65535;
    }
    else {
      recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
    }
    //header field designation
    send_tcp_hdr->src_port   = htons(con->ipv4_tuple.local_port);
    send_tcp_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
    send_tcp_hdr->seq_num    = htonl(1);
    send_tcp_hdr->ack_num    = htonl(ntohl(tcp_hdr->seq_num) + 1);
    send_tcp_hdr->flags.ACK  = 1;
    send_tcp_hdr->recv_win   = recv_win;
    send_tcp_hdr->header_len = 5;

    send_tcp_hdr->checksum = __calculate_chksum(con, con->ipv4_tuple.remote_ip, send_pkt);
    print_tcp_header(send_tcp_hdr);
    ipv4_pkt_tx(send_pkt, src_ip);

    //states connection variables 
    con->con_state    = ESTABLISHED;
    con->last_seq_num = ntohl(tcp_hdr->seq_num);
    con->last_ack_num = ntohl(tcp_hdr->ack_num);

    //signals the socket layer that a connection has been Established
    pet_socket_connected(con->sock);

    put_and_unlock_tcp_con(con);

      //    __send_ACK(con, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port), last_seq_num, last_ack_num);
  }
  //if a FIN-ACK is recieved
  else if ( tcp_hdr->flags.FIN && tcp_hdr->flags.ACK ){
  //creates packet/tcp header for sending the intial SYN to the server
    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,  dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
    if ( con == NULL ){
      //log_error("Connection Doesn't Exist");
      goto out;
    }

    send_pkt   = create_empty_packet();
    send_tcp_hdr = __make_tcp_hdr(send_pkt, 0);
      //designates the recv window
    // if ( pet_socket_recv_capacity(con->sock) > 65535 ){
    //   recv_win = 65535;
    // }
    // else {
    //   recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
    // }
    //header field designation
    send_tcp_hdr->src_port   = htons(con->ipv4_tuple.local_port);
    send_tcp_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
    send_tcp_hdr->seq_num    = htonl(1);;
    send_tcp_hdr->ack_num    = htonl(ntohl(tcp_hdr->seq_num) + 1);
    send_tcp_hdr->flags.ACK  = 1;
    send_tcp_hdr->recv_win   = 65535;
    send_tcp_hdr->header_len = 5;

    print_tcp_header(send_tcp_hdr);
    ipv4_pkt_tx(send_pkt, src_ip);

    //states connection variables 
    con->con_state = TIME_WAIT;

    con->last_seq_num = ntohl(tcp_hdr->seq_num);
    con->last_ack_num = ntohl(tcp_hdr->ack_num);

    put_and_unlock_tcp_con(con);
    //signals the socket layer that a connection has been Established
 }
 //Here if the application only recieves a FIN from the source, here we have to deal with a few different states.
 else if ( tcp_hdr->flags.FIN ){
  //creates packet/tcp header for sending the intial SYN to the server

    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));

    send_pkt   = create_empty_packet();
    send_tcp_hdr = __make_tcp_hdr(send_pkt, sizeof(struct packet));
      //designates the recv window
    if ( pet_socket_recv_capacity(con->sock) > 65535 ){
      recv_win = 65535;
    }
    else {
      recv_win = 65535 - pet_socket_recv_capacity(con->sock); 
    }
    //header field designation
    send_tcp_hdr->src_port   = htons(con->ipv4_tuple.local_port);
    send_tcp_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
    send_tcp_hdr->seq_num    = htonl(1);
    send_tcp_hdr->ack_num    = htonl(ntohl(tcp_hdr->seq_num) + 1);
    send_tcp_hdr->flags.ACK  = 1;
    send_tcp_hdr->recv_win   = recv_win;
    send_tcp_hdr->header_len = 5;

    send_tcp_hdr->checksum = __calculate_chksum(con, con->ipv4_tuple.remote_ip, send_pkt);
    print_tcp_header(send_tcp_hdr);
    ipv4_pkt_tx(send_pkt, src_ip);

    //states connection variables 
    if ( con->con_state == ESTABLISHED){
      con->con_state = CLOSE_WAIT;
    }
    else if ( con->con_state == FIN_WAIT1 ){
      con->con_state = CLOSING;
    }
    else if ( con->con_state == FIN_WAIT2 ){
      con->con_state = TIME_WAIT;
    }
    con->last_seq_num = ntohl(tcp_hdr->seq_num);
    con->last_ack_num = ntohl(tcp_hdr->ack_num);
 }
  else if ( tcp_hdr->flags.ACK && tcp_hdr->flags.PSH ){
    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
 //if the state is established, then that means there's data coming.
  if ( con->con_state == ESTABLISHED){

    con->stop = 0;

    ret = pet_socket_received_data(con->sock,  __get_payload(pkt), (size_t) __get_payload_len(pkt));

    if (ret == -1) {
      log_error("Failed to receive data\n");
      goto out;
    }
  }
  else if ( con->con_state == SYN_RCVD){ 
    pet_printf("Now Entering Established State");
    con->con_state = ESTABLISHED;
  }
  put_and_unlock_tcp_con(con);
  }
 //Anytime an ACK is recieved adjust the state of the connection
 else if ( tcp_hdr->flags.ACK ){
  //if the connection is in SYN_RCVD then the connection is established.
  con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));

  //if the state is established, then that means there's data coming.
  if ( con->con_state == ESTABLISHED){

    con->stop = 0;

    ret = pet_socket_received_data(con->sock,  __get_payload(pkt), (size_t) __get_payload_len(pkt));

    if (ret == -1) {
      log_error("Failed to receive data\n");
      goto out;
    }
  }
  else if ( con->con_state == SYN_RCVD){ 
    pet_printf("Now Entering Established State");
    con->con_state = ESTABLISHED;

  }
  put_and_unlock_tcp_con(con);
 }
  return 0;

  out:
    if (con) put_and_unlock_tcp_con(con);
    return -1; 
  }

/*This function is a check before calling the private recieve pkt method
on whether layer 3 is an ipv4 packet. We can't handle ipv6 at this time as
this stack only implements ipv4. Therefore, it returns an error if any other
pkt type is passed. */
int
tcp_pkt_rx(struct packet * pkt)
{

  if (pkt->layer_3_type == IPV4_PKT) {
    
    pet_printf("%d", pkt->buf);
    // Handle IPV4 Packet
    return __tcp_pkt_rx_ipv4(pkt);

  }
  return -1;
}

//intializes the tcp_state
int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));
    state->con_map  = create_tcp_con_map();
    petnet_state->tcp_state = state;
    return 0;
}