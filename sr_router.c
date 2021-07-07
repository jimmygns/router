/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);
  
  /* fill in code here */
  uint16_t ether_type = ethertype(packet);
  unsigned int minlength = sizeof(sr_ethernet_hdr_t);

  /* arp type 
  ***************************************/
  if(ether_type == ethertype_arp){
    fprintf(stderr, "arp received\n");
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength){
      fprintf(stderr, "arp packet too short\n");
      return;
    }
    /*getting the current interface*/
    struct sr_if* router_interface = sr_get_interface(sr, interface);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    if (router_interface==0){
      fprintf(stderr, "interface not found\n");
      return;
    }
    /* router interface*/
    sr_print_if(router_interface);
    if(router_interface->ip != arp_hdr->ar_tip){
      fprintf(stderr, "arp not destined for interface: %s\n",interface);
      return;
    } 
    unsigned short opcode = ntohs(arp_hdr->ar_op);
    if(opcode == arp_op_request){
      fprintf(stderr, "arp is a request\n");
      unsigned char* mac_addr = router_interface->addr;
      
      arp_hdr->ar_op = htons(arp_op_reply);
      
      memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = router_interface->ip;
      
      memcpy(arp_hdr->ar_sha, mac_addr, ETHER_ADDR_LEN);
      sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
      memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, mac_addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, interface);
      fprintf(stderr, "arp reply sent\n");
    }
    else if(opcode == arp_op_reply){
      fprintf(stderr, "handle arp reply\n");
      handle_arp_reply(sr, arp_hdr, router_interface);

    }
    else{
      fprintf(stderr, "unknow type of arp\n");
      return;
    }
  }

  /* ip type 
  ***************************************/
  else if (ether_type == ethertype_ip)
  {
    fprintf(stderr, "ip packet received\n");
    handle_ip_packet(sr, packet, len, interface, minlength);
  }
  else{
    fprintf(stderr, "unknow type of packet\n");
    return;
  }

}/* end sr_ForwardPacket */

void handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* router_interface){
  struct sr_arpreq* arp_request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
  if (arp_request){
    struct sr_packet * packet = arp_request->packets;
    while(packet){
      uint8_t * outgoing_packet = packet->buf;
      sr_ethernet_hdr_t* outgoing_ethernet_hdr = (sr_ethernet_hdr_t*)(outgoing_packet);
      sr_ip_hdr_t* outgoing_ip_hdr = (sr_ip_hdr_t*)(outgoing_packet+sizeof(sr_ethernet_hdr_t));
      memcpy(outgoing_ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(outgoing_ethernet_hdr->ether_shost, router_interface->addr, ETHER_ADDR_LEN);
      outgoing_ip_hdr->ip_sum = 0;
      outgoing_ip_hdr->ip_sum = cksum(outgoing_ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, outgoing_packet, packet->len, router_interface->name);
      packet = packet->next;
    }
    sr_arpreq_destroy(&sr->cache, arp_request);
  }

}

void handle_ip_packet(struct sr_instance* sr, 
                      uint8_t * packet/* lent */, 
                      unsigned int len, char* interface/* lent */, 
                      unsigned int minlength)
{
  minlength += sizeof(sr_ip_hdr_t);
  if (len < minlength){
    fprintf(stderr, "ip packet too short\n");
    return;
  }
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  if(ip_hdr->ip_v!=4){
    fprintf(stderr, "ip version not 4\n");
    return;
  }
  if (ip_hdr->ip_hl<5)
  {
    fprintf(stderr, "ip header too short\n");
    return;
  }

  uint16_t check_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (check_sum != 0xffff)
  {
    fprintf(stderr, "check sum fail\n");
    return;
  }

  struct sr_if* router_interface = 0;
  if(sr->if_list == 0){
        fprintf(stderr, " Interface list empty \n");
        return;
  }
  router_interface = sr->if_list;

  while(router_interface)
  {
    if(router_interface->ip == ip_hdr->ip_dst){ 
      break;
    }
    router_interface = router_interface->next;
  }
  int is_destined_to_router = 1;
  if (router_interface == 0)
  {
    fprintf(stderr, "ip is not on the router\n");
    is_destined_to_router = 0;
    router_interface = sr_get_interface(sr, interface);
  }

  if(is_destined_to_router == 0){
    if (ip_hdr->ip_ttl<=1){
      fprintf(stderr, "ip packet timeout\n");
      send_icmp_tx(sr, packet, router_interface, interface, 0, 11);
    }
    else{
      fprintf(stderr, "forwarding ip packet\n");
      handle_ip_fowarding(sr, packet, router_interface, len);
    }
  }
  else{
    fprintf(stderr, "ip packet is for router\n");
    uint16_t protocol = ip_hdr->ip_p;
    if (protocol == ip_protocol_icmp) { 
      /* ICMP */
      fprintf(stderr, "ip packet is icmp\n");
      sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if(icmp_hdr->icmp_type != 8){
        fprintf(stderr, "It is not a ICMP type 8 Packet\n");
        return;
      }else{
        fprintf(stderr, "type 8 Packet received\n");
        sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
        uint8_t *temp_ether_dhost = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(temp_ether_dhost, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
        memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet_hdr->ether_shost, temp_ether_dhost, ETHER_ADDR_LEN);
        free(temp_ether_dhost);
        uint32_t temp_ip_src = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = temp_ip_src;
        icmp_hdr->icmp_type=0;
        icmp_hdr->icmp_sum=cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
        fprintf(stderr, "sending off the icmp reply type 0\n");
        sr_send_packet(sr, packet, len, interface);
      }
      
    }
    else{
      fprintf(stderr, "ip packet is not an icmp, sending off icmp reply type 3 code 3\n");
      send_icmp_tx(sr, packet, router_interface, interface, 3, 3);
    }
  }
}

void send_icmp_tx(struct sr_instance* sr, uint8_t * packet, 
                  struct sr_if* router_interface, char* interface, uint8_t code, uint8_t type)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t);
  uint8_t * icmp_packet = malloc(len);
  /* creating the ethernet header */
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *new_ethernet_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  new_ethernet_hdr->ether_type = ethernet_hdr->ether_type;
  memcpy(new_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethernet_hdr->ether_shost, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
  /* creating the ip header */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_packet+sizeof(sr_ethernet_hdr_t));
  memcpy(new_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
  new_ip_hdr->ip_src = router_interface->ip;
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t));
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  /* creating icmp header */
  sr_icmp_t11_hdr_t *new_icmp_hdr = (sr_icmp_t11_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  new_icmp_hdr->icmp_code = code;
  new_icmp_hdr->icmp_type = type;
  new_icmp_hdr->unused = 0;
  memcpy(new_icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), 28);
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  fprintf(stderr, "sending icmp packet type %d, code %d on interface %s\n", type, code, interface);
  sr_send_packet(sr, icmp_packet, len, interface);
  free(icmp_packet);
}

void handle_ip_fowarding(struct sr_instance* sr, uint8_t * packet, 
                  struct sr_if* router_interface, unsigned int len)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  struct sr_rt * routing_table = sr->routing_table;
  unsigned long lpm = 0;
  
  struct sr_rt * routing_entry = 0;
  while(routing_table)
  {
    /* Longest prefix match */
    if((routing_table->mask.s_addr & ip_hdr->ip_dst) == (routing_table->dest.s_addr & routing_table->mask.s_addr)
      && routing_table->mask.s_addr>lpm)
    {
      lpm = routing_table->mask.s_addr;
      routing_entry = routing_table;
    }
    routing_table = routing_table->next;
  }

  if (!routing_entry)
  {
    fprintf(stderr, "rtable no match is found\n");
    send_icmp_tx(sr, packet, router_interface, router_interface->name, 0, 3);
  }
  else{
    fprintf(stderr, "rstable entry is found\n");
    struct sr_if* new_interface = sr_get_interface(sr, routing_entry->interface);
    create_arp_request(sr, packet, new_interface, routing_entry, len);
  }
}

void create_arp_request(struct sr_instance* sr, uint8_t * packet, 
                  struct sr_if* new_interface, struct sr_rt* routing_entry, unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  struct sr_arpentry * arp_entry = sr_arpcache_lookup(&(sr->cache), routing_entry->gw.s_addr);
  if (!arp_entry)
  {
    fprintf(stderr, "arp is not in the cache\n");
    struct sr_arpreq * request = sr_arpcache_queuereq(&sr->cache, routing_entry->gw.s_addr, packet, len, new_interface->name);
    handle_arpreq(sr, request);
  }
  else{
    fprintf(stderr, "arp is in the cache\n");
    sr_ethernet_hdr_t * ethernet_hdr = (sr_ethernet_hdr_t *) packet;
    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, new_interface->name);
  }
}

