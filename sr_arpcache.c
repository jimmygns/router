#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpreq *arp_request = sr->cache.requests;
    while(arp_request){
        handle_arpreq(sr, arp_request);
        arp_request = arp_request->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


/* This file defines an ARP cache, which is made of two structures: an ARP
   request queue, and ARP cache entries. The ARP request queue holds data about
   an outgoing ARP cache request and the packets that are waiting on a reply
   to that ARP cache request. The ARP cache entries hold IP->MAC mappings and
   are timed out every SR_ARPCACHE_TO seconds.

   Pseudocode for use of these structures follows.

   --

   # When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)

   --

   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:

   function handle_arpreq(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

   --

   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --

   To meet the guidelines in the assignment (ARP requests are sent every second
   until we send 5 ARP requests, then we send ICMP host unreachable back to
   all packets waiting on this ARP request), you must fill out the following
   function that is called every second and is defined in sr_arpcache.c:

   void sr_arpcache_sweepreqs(struct sr_instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
   }

   Since handle_arpreq as defined in the comments above could destroy your
   current request, make sure to save the next pointer before calling
   handle_arpreq when traversing through the ARP requests linked list.
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq * arp_request){
    time_t now = time(NULL);
    if(difftime(now, arp_request->sent) >= 1.0){
        if(arp_request->times_sent >= 5){
            struct sr_packet *packet_on_the_request = arp_request->packets;
            while(packet_on_the_request){
                fprintf(stderr, "%s\n", "printing the buf in sr_packet");
                print_hdrs(packet_on_the_request->buf, packet_on_the_request->len);
                sr_print_if(sr_get_interface(sr, packet_on_the_request->iface));

                uint8_t *packet = packet_on_the_request->buf;
                sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
                

                struct sr_if* if_walker = 0;
                if_walker = sr->if_list;

                while(if_walker)
                {
                  if(memcmp(ethernet_hdr->ether_dhost, if_walker->addr, ETHER_ADDR_LEN) == 0){
                    break;
                  }
                  if_walker = if_walker->next;
                }
                if (if_walker)
                {
                    sr_print_if(if_walker);
                    send_icmp_tx(sr, packet, if_walker, if_walker->name, 1, 3);
                }
                
                packet_on_the_request = packet_on_the_request->next;
            }
            sr_arpreq_destroy(&sr->cache, arp_request);
        }
        else{
            struct sr_if *out_interface = sr_get_interface(sr, arp_request->packets->iface);

            uint8_t * arp_request_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)arp_request_packet;
            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_request_packet + sizeof(sr_ethernet_hdr_t));
            ethernet_hdr->ether_type = htons(ethertype_arp);
            memset(ethernet_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
            memcpy(ethernet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            arp_hdr->ar_pro = htons(ethertype_ip);
            arp_hdr->ar_hln = ETHER_ADDR_LEN;
            arp_hdr->ar_pln = 4;
            arp_hdr->ar_op = htons(arp_op_request);
            memcpy(arp_hdr->ar_sha, out_interface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = out_interface->ip;
            memset(arp_hdr->ar_tha, 255, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = arp_request->ip;
            sr_send_packet(sr, arp_request_packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), out_interface->name);
            arp_request->sent = now;
            arp_request->times_sent++;
        }

    }
}


void send_icmp_t3_c1(struct sr_instance* sr, uint8_t * packet, struct sr_if* router_interface){
  unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t);
  uint8_t * icmp_packet = malloc(len);
  /* creating the ethernet header */
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *new_ethernet_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  new_ethernet_hdr->ether_type = ethernet_hdr->ether_type;
  memcpy(new_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethernet_hdr->ether_shost, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
  /* creating the ip header */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_packet+sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_hl = 5;
  new_ip_hdr->ip_v = 4;
  new_ip_hdr->ip_id = htons(0);
  new_ip_hdr->ip_off = htons(0);
  new_ip_hdr->ip_src = router_interface->ip;
  new_ip_hdr->ip_dst = arp_hdr->ar_sip;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t));
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  /* creating icmp header */
  sr_icmp_t11_hdr_t *new_icmp_hdr = (sr_icmp_t11_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  new_icmp_hdr->icmp_code = 1;
  new_icmp_hdr->icmp_type = 3;
  new_icmp_hdr->unused = 0;
  memcpy(new_icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), 28);
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  fprintf(stderr, "sending icmp packet type %d, code %d on interface %s\n", 3, 1, router_interface->name);
  sr_send_packet(sr, icmp_packet, len, router_interface->name);
  free(icmp_packet);
}
                  

                  
