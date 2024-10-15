/*
 * This file is part of dnsmeter by Patrick Fedick <fedick@denic.de>
 *
 * Copyright (c) 2019 DENIC eG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <ppl7.h>
#include <ppl7-inet.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifndef __FreeBSD__
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <math.h>


#include "../include/dnsmeter.h"

#define USZ sizeof(struct udphdr)
#define ISZ sizeof(struct ip)
#define HDRSZ ISZ+USZ
#define MAXPACKETSIZE 4096

static unsigned short in_cksum(unsigned short* addr, int len)
{
	int nleft  = len;
	unsigned short* w = addr;
	int sum    = 0;
	unsigned short answer = 0;
	while (nleft > 1) {
		sum   += *w++;
		nleft -=  2;
	}
	if (nleft == 1) {
		//*(unsigned char*)(&answer) = *(unsigned char*)w;
		//sum += answer;
		sum+=*(unsigned char*)w;
	}
	sum  = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// Structure for IP pseudo-header (for IPv4)
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};



static unsigned short udp_cksum(const struct ip* iphdr, const struct udphdr* udp, const unsigned char* payload, size_t payload_size)
{
	unsigned char cbuf[MAXPACKETSIZE];
	memset(cbuf, 0, sizeof(cbuf));
	pseudo_header *psh=(pseudo_header*)cbuf;
	psh->src_addr=iphdr->ip_src.s_addr;
	psh->dest_addr=iphdr->ip_dst.s_addr;
	psh->placeholder=0;
	psh->protocol=iphdr->ip_p;
	psh->udp_length=udp->uh_ulen;
	memcpy(cbuf+sizeof(pseudo_header),udp,sizeof(struct udphdr));
	memcpy(cbuf+sizeof(pseudo_header)+sizeof(struct udphdr),payload,payload_size);
	return in_cksum((unsigned short*)cbuf, sizeof(pseudo_header) + sizeof(struct udphdr) + payload_size);
}







Packet::Packet()
{
	buffersize=MAXPACKETSIZE;
	payload_size=0;
	buffer=(unsigned char*)calloc(1, buffersize);
	if (!buffer) throw ppl7::OutOfMemoryException();

	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);

	iphdr->ip_hl  = ISZ >> 2;
	iphdr->ip_v   = IPVERSION;
	iphdr->ip_tos = 0;
	iphdr->ip_off = 0;
	iphdr->ip_ttl = 64;
	iphdr->ip_p   = IPPROTO_UDP;
	iphdr->ip_sum = 0;
	iphdr->ip_id  = 0;
	iphdr->ip_src.s_addr = 0;
	iphdr->ip_dst.s_addr = 0;
	iphdr->ip_len=htons(HDRSZ + payload_size);
	iphdr->ip_sum = 0;

	udp->uh_ulen=htons(USZ + payload_size);
}

Packet::~Packet()
{
	free(buffer);
}

void Packet::setSource(const ppl7::IPAddress& ip_addr, int port)
{
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_src.s_addr = *(in_addr_t*)ip_addr.addr();
	udp->uh_sport=htons(port);
}

void Packet::randomSourcePort()
{
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	udp->uh_sport=htons(ppl7::rand(1024, 65535));
}

void Packet::randomSourceIP(const ppl7::IPNetwork& net)
{
	struct ip* iphdr = (struct ip*)buffer;
	in_addr_t start=ntohl(*(in_addr_t*)net.first().addr());
	size_t size=powl(2, 32 - net.prefixlen());
	iphdr->ip_src.s_addr = htonl(ppl7::rand(start, start + size - 1));
}

void Packet::randomSourceIP(unsigned int start, unsigned int size)
{
	struct ip* iphdr = (struct ip*)buffer;
	iphdr->ip_src.s_addr = htonl(ppl7::rand(start, start + size - 1));
}


void Packet::useSourceFromPcap(const char* pkt, size_t size)
{
	const struct ip* s_iphdr = (const struct ip*)(pkt + 14);
	const struct udphdr* s_udp = (const struct udphdr*)(pkt + 14 + sizeof(struct ip));
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_src.s_addr=s_iphdr->ip_src.s_addr;
	udp->uh_sport=s_udp->uh_sport;
}

void Packet::setDestination(const ppl7::IPAddress& ip_addr, int port)
{
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_dst.s_addr = *(in_addr_t*)ip_addr.addr();
	udp->uh_dport=htons(port);
}

void Packet::setIpId(unsigned short id)
{
	struct ip* iphdr = (struct ip*)buffer;
	iphdr->ip_id  = htons(id);
}

void Packet::setDnsId(unsigned short id)
{
	*((unsigned short*)(buffer + HDRSZ))=htons(id);
}

void Packet::setPayload(const void* payload, size_t size)
{
	if (size + HDRSZ > MAXPACKETSIZE) throw BufferOverflow("%zd > %zd", size, MAXPACKETSIZE - HDRSZ);
	memcpy(buffer + HDRSZ, payload, size);
	payload_size=size;
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_len=htons(HDRSZ + payload_size);
	udp->uh_ulen=htons(USZ + payload_size);
}

void Packet::setPayloadDNSQuery(const ppl7::String& query, bool dnssec)
{
	payload_size=MakeQuery(query, buffer + HDRSZ, buffersize - HDRSZ, dnssec);
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_len=htons(HDRSZ + payload_size);
	udp->uh_ulen=htons(USZ + payload_size);
}

void Packet::updateChecksums()
{
	struct ip* iphdr = (struct ip*)buffer;
	struct udphdr* udp = (struct udphdr*)(buffer + ISZ);
	iphdr->ip_sum = 0;
	iphdr->ip_sum = in_cksum((unsigned short*)iphdr, ISZ);
	udp->uh_sum=0;
	udp->uh_sum=udp_cksum(iphdr, udp, buffer + HDRSZ, payload_size);
}

size_t Packet::size() const
{
	return HDRSZ + payload_size;
}

unsigned char* Packet::ptr()
{
	updateChecksums();
	return buffer;
}
