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
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <math.h>
#include <errno.h>

#include "../include/dnsmeter.h"


DNSSenderThread::DNSSenderThread()
{
	buffer=(unsigned char*)malloc(4096);
	if (!buffer) throw ppl7::OutOfMemoryException();
	runtime=10;
	timeout=5;
	queryrate=0;
	counter_packets_send=0;
	counter_bytes_send=0;
	errors=0;
	counter_0bytes=0;
	duration=0.0;
	for (int i=0;i < 255;i++) counter_errorcodes[i]=0;
	verbose=true;
	spoofingEnabled=false;
	DnssecRate=0;
	dnsseccounter=0;
	payload=NULL;
	spoofing_net_start=0;
	spoofing_net_size=0;
	payloadIsPcap=false;
	spoofingFromPcap=false;
}


DNSSenderThread::~DNSSenderThread()
{
	free(buffer);
}



void DNSSenderThread::setDestination(const ppl7::IPAddress& ip, int port)
{
	Socket.setDestination(ip, port);
	pkt.setDestination(ip, port);
}


void DNSSenderThread::setPayload(PayloadFile& payload)
{
	this->payload=&payload;
	this->payloadIsPcap=payload.isPcap();
}


void DNSSenderThread::setRuntime(int seconds)
{
	runtime=seconds;
}


void DNSSenderThread::setTimeout(int seconds)
{
	timeout=seconds;
}

void DNSSenderThread::setDNSSECRate(int rate)
{
	DnssecRate=rate;
}


void DNSSenderThread::setQueryRate(uint64_t qps)
{
	queryrate=qps;
}


void DNSSenderThread::setSourceIP(const ppl7::IPAddress& ip)
{
	sourceip=ip;
	spoofingEnabled=false;
}

void DNSSenderThread::setSourceNet(const ppl7::IPNetwork& net)
{
	sourcenet=net;
	spoofingEnabled=true;
	spoofing_net_start=ntohl(*(in_addr_t*)net.first().addr());
	spoofing_net_size=powl(2, 32 - net.prefixlen());
}

void DNSSenderThread::setSourcePcap()
{
	spoofingEnabled=true;
	spoofingFromPcap=true;
}

void DNSSenderThread::setVerbose(bool verbose)
{
	this->verbose=verbose;
}


#define PCAP_HEADER_SIZE 14+sizeof(struct ip)+sizeof(struct udphdr)

void DNSSenderThread::sendPacket()
{
	size_t query_size;
	while (1) {
		try {
			const ppl7::ByteArrayPtr& bap=payload->getQuery();
			query_size=bap.size();
			if (payloadIsPcap) {
				query_size-=PCAP_HEADER_SIZE;
				memcpy(buffer, ((const char*)bap.ptr()) + PCAP_HEADER_SIZE, query_size);
			} else {
				memcpy(buffer, bap.ptr(), query_size);
				dnsseccounter+=DnssecRate;
				if (dnsseccounter >= 100) {
					query_size=AddDnssecToQuery(buffer, 4096, query_size);
					dnsseccounter-=100;
				}
			}
			pkt.setPayload(buffer, query_size);
			if (spoofingEnabled) {
				if (spoofingFromPcap) {
					pkt.useSourceFromPcap((const char*)bap.ptr(), bap.size());
				} else {
					pkt.randomSourceIP(spoofing_net_start, spoofing_net_size);
					pkt.randomSourcePort();
				}
			}
			pkt.setDnsId(getQueryTimestamp());
			ssize_t n=Socket.send(pkt);
			if (n > 0 && (size_t)n == pkt.size()) {
				counter_packets_send++;
				counter_bytes_send+=pkt.size();
			} else if (n < 0) {
				if (errno < 255) counter_errorcodes[errno]++;
				errors++;
			} else {
				counter_0bytes++;
			}
			return;
		}
		catch (const UnknownRRType& exp) {
		}
		catch (const InvalidDNSQuery& exp) {
		}
	}
}




void DNSSenderThread::run()
{
	if (!payload) throw ppl7::NullPointerException("payload not set!");
	if (!spoofingEnabled) {
		pkt.setSource(sourceip, 0x4567);
	}
	dnsseccounter=0;
	counter_packets_send=0;
	counter_bytes_send=0;
	counter_0bytes=0;
	errors=0;
	duration=0.0;
	for (int i=0;i < 255;i++) counter_errorcodes[i]=0;

	ppl7::ppl_time_t sync_start=ppl7::GetTime();
	while (ppl7::GetTime() == sync_start) ppl7::MSleep(1);

	double start=ppl7::GetMicrotime();
	if (queryrate > 0) {
		runWithRateLimit();
	} else {
		runWithoutRateLimit();
	}
	duration=ppl7::GetMicrotime() - start;
	waitForTimeout();
}



void DNSSenderThread::runWithoutRateLimit()
{
	double start=ppl7::GetMicrotime();
	double end=start + (double)runtime;
	double now;
	int pc=0;
	while (1) {
		sendPacket();
		pc++;
		if (pc > 10000) {
			pc=0;
			if (this->threadShouldStop()) break;
			now=ppl7::GetMicrotime();
			if (now > end) break;
		}
	}
}

static inline double getNsec()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

void DNSSenderThread::runWithRateLimit()
{
	struct timespec ts;
	double Timeslice=1.0f / queryrate;
	if (Timeslice < 0.002f) Timeslice=0.002f;
	//Timeslice=0.01;

	uint64_t total_timeslices=round((double)runtime / Timeslice);
	uint64_t timeslices_per_second=(uint64_t)round((1.0f / Timeslice));
	uint64_t queries_rest=runtime * queryrate;
	ppl7::SockAddr addr=Socket.getSockAddr();
	//verbose=true;
	if (verbose) {
		printf("runtime: %d s, timeslice: %0.4f s, total: %lu, per second: %lu, Qpts: %lu, Target: %s:%d\n",
			runtime, Timeslice, total_timeslices, timeslices_per_second,
			queries_rest / total_timeslices,
			(const char*)addr.toIPAddress().toString(), addr.port());
	}
	double now=getNsec();
	double next_timeslice=now;
	double next_checktime=now + 0.1;

	double start=ppl7::GetMicrotime();
	double end=start + (double)runtime;
	double total_idle=0.0;

	for (int zr=0;zr < runtime;zr++) {
		uint64_t queries_per_second_rest=queryrate;
		for (uint64_t z=0;z < timeslices_per_second;z++) {
			next_timeslice+=Timeslice;
			uint64_t timeslices_rest=timeslices_per_second - z;
			uint64_t queries_per_timeslice=queries_per_second_rest / timeslices_rest;
			if (timeslices_rest == 1) {
				if (queries_per_second_rest != queries_per_timeslice) {
					printf("Adjusting qpt from %lu to %lu for last slice!\n", queries_per_timeslice, queries_per_second_rest);
					queries_per_timeslice=queries_per_second_rest;
				}
			}
			//printf ("zr=%d, z=%llu, ts rest=%llu, qpts=%llu, qps_rest=%llu, now=%0.8f\n",
			//		zr, z,timeslices_rest,queries_per_timeslice,queries_per_second_rest,now);
			for (uint64_t i=0;i < queries_per_timeslice;i++) {
				sendPacket();
			}
			queries_per_second_rest-=queries_per_timeslice;
			while ((now=getNsec()) < next_timeslice) {
				if (now < next_timeslice) {
					total_idle+=next_timeslice - now;
					ts.tv_sec=0;
					ts.tv_nsec=(next_timeslice - now) * 1000000000;
					//printf("nanosleep???\n");
					nanosleep(&ts, NULL);
				}
			}
			if (now > next_checktime) {
				next_checktime=now + 0.1;
				if (this->threadShouldStop()) return;
				if (ppl7::GetMicrotime() >= end) return;
			}
		}
	}
}


void DNSSenderThread::waitForTimeout()
{
	double start=ppl7::GetMicrotime();
	double end=start + (double)timeout;
	double now, next_checktime=start + 0.1;
	while ((now=ppl7::GetMicrotime()) < end) {
		if (now > next_checktime) {
			next_checktime=now + 0.1;
			if (this->threadShouldStop()) break;
		}
		ppl7::MSleep(10);
	}
}

uint64_t DNSSenderThread::getPacketsSend() const
{
	return counter_packets_send;
}

uint64_t DNSSenderThread::getBytesSend() const
{
	return counter_bytes_send;
}

uint64_t DNSSenderThread::getErrors() const
{
	return errors;
}

uint64_t DNSSenderThread::getCounter0Bytes() const
{
	return counter_0bytes;
}

uint64_t DNSSenderThread::getCounterErrorCode(int err) const
{
	if (err < 255) return counter_errorcodes[err];
	return 0;
}

double DNSSenderThread::getDuration() const
{
	return duration;
}
