/****************************************************************************************
 *   Copyright (C) 2005 by UNINETT A/S                                     
 *   info@uninett.no                                                       
 *                                                                         
 *   This program is free software; you can redistribute it and/or modify  
 *   it under the terms of the GNU General Public License as published by  
 *   the Free Software Foundation; either version 2 of the License, or     
 *   (at your option) any later version.                                   
 *                                                                         
 *   This program is distributed in the hope that it will be useful,       
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         
 *   GNU General Public License for more details.                          
 *                                                                         
 *   You should have received a copy of the GNU General Public License     
 *   along with this program; if not, write to the                         
 *   Free Software Foundation, Inc.,                                       
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             
 *
 *
 *
 *                    M P I N G . H
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * IPv4 support based partly on ping.c from Mike Muus, U. S. Army Ballistic
 * Research Lab, with various modifications.
 *
 * IPv6 support based partly on ping/ping6 from the UNIX iputils package and
 * ping/ping6 from BSD-ping.
 *
 * Notes -
 *      This program has to be setuid or run as ROOT to access ICMP sockets on
 *      most UNIX systems. This does not apply to Darwin 8.1.X (Mac OSX Tiger).
 *
 * Tested on:
 *      GNU/Linux 2.4.X/2.6.X
 *      NetBSD 1.X / FreeBSD 4.X
 *      Darwin 8.1.X (Mac OSX Tiger)
 *
 ****************************************************************************************/

/* Expose BSD/glibc networking types consistently on Linux and macOS */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <signal.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Linux netinet/ip_icmp.h uses ICMP_FRAG_NEEDED; BSD uses ICMP_UNREACH_NEEDFRAG */
#if defined(__linux__) && defined(ICMP_FRAG_NEEDED) && !defined(ICMP_UNREACH_NEEDFRAG)
#define ICMP_UNREACH_NEEDFRAG ICMP_FRAG_NEEDED
#endif

#include <net/if.h>
#include <arpa/inet.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <sys/time.h>
#include <sys/select.h>

#define MAXWAIT         10              /* max time to wait for response, sec. */
#define MAXPACKET       (65536-60-8)    /* max packet size */



/* Various options */
int options;
#define F_VERBOSE          0x001         /* verbose flag */
#define F_QUIET            0x002         /* quiet flag */
#define F_PACKED           0x004         /* packed output flag */
#define F_SO_DONTROUTE     0x008         /* record route flag */
#define F_NUMERIC          0x010         /* don't look up ip-numbers */
#define F_PERCENTILE       0x020         /* use percentile and not min/avg/max */
#define F_MEDIAN           0x040         /* use median instead of avg */
#define F_NROUTES          0x080         /* number of record route slots */
#define F_IPV4             0x100         /* Prefer IPv4 adress on DNS resolve */
#define F_IPV6             0x200         /* Prefer IPv6 adress on DNS resolve */
#define F_ARPCACHEPREFIRE  0x400         /* Send 1 packet to each host to update ARPCache*/
#define F_POISSON_BURST    0x800        /* Create 1 hour reports instead of normal behaviour */
#define F_POISSON_PACKET   0x1000        /* Create 1 hour reports instead of normal behaviour */
#define F_TIMESTAMP_BURST  0x2000        /* Timestamp each packetburst sent */
#define F_TIMESTAMP_PACKET 0x4000        /* Timestamp each packetburst sent */
#define F_TTL              0x8000       /* Time-to-live */
#define F_KERNEL_STAMP     0x10000       /* Let kernel timestamp packets */

/* Per-target argv/file labels (%254s); must not use undersized OS MAXHOSTNAMELEN */
#define MPING_HOST_LABEL_LEN 256

#define MAXHOSTS 500
#define MAXCOUNT 65535



/* functions */
static void finish(int dummy);
static void catcher(int dummy);
static void prefire(int dummy);               /* Prefire class for updating ARPCache */
static void pinger(int hostnum);
static void pinger6(int hostnum);

static void pr_pack(u_char *buf, int cc, struct sockaddr_in *from, int ttl_cmsg,
    const struct timeval *recv_kern_tv);
static void pr_pack6(u_char *buf, int cc, struct sockaddr_in6 *from, int hops,
    const struct timeval *recv_kern_tv);
static void pr_icmph(struct icmp *icp);
static void pr_icmph6(struct icmp6_hdr *icp6);
static void pr_retip(struct ip *ip);
static void pr_iph(struct icmp *icp, int cc);
static void tvsub(register struct timeval *out, register struct timeval *in);

static u_short in_cksum(const u_short *addr, int len);

static int read_nodefile(char *nodefile, char **nodebuf);

void poissonsleep(float pmean, int truncval);
void prettydate(char *buffer, size_t buffsize); 

char *pr_addr(const void *sa);

int compare(const void*, const void*);
long int calculate_n_percentile(int *arr, int arr_len, int n);
static long llsqrt(long long a);



/* struct */
struct hostent *hp;                             /* Pointer to host info */
struct timezone tz;                             /* leftover */
struct timeval it;                              /* struct to hold processing time */

struct sockaddr_storage whereto[MAXHOSTS];      /* Who to ping */
struct sockaddr_in *to;
struct sockaddr_in6 *to6;
struct addrinfo hints, *res;

