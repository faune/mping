/**********************************************************************************
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
 *                    M P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
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
 **********************************************************************************/

#include "mping.h"

/* Definition of variables */
u_char *packet;
u_char *outpack; /* ICMP send buffer; heap avoids huge .bss / ld alignment warning on macOS */
int packlen;
int i;

int s = -1;                                     /* Socket IPv4 file descriptor */
int s6 = -1;                                    /* Socket IPv6 file descriptor */

int af = AF_UNSPEC;                             /* Adress family to be determined */

int error;
int datalen;                                    /* How much data */

char hostname[MAXHOSTS][MPING_HOST_LABEL_LEN];
char hostnameresolv[MAXHOSTS][MPING_HOST_LABEL_LEN];
char hnamebuf[MPING_HOST_LABEL_LEN];

int nhosts = 0;                         /* number of hosts on command line */
int npackets;                           /* number of packets to send to each host. */
int wtime = 2;                          /* time (ms) to wait after last packet sent */
int deadline = 0;                       /* timeout in seconds before mping exits regardless of packets sent */
int preload = 0;                        /* number of packets to "preload" */
int ntransmitted=0;                     /* sequence # for outbound packets = #sent */
int idle;                               /* How long, in %, should mping try to
                                           idle during hourreport */
int interval = 100;                     /* interval between packets (msec)
                                           Default: 10 packets/sec */
int ident;
int ttl;

long nreceived[MAXHOSTS];               /* # of packets we got back */
long nsent[MAXHOSTS];                    /* successful echo requests per host (for loss %) */
int nactive = 0;                        /* Number of hosts that we're still pinging. */
int active[MAXHOSTS];                   /* Array of flags */
int timing = 0;
int chnum = 0;
long tmin[MAXHOSTS];
long tmax[MAXHOSTS];
long long tsum[MAXHOSTS];                  /* sum of all times, for doing average */
long long sqsum[MAXHOSTS];                 /* square sum of all times, */
int *packet_time[MAXHOSTS];
long tmax_tot = 0;
int finishing = 0;                      /* bool finish alarm is set - false each time new pkt alarm is set */
float pmean;
int truncval;
char date[64];

int alloc_count;                        /* Number of packets we allocate space for
                                           for recording statistics */

#define RESOLVE_RETRY_SEC 30
static int pending_resolve[MAXHOSTS];
static time_t resolve_next_try[MAXHOSTS];

static int apply_addrinfo_to_slot(int slot, struct addrinfo *rai);
static void try_resolve_host(int slot);
static ssize_t recv_raw_icmp(int fd, int is_v6, unsigned char *buf, size_t buflen,
    struct sockaddr_storage *from, socklen_t *fromlen, int *ttlorhop,
    struct timeval *kern_ts);
static int copy_hostname_slot(int slot, const char *src);

/* Usage string printed at program call with no argument specified */
char usage[] =
"\n"
"Usage:\t  mping  [-rln46ktTqvSmfV] [-c count] [-i interval] [-s packetsize] [-w deadline]\n"
"\t\t [-W waittime] [-e ttl] [-p/-P -a mean -b truncated] [-F hostfile] host1 host2...\n"
"\n"
"Packet options: \n"
"  -r\t\t No routing.\n"
"  -c count\t Send count packets.\n"
"  -s packetsize\t Size of ICMP packet MTU payload.\n"
"  -l\t\t Pre-fire 1 packet to each host before starting.\n"
"  \t\t to collect statistics. Prevents ARP-cache influence.\n"
"\n"
"DNS options:\n"
"  -n\t\t Numeric output only. No attempt will be made to\n"
"\t\t lookup symbolic names for host addresses.\n"
"  -4\t\t Prefer IPv4 adress on multiple DNS hits.\n"
"  -6\t\t Prefer IPv6 adress on multiple DNS hits.\n"
"\n"
"Timing options:\n"
"  -k\t\t Let the kernel timestamp packets.\n"
"  -t\t\t Timestamp each burst sent.\n"
"  -T\t\t Timestamp each packet sent.\n"
"  -i interval\t msec between each packet sent (default is 100).\n"
"  -w deadline\t Specify a timeout, in seconds, before Mping exits.\n"
"  -W waittime\t Time to wait for stray packets after last sent.\n"
"  -e ttl\t Set the IP Time To Live for outgoing packets.\n"
"\n"
"Statistics and information:\n"
"  -q\t\t Quiet output. \n"
"  -v\t\t Verbose output.\n"
"  -S\t\t Show data in shorter style.\n"
"  -p\t\t Poisson distribute each burst sent.\n"
"  -P\t\t Poisson distribute each packet sent.\n"
"  -a mean\t Set the mean value for the Poisson distribution.\n"
"  -b truncated\t Set the truncated value for the Poisson distribution.\n"
"  -m\t\t Print min/avg/max/stddev/median.\n"
"  -f\t\t Print 10-percentile/median/90-percentile/stddev.\n"
"  -V\t\t Show version info and exit.\n"
"\n"
"Host options: \n"
"  -F hostlist\t Read list of hosts from file.\n"
"\n";

/* Display version info when invoked with the -V switch */
char version[] =
"\n"
"Mping v3.00 rc1 build 2005-09-16\n"
"Developed by Uninett (http://www.uninett.no) 1996-2005\n"
"All rights reserved\n"
"\n"
"See 'man mping' for more information\n"
"\n";






/*
 *                    M A I N
 */


int main(int argc, char **argv)
{
        struct sockaddr_storage from;
        
        char **av = NULL;
	extern char *optarg;

	char *nodefile = NULL;
	int nodecount = 0;
	static char *nodebuf[MAXHOSTS];
        int i,ch;
                
        datalen = 64 - 8;
	
	/* Determine which options are set at command line, and set neccesary flags */
	//while ((ch = getopt(argc, argv, "i:rvqSpPa:b:nmflktTe:c:w:W:s:V46F:")) != EOF) {
	while ((ch = getopt(argc, argv, "rc:s:ln46ktTi:w:W:e:qvSpPa:b:mfVF:")) != EOF) {
		switch(ch) {
			/* Packet options */
		case 'r':
			options |= F_SO_DONTROUTE;
			break;
		case 'c':
			npackets = atoi(optarg);
			if (npackets <= 0) {
				fprintf(stderr, "ping: bad number of packets to transmit.\n");
				exit(2);
			}
			if (npackets > MAXCOUNT) {
				fprintf(stderr, "Mping: count exceeds maximum %d.\n", MAXCOUNT);
				exit(2);
			}
			break;
		case 's':
			datalen = atoi(optarg);
			if (datalen < 0) {
				fprintf(stderr, "Mping: illegal negative packet size %d.\n", datalen);
				exit(2);
			}
			if (datalen > MAXPACKET) {
				fprintf(stderr, "Mping: packet size too large. Max packet size is %d data bytes.\n", MAXPACKET);
				exit(2);
			}
			if (datalen < (int)sizeof(int)) {
				fprintf(stderr, "Mping: packet size too small. Need at least %d data bytes.\n", (int)sizeof(int));
				exit(2);
			}
			break;
		case 'l':
			options |= F_ARPCACHEPREFIRE;
			break;

			/* DNS options */
		case 'n':
			options |= F_NUMERIC;
			break;
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;

			/* Timing options */
		case 'k':
			options |= F_KERNEL_STAMP;
			break;
		case 't':
			options |= F_TIMESTAMP_BURST;
			break;
		case 'T':
			options |= F_TIMESTAMP_PACKET;
			break;
		case 'i':
			interval = atoi(optarg);
			if (interval < 0) {
				fprintf(stderr, "Mping: bad timing interval.\n");
				exit(2);
			}
			break;
		case 'w':
			deadline = atoi(optarg);
			if (deadline < 0) {
				fprintf(stderr, "Mping: bad deadline.\n");
				exit(2);
			}
			break;
		case 'W':
			wtime = atoi(optarg);
			if (wtime < 0) {
				fprintf(stderr, "Mping: bad wait interval.\n");
				exit(2);
			}
			break;
		case 'e':
			ttl = atoi(optarg);
			if (ttl < 0 || ttl > 255) {
				fprintf(stderr, "Mping: ttl %u out of range\n", ttl);
				exit(2);
			}
			options |= F_TTL;
			break;

			/* Statistics and information */
		case 'q':
			options |= F_QUIET;
			break;
		case 'v':
			options |= F_VERBOSE;
			break;
		case 'S':
			options |= F_PACKED;
			break;
		case 'p':
			options |= F_POISSON_BURST;
			break;
		case 'P':
			options |= F_POISSON_PACKET;
			break;
		case 'a':
			pmean = atoi(optarg);
			if (pmean < 0) {
				fprintf(stderr, "Mping: Poisson mean value %0.3f out of range.\n", pmean);
				exit(2);
			}
			break;
		case 'b':
			truncval = atoi(optarg);
			if (truncval < 0) {
				fprintf(stderr, "Mping: Poisson truncated value %i out of range.\n", truncval);
				exit(2);
			}
			break;
		case 'm':
			options |= F_MEDIAN;
			break;
		case 'f':
			options |= F_PERCENTILE;
			break;
		case 'V':
			fputs(version, stdout);
			exit(0);
			break;

			/* Host options*/
		case 'F':
			nodefile = optarg;
			nodecount = read_nodefile(nodefile, nodebuf);
			if (nodecount == -1) {
				fprintf(stderr, "Mping: File not found.\n");
			}
			break;
		default:
			fputs(usage, stdout);
		}
	}
	argc -= optind;
	argv += optind;


	if (datalen >= (int)(sizeof(struct timeval) + sizeof(int))) {
                timing = 1;
	}
	
        /* Check memory allocation */
        packlen = datalen + 60 + 76;
	if (!(packet = (u_char *)malloc((u_int)packlen))) {
                fprintf(stderr, "Mping: Memory allocation failed. Check arguements\n");
                exit(2);
        }
	if (!(outpack = (u_char *)malloc((size_t)MAXPACKET))) {
		fprintf(stderr, "Mping: Memory allocation failed.\n");
		exit(2);
	}

        /* Display Usage for program if no arguments are given */
        if (argc == 0 && nodefile == NULL) {
                fputs(usage, stdout);
		exit(1);
        }
	
        /* ident holds process id */    
        ident = getpid() & 0xFFFF;

	/* Seed the random function with system time */
	srandom((long)time(NULL));
	
	/* Check conflicting options */
	if (((options & F_TIMESTAMP_BURST) && (options & F_TIMESTAMP_PACKET)) || ((options & F_POISSON_BURST) && (options & F_POISSON_PACKET))) {
		fprintf(stderr, "Mping: Conflicting options set.\n");
		exit(2);
	}

	/* Check for mandatory poisson options, if requested */
	if ((options & F_POISSON_BURST) || (options & F_POISSON_PACKET)) {
		if (!(pmean)) {
			fprintf(stderr, "Mping: You need to specify the desired mean value for the Poisson distribution with the -a option\n");
			exit(2);
		}
		if (!(truncval)) {
			fprintf(stderr, "Mping: You need to specify the desired maximum truncated value for the Poisson distribution with the -b option\n");
			exit(2);
		}
	}
			
	/* How long should we be kept alive? */
	if (deadline) {
		if (gettimeofday((struct timeval *)&it, NULL)) {
			perror("Mping ");
		}
		/* Set the new deadline */
		deadline = deadline+it.tv_sec;
        }

        /* 
         * Note: if mping is invoked with an IPv4 or IPv6 address, and is unable
         * to create the the corresponding raw socket - we make it fail on purpose, since
         * mping then will be unable to do what its told.
         *
         */
	
	if (nodecount > 0) {
		av   = nodebuf;
		argc = nodecount;
	} else {
		av = argv;
	}

        i = 0;
        while ((i < argc) && (nhosts < (MAXHOSTS - 1))) {
		char hostid[255];
		if (strncmp(av[i], "#", 1) == 0 || ! sscanf(av[i], "%254s", hostid)) {
			i++;
			continue;
		}
		
		
                active[nhosts] = 1;
                tmin[nhosts] = 999999999;
                tmax[nhosts] = 0;
                tsum[nhosts] = 0;
                sqsum[nhosts] = 0.0;
		alloc_count = (npackets > 0) ? npackets : MAXCOUNT;
		{
			size_t ptz = (size_t)alloc_count * sizeof(int);
			if (alloc_count != 0 && ptz / sizeof(int) != (size_t)alloc_count) {
				fprintf(stderr, "Mping: packet statistics allocation overflow.\n");
				exit(1);
			}
			if (!(packet_time[nhosts] = (int *)malloc(ptz))) {
				fprintf(stderr, "Mping: Memory allocation failed\n");
				exit(1);
			}
		}

		/* Remember to free up this memory afterwards */
		memset(packet_time[nhosts], -1, (size_t)alloc_count * sizeof(int));
		if (copy_hostname_slot(nhosts, hostid) != 0) {
			free(packet_time[nhosts]);
			packet_time[nhosts] = NULL;
			i++;
			continue;
		}
                
                bzero((char *) &whereto[nhosts], sizeof(struct sockaddr_storage));
		to = (struct sockaddr_in *) &whereto[nhosts];
		to6 = (struct sockaddr_in6 *) &whereto[nhosts];

		int trigger = -1;
	restamp:
		/* Remember to free up this memory afterwards */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = af;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_flags = AI_CANONNAME;
		/*hints.ai_protocol = IPPROTO_???;*/

		error = getaddrinfo(hostid, NULL, &hints, &res);
		if (error) {
			/* Perhaps the hostname support another protocol? */
			if (trigger == -1) {
				if (af == AF_INET) {
					af = AF_INET6;
					trigger=4;
				}
				if (af == AF_INET6) {
					af = AF_INET;
					trigger=6;
				}
				goto restamp;
			}
		        fprintf(stderr, "Mping: host %s : %s (retry every %ds)\n", hostid,
				gai_strerror(error), RESOLVE_RETRY_SEC);
			hostnameresolv[nhosts][0] = '\0';
			memset(&whereto[nhosts], 0, sizeof(whereto[nhosts]));
			pending_resolve[nhosts] = 1;
			resolve_next_try[nhosts] = 0;
			active[nhosts] = 1;
			if (!(options & F_PACKED))
				printf("PING %s: (DNS unresolved, will retry)\n", hostname[nhosts]);
			if (options & F_NUMERIC) {
				snprintf(hnamebuf, sizeof(hnamebuf), "%s", hostid);
				(void)copy_hostname_slot(nhosts, hnamebuf);
			}
			nhosts++;
			nactive++;
			i++;
			continue;
		}
		/* Lets change af back to what it originally was */
		if (trigger==4) 
			af = AF_INET;
		if (trigger==6)
			af = AF_INET6;
		

		if (apply_addrinfo_to_slot(nhosts, res) != 0) {
			freeaddrinfo(res);
			res = NULL;
			exit(1);
		}
		freeaddrinfo(res);
		res = NULL;
		pending_resolve[nhosts] = 0;

		if (!(options & F_PACKED)) {
			printf("PING %s", hostname[nhosts]);
			if (hostnameresolv[nhosts][0] != '\0')
				printf(" [%s]", hostnameresolv[nhosts]);
			printf(": %d bytes of data to %s\n", datalen,
			       pr_addr((struct sockaddr *)&whereto[nhosts]));
		}
		
		if (options & F_NUMERIC) {
			snprintf(hnamebuf, sizeof(hnamebuf), "%s", hostid);
			(void)copy_hostname_slot(nhosts, hnamebuf);
			hostnameresolv[nhosts][0] = '\0';
		}
	
		if (active[nhosts]) {
			nhosts++;
			nactive++;
		}
		i++;
		if (nhosts >= MAXHOSTS) {
			fprintf(stderr, "Max hosts reached. Skipping rest.\n");
		}
	}
	if (!(options & F_PACKED))
		putchar('\n');
	

	signal(SIGINT, finish);
	signal(SIGALRM, catcher);
	if (nhosts > 0) {
		if (options & F_ARPCACHEPREFIRE) {
			for (i=0; i < nhosts; i++) {
				prefire(i);
			}
		}
		if ((options & F_POISSON_BURST) && (options & F_VERBOSE)) {
			printf("Mping: Mean time between bursts: %.2f sec\n", pmean);
			printf("Mping: Truncated upper value between bursts: %i sec\n", truncval);
		}
		if ((options & F_POISSON_PACKET) && (options & F_VERBOSE)) {
			printf("Mping: Mean time between packets: %.2f sec\n", pmean);
			printf("Mping: Truncated upper value between packets: %i sec\n", truncval);
		}
		
		
		
		catcher(-1 /* dummy */);
	}
	else
                exit(-1);
	
	/* Lets loop! */
        for (;;) {
                socklen_t fromlen = sizeof(from);
                int cc;
                int smax;
                
                struct timeval timeout;
                fd_set read_fdset;
                
                static const time_t SELECT_TIMEOUT_SECS = 0;
                static const time_t SELECT_TIMEOUT_USECS = 10000;
                
                timeout.tv_sec = SELECT_TIMEOUT_SECS;
                timeout.tv_usec = SELECT_TIMEOUT_USECS;

                /* Initialize the select loop */
                if (s < 0 && s6 < 0) {
                        /* Deferred DNS: no raw sockets until at least one host resolves */
                        (void)usleep(50000);
                        continue;
                }
                smax = s6 > s ? s6 : s;
                if (smax >= FD_SETSIZE) {
                        perror("mping: smax > FD_SETSIZE");
                        exit(1);
                }

                FD_ZERO(&read_fdset);
                if (s >= 0)
                        FD_SET(s, &read_fdset);
                if (s6 >= 0)
                        FD_SET(s6, &read_fdset);

		/* Using select to prevent socket blocking */
		if (select(smax + 1, &read_fdset, (fd_set *)0, (fd_set *)0, NULL) < 0) {
                        if (errno != EINTR) {
                                perror("mping: select error");
                                exit(1);
                        }
			continue;
                }
                if (s >= 0) {
                        if (FD_ISSET(s, &read_fdset)) {
				int ttl_cmsg = -1;
				struct timeval kern_tv, *ktp = NULL;

				fromlen = sizeof(from);
				if ((cc = (int)recv_raw_icmp(s, 0, packet, (size_t)packlen, &from, &fromlen,
							      &ttl_cmsg, &kern_tv)) < 0) {
					if (errno != EINTR) {
						perror("mping: recvmsg");
						(void)fflush(stderr);
					}
					continue;
				}
				if ((options & F_KERNEL_STAMP))
					ktp = &kern_tv;
				if (cc > 0)
					pr_pack(packet, cc, (struct sockaddr_in *)&from, ttl_cmsg, ktp);
                        }
                }
                if (s6 >= 0) {
                        if (FD_ISSET(s6, &read_fdset)) {
				int hops = -1;
				struct timeval kern_tv, *ktp = NULL;

				fromlen = sizeof(from);
				if ((cc = (int)recv_raw_icmp(s6, 1, packet, (size_t)packlen, &from, &fromlen,
							      &hops, &kern_tv)) < 0) {
					if (errno != EINTR) {
						perror("mping: recvmsg");
						(void)fflush(stderr);
					}
					continue;
				}
				if ((options & F_KERNEL_STAMP))
					ktp = &kern_tv;
				if (cc > 0)
					pr_pack6(packet, cc, (struct sockaddr_in6 *)&from, hops, ktp);
                        }
                }
		
                /* Lets finish up and print out statistics */
		/* pinger should set finish-alarm, but if lost this is a safequard */
		if ( npackets && !finishing && ( nactive <= 0 || ntransmitted > npackets)){
			signal(SIGALRM, finish);
			alarm(wtime);
			finishing=1;
		}
        }
        /*WE REALLY SHOULDNT BE HERE :-| */

        return 0;               /* Dummy return */
}


static int
read_nodefile (char *nodefile, char **nodebuf)
{
	char linebuf[256];
	int nodecount = 0;
	FILE *fh = fopen(nodefile, "r");

	if (fh == NULL)
		return -1;

	while(fgets(linebuf,sizeof linebuf, fh) && nodecount < MAXHOSTS) {
		int llen = strlen(linebuf);
		if (linebuf[llen - 1] == '\n')
			linebuf[llen - 1] = '\0';
		nodebuf[nodecount] = strdup(linebuf);
		nodecount++;
	}
	if (!feof(fh))
		nodecount = 0;
	fclose(fh);
	return nodecount;
}

static int
copy_hostname_slot(int slot, const char *src)
{
	int n;

	if (src == NULL)
		src = "";
	n = snprintf(hostname[slot], sizeof(hostname[slot]), "%s", src);
	if (n < 0 || (size_t)n >= sizeof(hostname[slot])) {
		fprintf(stderr, "Mping: host name too long (max %zu bytes).\n",
		    sizeof(hostname[slot]) - 1);
		return -1;
	}
	return 0;
}

#define CTRL_CMSG_BUFSIZ 256

static ssize_t
recv_raw_icmp(int fd, int is_v6, unsigned char *buf, size_t buflen,
    struct sockaddr_storage *from, socklen_t *fromlen, int *ttlorhop,
    struct timeval *kern_ts)
{
	struct iovec iov;
	struct msghdr msg;
	unsigned char cmsgbuf[CTRL_CMSG_BUFSIZ];
	ssize_t cc;

	iov.iov_base = buf;
	iov.iov_len = buflen;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = from;
	msg.msg_namelen = *fromlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	*ttlorhop = -1;
	memset(kern_ts, 0, sizeof(*kern_ts));

	cc = recvmsg(fd, &msg, 0);
	if (cc < 0)
		return cc;
	*fromlen = msg.msg_namelen;

	{
		struct cmsghdr *cm;
		for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
#if defined(IP_RECVTTL)
			if (!is_v6 && cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_RECVTTL) {
				if (cm->cmsg_len >= CMSG_LEN(sizeof(unsigned char)))
					*ttlorhop = (int)*(unsigned char *)CMSG_DATA(cm);
			}
#endif
#ifdef IPV6_RECVHOPLIMIT
			if (is_v6 && cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT) {
				if (cm->cmsg_len >= CMSG_LEN(sizeof(int)))
					*ttlorhop = *(int *)CMSG_DATA(cm);
			}
#endif
			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMP) {
				if (cm->cmsg_len >= CMSG_LEN(sizeof(struct timeval)))
					memcpy(kern_ts, CMSG_DATA(cm), sizeof(struct timeval));
			}
		}
	}
	return cc;
}

static int
apply_addrinfo_to_slot(int slot, struct addrinfo *rai)
{
	int on = 1;

	if (rai->ai_family == AF_INET6) {
		if (getprotobyname("ipv6-icmp") == NULL) {
			fprintf(stderr, "IPv6-ICMP: Protocol not supported by kernel.\n");
			return -1;
		}
		if (s6 < 0) {
			s6 = socket(rai->ai_family, rai->ai_socktype, IPPROTO_ICMPV6);
			if (s6 < 0) {
				perror("Mping");
				return -1;
			}
		}
#ifdef IPV6_RECVHOPLIMIT
		{
			int hopon = 1;
			(void)setsockopt(s6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &hopon, sizeof(hopon));
		}
#endif
		if (options & F_SO_DONTROUTE)
			(void)setsockopt(s6, SOL_SOCKET, SO_DONTROUTE, (char *)&on, sizeof(on));
		if (options & F_TTL) {
			if (setsockopt(s6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) == -1) {
				perror("Mping: can't set unicast IPv6 time-to-live");
				return -1;
			}
		}
		if (options & F_KERNEL_STAMP) {
			if (setsockopt(s6, SOL_SOCKET, SO_TIMESTAMP, (char *)&on, sizeof(on)) == -1) {
				perror("Mping");
				return -1;
			}
		}
	} else if (rai->ai_family == AF_INET) {
		if (getprotobyname("icmp") == NULL) {
			fprintf(stderr, "IPv4-ICMP: Protocol not supported by kernel.\n");
			return -1;
		}
		if (s < 0) {
			s = socket(rai->ai_family, rai->ai_socktype, IPPROTO_ICMP);
			if (s < 0) {
				perror("Mping");
				return -1;
			}
		}
#if defined(IP_RECVTTL)
		{
			int rttl = 1;
			(void)setsockopt(s, IPPROTO_IP, IP_RECVTTL, &rttl, sizeof(rttl));
		}
#endif
		if (options & F_SO_DONTROUTE) {
			if (setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&on, sizeof(on)) == -1) {
				perror("Mping");
				return -1;
			}
		}
		if (options & F_TTL) {
			if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
				perror("Mping");
				return -1;
			}
		}
		if (options & F_KERNEL_STAMP) {
			if (setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, (char *)&on, sizeof(on)) == -1) {
				perror("Mping");
				return -1;
			}
		}
	} else {
		fprintf(stderr, "Mping: unknown address family\n");
		return -1;
	}

	if (rai->ai_addrlen <= 0 ||
	    rai->ai_addrlen > (socklen_t)sizeof(struct sockaddr_storage)) {
		fprintf(stderr, "Mping: invalid resolved address length.\n");
		return -1;
	}
	memcpy(&whereto[slot], rai->ai_addr, rai->ai_addrlen);
	if (rai->ai_canonname != NULL && rai->ai_canonname[0] != '\0')
		snprintf(hostnameresolv[slot], sizeof(hostnameresolv[slot]), "%s", rai->ai_canonname);
	else
		hostnameresolv[slot][0] = '\0';
	return 0;
}

static void
try_resolve_host(int slot)
{
	struct addrinfo *lres = NULL;
	struct addrinfo lhints;
	int err;
	int trigger = -1;
	time_t now;
	int saved_af = af;

	if (!pending_resolve[slot])
		return;
	now = time(NULL);
	if (now < resolve_next_try[slot])
		return;

    restry:
	memset(&lhints, 0, sizeof(lhints));
	lhints.ai_family = af;
	lhints.ai_socktype = SOCK_RAW;
	lhints.ai_flags = AI_CANONNAME;
	err = getaddrinfo(hostname[slot], NULL, &lhints, &lres);
	if (err) {
		if (trigger == -1) {
			if (af == AF_INET) {
				af = AF_INET6;
				trigger = 4;
			}
			if (af == AF_INET6) {
				af = AF_INET;
				trigger = 6;
			}
			goto restry;
		}
		af = saved_af;
		if (options & F_VERBOSE)
			fprintf(stderr, "Mping: retry %s: %s\n", hostname[slot], gai_strerror(err));
		resolve_next_try[slot] = now + (time_t)RESOLVE_RETRY_SEC;
		return;
	}
	if (trigger == 4)
		af = AF_INET;
	if (trigger == 6)
		af = AF_INET6;

	if (apply_addrinfo_to_slot(slot, lres) != 0) {
		freeaddrinfo(lres);
		af = saved_af;
		resolve_next_try[slot] = now + (time_t)RESOLVE_RETRY_SEC;
		return;
	}
	freeaddrinfo(lres);
	pending_resolve[slot] = 0;
	resolve_next_try[slot] = 0;
	if (!(options & F_PACKED))
		printf("Mping: %s resolved -> %s\n", hostname[slot],
		       pr_addr((struct sockaddr *)&whereto[slot]));
}


/*
 *                    P R E F I R E
 *
 * Prefire will send 1 packet to each host on stdin, before starting to
 * collect statistics. The idea is to update the arpcache, so the first
 * packets rtt returned is more realistic than it would normally be due
 * to arpcache.
 */
static void
prefire(int dummy)
{
	if (pending_resolve[dummy] || !active[dummy])
		return;
	if (!(options & F_QUIET)) {
		printf("\nPre-fire initiated...\n");
		printf("1 packet to host : %-15s", hostname[dummy] );
	}
	int i;
	register int cc;

	if (((struct sockaddr *) &whereto[dummy]) -> sa_family == AF_INET) {

		register struct icmp *icp = (struct icmp *) outpack;

		icp->icmp_type = ICMP_ECHO;
		cc = datalen + 8;               /* skips ICMP portion */
		
		i = sendto(s, (char *)outpack, cc, 0,
			   (struct sockaddr *) &whereto[dummy],
			   sizeof(struct sockaddr_in));
	}
	else if (((struct sockaddr *) &whereto[dummy]) -> sa_family == AF_INET6) {

		struct icmp6_hdr *icmph;

		icmph = (struct icmp6_hdr *)outpack;
		icmph->icmp6_type = ICMP6_ECHO_REQUEST;
		icmph->icmp6_data32[1] = dummy;

		if (timing) {
			gettimeofday((struct timeval *)&icmph->icmp6_data32[1],
				     (struct timezone *)NULL);
			icmph->icmp6_data32[3] = dummy;       
		}
		else {
			icmph->icmp6_data32[1] = dummy;
		}
		
		/* Should also fill in data, and we need to skip hnum value */
		cc = datalen + 8;                   /* skips ICMP portion */
		
		i = sendto(s6, (char *)outpack, cc, 0 /*confirm*/,
			   (struct sockaddr *) &whereto[dummy],
			   sizeof(struct sockaddr_in6));
	}
	else {
		/* We should never reach this state */
		fprintf(stderr, "ERROR: prefire\n");
		exit(5);
	}

	if (!(options & F_QUIET)) {
		if (i >= 0) {
			printf("\t\t [ ok ]\n");
		}
		else
			printf("\t\t [ failed ]\n");
	}
	/* Pre-fire complete */
	if (!(options & F_QUIET))
		printf("Pre-fire complete\n\n");
}



/*
 *                    C A T C H E R
 * 
 * This routine causes another PING to be transmitted, and then
 * schedules another SIGALRM for 'interval' seconds from now.
 * 
 * Bug -
 *      Our sense of time will slowly skew (ie, packets will not be launched
 *      exactly at 'interval' intervals).  This does not affect the quality
 *      of the delay and loss statistics.
 */

static void
catcher(int dummy)
{
	(void)dummy;
	int waittime;
	
        if (chnum == 0) {

		/* Check how long we have been alive. The reason we must do this here, is so we dont
		   abort a burst while it is processing, as this can lead to artificial packet loss.
		   If however, deadline is not reached - another burst with up to 500 hosts can be
		   initiated, including poisson sleep intervals. This is a little bit different from
		   how normal ping deadline works, however it is neccessary for mping, due to its
		   multihost-support - else artificial packet loss can be introduced. */
		if (deadline) {
			if (gettimeofday((struct timeval *)&it, NULL))
				perror("Mping ");
			if (deadline < it.tv_sec) {
				goto finishstamp;
			}
		}

		/* Initiate sleep per burst if poisson distribution is selected*/
		if ((options & F_POISSON_BURST) && ntransmitted > 0) {
			poissonsleep(pmean,truncval);
		}

		/* Timestamp beginning of burst */
		if (options & F_TIMESTAMP_BURST) {
			prettydate(date, sizeof(date));
			puts(date);
		}
		
		/* Lets do another round */
		ntransmitted++;
	}
	
        /* Finished hosts: no send; DNS-pending: try resolve; else ping */
        if (!active[chnum] && !pending_resolve[chnum]) {
		if ((options & F_POISSON_PACKET) && ntransmitted > 0)
			poissonsleep(pmean, truncval);
		chnum++;
	} else if (pending_resolve[chnum]) {
		if ((options & F_POISSON_PACKET) && ntransmitted > 0)
			poissonsleep(pmean, truncval);
		try_resolve_host(chnum);
		chnum++;
	} else if (((struct sockaddr *)&whereto[chnum])->sa_family == AF_INET) {
		if ((options & F_POISSON_PACKET) && ntransmitted > 0)
			poissonsleep(pmean, truncval);
		pinger(chnum++);
	} else if (((struct sockaddr *)&whereto[chnum])->sa_family == AF_INET6) {
		if ((options & F_POISSON_PACKET) && ntransmitted > 0)
			poissonsleep(pmean, truncval);
		pinger6(chnum++);
	} else {
		if ((options & F_VERBOSE))
			fprintf(stderr, "Mping: no address yet for %s\n", hostname[chnum]);
		chnum++;
	}

        if (chnum >= nhosts) {
                chnum = 0;
        }

	/* Schedule another ping, or finish up ?*/
        if ((npackets == 0) || ((ntransmitted < npackets) || (chnum != 0))) {


#ifdef NO_UALARM
                alarm(waittime);
                signal(SIGALRM, catcher);
#else
		
                signal(SIGALRM, catcher);
		//ualarm(wtime * interval, 0);

		ualarm(interval * 1000,0);
		finishing=0;
#endif

        } else {
finishstamp:
		waittime=wtime;
		signal(SIGALRM, finish);
		if ( alarm(waittime) < 0 ){
			perror("mping: alarm error");
			exit(1);
		}
        }
}

/*
 *                    P I N G E R
 * 
 * Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 *
 * The pinger entitry consists of pinger and pinger6, for IPv4 and IPv6.
 *
 */

static void
pinger(int hostnum)
{
	if (!active[hostnum])
		return;
        register struct icmp *icp = (struct icmp *) outpack;
        register int cc;
	int i;
	
        register struct timeval *tp = (struct timeval *) &outpack[8 + sizeof(int)];
        register int *hnum = (int *) &outpack[8];
        register u_char *datap = &outpack[8 + sizeof(int) + sizeof(struct timeval)];

        icp->icmp_type = ICMP_ECHO;
        icp->icmp_code = 0;
        icp->icmp_cksum = 0;
        icp->icmp_seq = ntransmitted-1;
        icp->icmp_id = ident;   /* ID */

        cc = datalen + 8;               /* skips ICMP portion */

        for (i = 8; i < datalen; i++) {/* skip 8 for time */
                *datap++ = i;
        }

        if ((npackets == 0) || (ntransmitted <= npackets)) {
                *hnum = hostnum;
                if (timing)
                        gettimeofday(tp, &tz);
                /* Compute ICMP checksum here */
                icp->icmp_cksum = 0;
                icp->icmp_cksum = in_cksum((u_short *)icp, cc);    /* */

		i = sendto(s, (char *)outpack, cc, 0,
                           (struct sockaddr *) &whereto[hostnum],
                           sizeof(struct sockaddr_in));


		if (i < 0 || i != cc)  {
			if (i < 0) {
				if (errno != EAGAIN)
					perror("Mping: sendto");
			} else {
				printf("Mping: wrote %s %d chars, ret=%d\n",
				       pr_addr(&whereto[hostnum]), cc, i);
			}
		} else
			nsent[hostnum]++;
        }
}

/*
 *                   P I N G E R 6 
 *
 * Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */

static void
pinger6(int hostnum)
{
	if (!active[hostnum])
		return;
        struct icmp6_hdr *icmph;
        register int cc;
        int i;

        icmph = (struct icmp6_hdr *)outpack;
        icmph->icmp6_type = ICMP6_ECHO_REQUEST;
        icmph->icmp6_code = 0;
        icmph->icmp6_cksum = 0;
        icmph->icmp6_seq = ntransmitted-1;
        icmph->icmp6_id = ident;
        icmph->icmp6_data32[1] = hostnum;

        if (timing) {
                gettimeofday((struct timeval *)&icmph->icmp6_data32[1],
                             (struct timezone *)NULL);
                icmph->icmp6_data32[3] = hostnum;       
        }
        else {
                icmph->icmp6_data32[1] = hostnum;
        }

        /* Should also fill in data, and we need to skip hnum value */
        cc = datalen + 8;                   /* skips ICMP portion */

	i = sendto(s6, (char *)outpack, cc, 0 /*confirm*/,
		   (struct sockaddr *) &whereto[hostnum],
		   sizeof(struct sockaddr_in6));

        if (i < 0 || i != cc)  {
                if (i < 0) {
                        if (errno != EAGAIN)
                                perror("Mping: sendto");
                } else {
                        printf("Mping: wrote %s %d chars, ret=%d\n",
                               pr_addr(&whereto[hostnum]), cc, i);
		}
	} else
		nsent[hostnum]++;
}


/*
 *                    P R _ P A C K
 *
 * Print out the IPv4 packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 *
 * pr_pack for IPv4 and pr_pack6 for IPv6
 *
 */

static void
pr_pack(u_char *buf, int cc, struct sockaddr_in *from, int ttl_cmsg,
    const struct timeval *recv_kern_tv)
{
        struct ip *ip;
        register struct icmp *icp;
        struct timeval tv;
        struct timeval *tp;
        int *hnum;
        int hlen;
	long triptime = 0;
	int display_ttl;

        if (recv_kern_tv != NULL && (options & F_KERNEL_STAMP))
                tv = *recv_kern_tv;
        else
                gettimeofday(&tv, &tz);
	
        /* Check the IP header */
        ip = (struct ip *) buf;

	if (ttl_cmsg >= 0)
		display_ttl = ttl_cmsg;
	else
		display_ttl = ip->ip_ttl;

	hlen = ip->ip_hl << 2;
        if (cc < hlen + ICMP_MINLEN) {
		if(options & F_VERBOSE)
			printf("packet too short (%d bytes) from %s\n", cc,
			       inet_ntoa(from->sin_addr));
		return;
        }
	
	

	
        cc -= hlen;
        icp = (struct icmp *)(buf + hlen);
        if (icp->icmp_type == ICMP_ECHOREPLY) {
                if (icp->icmp_id != ident) {
			if ((options & F_VERBOSE) && !(options & F_QUIET)) 
				fprintf(stderr, "Mping: received another hosts ICMP_ECHO_REPLY - dropping packet.\n");
			return;         /* This was not our ICMP ECHO reply */
		}
                hnum = (int *) &buf[hlen + 8];
		if (*hnum < 0 || *hnum >= nhosts) {
                        if (options & F_VERBOSE)
				fprintf(stderr, "Mping: bad host slot %d (nhosts=%d)\n", *hnum, nhosts);
                        return;
                }
                if ((++nreceived[*hnum] >= npackets) && npackets) {
                        nactive--;
                        active[*hnum] = 0;
                }
                if (timing) {
			/* These ifndef's needs to be changed */
#ifndef icmp_data
                        tp = (struct timeval *) &icp->icmp_ip;
#else
                        tp = (struct timeval *) &icp->icmp_data[sizeof(int)];
#endif
                        tvsub(&tv, tp);
			triptime = tv.tv_sec * 1000000 + tv.tv_usec;
			if (triptime < 0) {
                                fprintf(stderr, "Warning: time of day goes back, taking countermeasures.\n");
                                triptime = 0;
			}
			
			tsum[*hnum] += triptime;
                        sqsum[*hnum] += (long long)triptime * (long long)triptime;
			if (nreceived[*hnum] <= alloc_count)
				packet_time[*hnum][nreceived[*hnum]-1] = triptime;
			
                        if (triptime < tmin[*hnum])
                                tmin[*hnum] = triptime;
                        if (triptime > tmax[*hnum])
                                tmax[*hnum] = triptime;
                }
                if (triptime > tmax_tot)
                        tmax_tot = triptime;

                if (options & F_QUIET)
                        return;

		if (options & F_TIMESTAMP_PACKET) {
			prettydate(date, sizeof(date));
			puts(date);
		}

		if (!(options & F_PACKED)) {
			printf("%d bytes from %s icmp_seq=%d", cc,
			       pr_addr(from), icp->icmp_seq);  /* */
			if (display_ttl >= 0)
				printf(" ttl=%d", display_ttl);
		}
		else {
			printf("%s %d %d %d", pr_addr(from), cc, icp->icmp_seq, display_ttl);
		}
		
                if (timing) {
			if (!(options & F_PACKED))
				printf(" time=%ld.%03ld msec\n", triptime/1000, triptime%1000);
			else
				printf(" %ld.%03ld\n", triptime/1000, triptime%1000);
		}
		else
			putchar('\n');
				
	} else {
                /* We've got something other than an ECHOREPLY */
		if (!(options & F_QUIET) || !(options & F_PACKED)) {
			if (icp->icmp_type != ICMP_ECHO) { /* Filter out localhost */
				printf("%d bytes from %s: ", cc, pr_addr(from));
				/* Print out ICMP error message*/
				pr_icmph(icp);
				/* Print out additional header info, if verbose */ 
				if (options & F_VERBOSE)
					pr_iph(icp, cc);
			}
		}
	}
}


/*
 *                    P R _ P A C K 6
 *
 * Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive (this is only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 *
 *
 */

static void
pr_pack6(u_char *buf, int cc, struct sockaddr_in6 *from, int hops,
    const struct timeval *recv_kern_tv)
{
	struct icmp6_hdr *icmph;
        struct timeval tv;
        struct timeval *tp;
        long triptime = 0;
        int hnum;
	
	icmph = (struct icmp6_hdr *) buf;

	if (icmph->icmp6_type == ICMP6_ECHO_REPLY) {

		if (icmph->icmp6_id != ident) {
			if ((options & F_VERBOSE) && !(options & F_QUIET)) 
				fprintf(stderr, "Mping: received another hosts ICMP_ECHO_REPLY - dropping packet.\n");
			return;  /* This was not our ICMP ECHO reply */
		}

		if (cc < 8+4 || (timing && cc < (int)(8 + sizeof(struct timeval) + 4)) ) {
			if (options & F_VERBOSE)
				fprintf(stderr, "mping: packet too short (%d bytes)\n", cc);
			return;
		}

		hnum = (int)icmph->icmp6_data32[timing ? 3 : 1];
                if (hnum < 0 || hnum >= nhosts) {
                        printf("hnum=%d, outside [0..%d)\n", hnum, nhosts);
                        return;
                }

		if ((++nreceived[hnum] >= npackets) && npackets) {
			nactive--;
			active[hnum] = 0;
		}
		
		if (timing && cc >= (int)(8 + sizeof(struct timeval))) {
                        if (recv_kern_tv != NULL && (options & F_KERNEL_STAMP))
                                tv = *recv_kern_tv;
                        else
                                gettimeofday(&tv, NULL);
                        tp = (struct timeval *)(icmph + 1);

                        tvsub(&tv, tp);
                        triptime = tv.tv_sec * 1000000 + tv.tv_usec;

			if (triptime < 0) {
                                fprintf(stderr, "Warning: time of day goes back, taking countermeasures.\n");
                                triptime = 0;
			}

			tsum[hnum] += triptime;
                        sqsum[hnum] += (long long)triptime * (long long)triptime;
			if (nreceived[hnum] <= alloc_count)
				packet_time[hnum][nreceived[hnum]-1] = triptime;
                        if (triptime < tmin[hnum])
                                tmin[hnum] = triptime;
                        if (triptime > tmax[hnum])
                                tmax[hnum] = triptime;
		}

		if (triptime > tmax_tot)
			tmax_tot = triptime;
		
		if (options & F_QUIET)
			return;

		if (options & F_TIMESTAMP_PACKET) {
			prettydate(date, sizeof(date));
			puts(date);
		}
		
		if (!(options & F_PACKED)) {
			printf("%d bytes from %s icmp_seq=%u", cc,
			       pr_addr(from), icmph->icmp6_seq);
			
			if (hops >= 0)
				printf(" hops=%d", hops);
			
			if (cc < datalen+8) {
				printf(" (truncated)");
				return;
			}
		}
		else {
			printf("%s %d %u", pr_addr(from), cc, icmph->icmp6_seq);
		}

		if (timing) {
			if (!(options & F_PACKED))
				printf(" time=%ld.%03ld msec\n", triptime/1000, triptime%1000);
			else
				printf(" %ld.%03ld\n", triptime/1000, triptime%1000);
		}
		else
			putchar('\n');
		
	}else {
		/* We got something other than an ICMP6_ECHO_REPLY */
		if (!(options & F_QUIET) || !(options & F_PACKED)) {
			if (icmph->icmp6_type != ICMP6_ECHO_REQUEST) { /* Filter out localhost */
				printf("%d bytes from %s: ", cc, pr_addr(from));
				/* Print out ICMP error message*/
				pr_icmph6(icmph);
			}
		}
	}
}


/*
 *                    I N _ C K S U M
 *
 * Checksum routine for Internet Protocol V4 family headers (C Version)
 *
 */
static u_short
in_cksum(const u_short *addr, register int len)
{
        register int nleft = len;
        const u_short *w = addr;
        register int sum = 0;
        register u_short answer = 0;

        /*
         *  Our algorithm is simple, using a 32 bit accumulator (sum),
         *  we add sequential 16 bit words to it, and at the end, fold
         *  back all the carry bits from the top 16 bits into the lower
         *  16 bits.
         */
        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
		sum += htons(*(u_char *)w << 8);
        }
	
        /*
         * add back carry outs from top 16 bits to low 16 bits
         */
        sum = (sum >> 16) + (sum & 0xffff);             /* add hi 16 to low 16 */
        sum += (sum >> 16);                             /* add carry */
        answer = ~sum;                                  /* truncate to 16 bits */
        return (answer);
}


/*
 *                    I N _ C K S U M 6
 *
 * Checksum routine for Internet Protocol V6 family headers (C Version)
 *
 * NOTE: This code is deprecated, because a IPv6 compliant kernel will calculate the checksum
 *       automatically. Perhaps this will become handy some day.
 */

#if 0
static int
in_cksum6(void *pkg, int len)
{
        int tmplen = len + 36;
        uint16_t shortlen = htons ((uint16_t) len);
        /* TODO: Reuse old buffer if big enough */
        char *tmppkg = malloc (tmplen);
        int ret;
                
        /* Fill in pseudo header, starting at tmppkg */
        /*
        memcpy (tmppkg + 0, source address, 16);
        memcpy (tmppkg + 0, dest address, 16);
        */
        /* len in network byte order at offset 32 */
        memcpy (tmppkg + 32, &shortlen, 2);
        /* Pad */
        tmppkg[34] = '\0';
        /* "Next header" 58 */
        tmppkg[35] = 58;
        /* Origianl package at offset 36 */
        memcpy (tmppkg + 36, pkg, len);
        ret = in_cksum (tmppkg, tmplen);
        free (tmppkg);

        return ret;
}
#endif


/*
 *                    T V S U B
 * 
 * Subtract 2 timeval structs:  out = out - in.
 * 
 * Out is assumed to be >= in.
 */
static void
tvsub(struct timeval *out, struct timeval *in)
{
        if ((out->tv_usec -= in->tv_usec) < 0) {
                out->tv_sec--;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}

/*
 *                    F I N I S H
 *
 * Print out statistics, and give up.
 * Heavily buffered STDIO is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becomming intermingled.
 */
static void 
finish(int dummy)
{
	(void)dummy;
        int i;
	long long sqsumavg, tsumavg;
	long tsdev;
	
        fflush(stdout);

        if (!(options & F_PACKED)){
                printf("\n\n---- MPING Statistics----\n");
        }
	printf("%i poll rounds (one echo request per active host per round)\n", ntransmitted);
	if (!(options & F_PACKED))
		putchar('\n');
	
	for (i = 0; i < nhosts; i++) {
		int nrecorded = MIN (nreceived[i], MAXCOUNT);
		long sent = nsent[i];
		
		if((options & F_MEDIAN) || (options & F_PERCENTILE)){
			qsort(packet_time[i], nrecorded, sizeof(int), compare);
                }

		if (!(options & F_PACKED))
			printf("%s: %ld packets received, %ld sent, ", pr_addr(&whereto[i]), nreceived[i], sent);
		else
			printf("%s %ld %ld ", pr_addr(&whereto[i]), nreceived[i], sent);
		

		if (sent > 0){
                        if ((nreceived[i] > sent) && (options & F_VERBOSE)){
				printf("-- somebody's printing up packets!");
                        }else{
                                if (!(options & F_PACKED)) {
                                        printf("%d%% packet loss",
                                               (int) (((sent - nreceived[i]) * 100) / sent));
                                }
                        }
                } else if (!(options & F_PACKED))
			printf("0%% packet loss");
                if (!(options & F_PACKED)){
                        printf("\n");
                }

		if (nreceived[i] && timing) {
			sqsumavg = sqsum[i]/nreceived[i];
			tsumavg = tsum[i]/nreceived[i];
			tsdev = llsqrt(sqsumavg - tsumavg*tsumavg);
		}
		
		if (nreceived[i] && timing && !((options & F_MEDIAN) || (options & F_PERCENTILE))) {
			if (!(options & F_PACKED)) {
				printf("rtt min/avg/max/stddev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld msec\n",
				       tmin[i] / 1000, tmin[i]%1000,
				       (unsigned long) (tsumavg / 1000), (long)(tsumavg%1000),
				       tmax[i] / 1000, tmax[i]%1000,
				       tsdev/1000, tsdev%1000);
			}
			else {
				printf("%ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld\n",
				       tmin[i] / 1000, tmin[i]%1000,
				       (unsigned long) (tsumavg / 1000), (long)(tsumavg%1000),
				       tmax[i] / 1000, tmax[i]%1000,
				       tsdev/1000, tsdev%1000);
			}
	        }			    
		
		else if (nreceived[i] && timing && (options & F_MEDIAN) && !(options & F_PERCENTILE)) {
                        if (!(options & F_PACKED)) {
				printf("rtt min/avg/max/stddev/median = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld msec\n",
				       tmin[i] / 1000, tmin[i]%1000,
				       (unsigned long) (tsumavg / 1000), (long)(tsumavg%1000),
				       tmax[i] / 1000, tmax[i]%1000,
				       tsdev/1000, tsdev%1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50))/1000, (calculate_n_percentile(packet_time[i], nrecorded, 50))%1000);
			}
			else{
				printf("%ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld\n",
				       tmin[i] / 1000, tmin[i]%1000,
				       (unsigned long)(tsumavg / 1000), (long)(tsumavg%1000),
				       tmax[i] / 1000, tmax[i]%1000,
				       tsdev/1000, tsdev%1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50))/1000, (calculate_n_percentile(packet_time[i], nrecorded, 50))%1000);
			}
                }else if (nreceived[i] && timing) {
			if (!(options & F_PACKED)) {
				printf("rtt 10-percentile/median/90-percentile/stddev = %ld.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld msec\n",
				       (calculate_n_percentile(packet_time[i], nrecorded, 10)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 10))%1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50))%1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 90)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 90))%1000,
				       tsdev/1000, tsdev%1000);
			}else{
				printf("%ld.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld\n",
				       (calculate_n_percentile(packet_time[i], nrecorded, 10)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 10))%1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 50))%1000,
                                       (calculate_n_percentile(packet_time[i], nrecorded, 90)) / 1000,
				       (calculate_n_percentile(packet_time[i], nrecorded, 90))%1000,
				       tsdev/1000, tsdev%1000);
			}
		}
		if (!(options & F_PACKED) || !nreceived[i])
			printf("\n");
        }
	printf("----\n");
	/* Free up allocated memory */
	/* Something here makes mping segfault from time to time */
	// free(packet_time[nhosts]);
	// free(&hints);
	if (res != NULL)
		freeaddrinfo(res);
	fflush(stdout);
	exit(0);

}



/*
 *  Print a descriptive string about an ICMP header.
 */
static void
pr_icmph(struct icmp *icp)
{
        switch(icp->icmp_type) {
        case ICMP_ECHOREPLY:
                printf("Echo Reply\n");
                /* XXX ID + Seq + Data */
                break;
        case ICMP_UNREACH:
                switch(icp->icmp_code) {
                case ICMP_UNREACH_NET:
                        printf("Destination Net Unreachable\n");
                        break;
                case ICMP_UNREACH_HOST:
                        printf("Destination Host Unreachable\n");
                        break;
                case ICMP_UNREACH_PROTOCOL:
                        printf("Destination Protocol Unreachable\n");
                        break;
                case ICMP_UNREACH_PORT:
                        printf("Destination Port Unreachable\n");
                        break;
                case ICMP_UNREACH_NEEDFRAG:
			/* RFC792: unused 16 bits then next-hop MTU; avoid union field names (glibc vs musl vs BSD) */
			printf("Frag needed and DF set (mtu = %u)\n",
			       ntohs(((const uint16_t *)(const void *)&icp->icmp_hun)[1]));
                        break;
                case ICMP_UNREACH_SRCFAIL:
                        printf("Source Route Failed\n");
                        break;
                default:
                        printf("Dest Unreachable, Unknown Code: %d\n",
			       icp->icmp_code);
                        break;
                }
                if (!(options & F_VERBOSE))
                        break;
                /* Print returned IP header information */
                pr_retip((struct ip*)(icp + 1));
                break;
        case ICMP_SOURCEQUENCH:
                printf("Source Quench\n");
                if (!(options & F_VERBOSE))
                        break;
                pr_retip((struct ip*)(icp + 1));
                break;
        case ICMP_REDIRECT:
                switch(icp->icmp_code) {
                case ICMP_REDIRECT_NET:
			printf("Redirect Network");
                        break;
                case ICMP_REDIRECT_HOST:
                        printf("Redirect Host");
                        break;
                case ICMP_REDIRECT_TOSNET:
                        printf("Redirect Type of Service and Network");
                        break;
                case ICMP_REDIRECT_TOSHOST:
                        printf("Redirect Type of Service and Host");
                        break;
                default:
                        printf("Redirect, Unknown Code: %d", icp->icmp_code);
                        break;
                }
		{
			struct sockaddr_in gw;
			memset(&gw, 0, sizeof(gw));
			gw.sin_family = AF_INET;
			gw.sin_addr = icp->icmp_hun.ih_gwaddr;
			printf(" New router addr: %s",
			       pr_addr(&gw));
		}
		
                if (!(options & F_VERBOSE))
                        break;
                pr_retip((struct ip*)(icp + 1));
                break;
        case ICMP_ECHO:
                printf("Echo Request\n");
                /* XXX ID + Seq + Data */
                break;
        case ICMP_TIMXCEED:
                switch(icp->icmp_code) {
                case ICMP_TIMXCEED_INTRANS:
                        printf("Time to live exceeded\n");
                        break;
                case ICMP_TIMXCEED_REASS:
                        printf("Frag reassembly time exceeded\n");
                        break;
                default:
                        printf("Time exceeded, Bad Code: %d\n", icp->icmp_code);
                        break;
                }
                if (!(options & F_VERBOSE))
                        break;
                pr_retip((struct ip*)(icp + 1));
                break;
        case ICMP_PARAMPROB:
                printf("Parameter problem: pointer = 0x%02x",
		       icp->icmp_hun.ih_pptr);
		if (!(options & F_VERBOSE))
			break;
		pr_retip((struct ip*)(icp + 1));
                break;
        case ICMP_TSTAMP:
                printf("Timestamp\n");
                /* XXX ID + Seq + 3 timestamps */
                break;
        case ICMP_TSTAMPREPLY:
                printf("Timestamp Reply\n");
                /* XXX ID + Seq + 3 timestamps */
                break;
        case ICMP_IREQ:
                printf("Information Request\n");
                /* XXX ID + Seq */
                break;
        case ICMP_IREQREPLY:
                printf("Information Reply\n");
                /* XXX ID + Seq */
                break;
#ifdef ICMP_MASKREQ
        case ICMP_MASKREQ:
                printf("Address Mask Request\n");
                break;
#endif
#ifdef ICMP_MASKREPLY
        case ICMP_MASKREPLY:
                printf("Address Mask Reply\n");
                break;
#endif
        default:
                printf("Unknown ICMP type: %d\n", icp->icmp_type);
        }
}

/*
 *  Print a descriptive string about an ICMP6 header.
 */
static void
pr_icmph6(struct icmp6_hdr *icp6)
{
        switch(icp6->icmp6_type) {
        case ICMP6_DST_UNREACH:
                printf("Destination unreachable: ");
                switch (icp6->icmp6_code) {
                case ICMP6_DST_UNREACH_NOROUTE:
                        printf("No Route to Destination\n");
                        break;
                case ICMP6_DST_UNREACH_ADMIN:
                        printf("Administratively Prohibited\n");
                        break;
                case ICMP6_DST_UNREACH_NOTNEIGHBOR:
                        printf("Not a Neighbour\n");
                        break;
                case ICMP6_DST_UNREACH_ADDR:
                        printf("Destination Host Unreachable\n");
                        break;
                case ICMP6_DST_UNREACH_NOPORT:
                        printf("Bad port\n");
                        break;
                default:
                        printf("Unknown code %d\n", icp6->icmp6_code);
                        break;
                }
                break;
        case ICMP6_PACKET_TOO_BIG:
		printf("Packet too big: mtu=%u",
		       (unsigned int)ntohl(icp6->icmp6_mtu));
                if (icp6->icmp6_code)
                        printf(", code=%d", icp6->icmp6_code);
                break;
        case ICMP6_TIME_EXCEEDED:
                printf("Time exceeded: ");
                if (icp6->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
                        printf("Hop limit == 0 in transit\n");
                else if (icp6->icmp6_code == ICMP6_TIME_EXCEED_REASSEMBLY)
                        printf("Reassembly time out\n");
                else
                        printf("code %d\n", icp6->icmp6_code);
                break;
        case ICMP6_PARAM_PROB:
                printf("Parameter problem: ");
                if (icp6->icmp6_code == ICMP6_PARAMPROB_HEADER)
                        printf("Wrong header field\n");
                else if (icp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER)
                        printf("Unknown header\n");
                else if (icp6->icmp6_code == ICMP6_PARAMPROB_OPTION)
                        printf("Unknown option\n");
                else
                        printf("code %d\n", icp6->icmp6_code);
                printf ("at %u", (unsigned int)ntohl(icp6->icmp6_pptr));
                break;
	case ICMP6_ECHO_REQUEST:
		printf("Echo request\n");
                break;
        case ICMP6_ECHO_REPLY:
                printf("Echo reply\n");
                break;
        case ICMP6_MEMBERSHIP_QUERY:
                printf("Membership Query\n");
                break;
        case ICMP6_MEMBERSHIP_REPORT:
                printf("MLD Report\n");
                break;
        case ICMP6_MEMBERSHIP_REDUCTION:
                printf("MLD Reduction\n");
                break;
	case ND_ROUTER_ADVERT:
		printf("Router advertisment\n");
		break;
	case ND_NEIGHBOR_SOLICIT:
		printf("Neighbor solicitation\n");
		break;
        default:
		printf("Unknown ICMP type: %d\n", icp6->icmp6_type);

        }
        return;
}

/*
 *  Print an IP header with options.
 */
static void
pr_iph(struct icmp *icp, int cc)
{
        int     hlen;
        u_char  *cp;
        struct ip ipb, *ip = &ipb;

	if (cc < (int)(8 + sizeof(struct ip))) {
		if (options & F_VERBOSE)
			fprintf(stderr, "Mping: ICMP payload too short for embedded IP (%d)\n", cc);
		return;
	}
        (void) memcpy(ip, icp->icmp_data, sizeof(*ip));

        hlen = ip->ip_hl << 2;
	if (hlen < (int)sizeof(struct ip) || hlen > 60) {
		if (options & F_VERBOSE)
			fprintf(stderr, "Mping: bogus embedded IP header length %d\n", hlen);
		return;
	}
	if (cc < 8 + hlen) {
		if (options & F_VERBOSE)
			fprintf(stderr, "Mping: ICMP payload too short for IP options dump\n");
		return;
	}
        cp = (u_char *) &icp->icmp_data[20];    /* point to options */

        (void)printf(" Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src          Dst\n");
        (void)printf("  %1x  %1x  %02x %04x %04x",
                     ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id);
        (void)printf("   %1x %04x",
                     ((ip->ip_off)&0xe000)>>13, (ip->ip_off)&0x1fff);
        (void)printf("  %02x  %02x %04x",
                     ip->ip_ttl, ip->ip_p, ip->ip_sum);
        (void)printf(" %15s ",
                     inet_ntoa(*(struct in_addr *)&ip->ip_src.s_addr));
        (void)printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->ip_dst.s_addr));
        /* dump any option bytes */
        while (hlen-- > 20 && cp < (u_char*)icp+cc) {
                (void)printf("%02x", *cp++);
        }
	printf("\n\n");
}

/*
 *  Return an ascii host address
 *  as a dotted quad IPv4 or hexadecimal IPv6, and optionally with a hostname
 */

char *pr_addr(const void *sap) {
	const struct sockaddr *sa = (const struct sockaddr *)sap;
	/* Two buffers so one printf can use two addresses (e.g. "%s ... %s") safely */
	static char buf[2][4096];
	static int pr_addr_rot;
	char *out = buf[++pr_addr_rot & 1];

	switch (sa->sa_family) {
        case AF_INET: {
                static char addr[INET_ADDRSTRLEN];
		static char hbuf[NI_MAXHOST];
                const struct sockaddr_in *sain = (const struct sockaddr_in *) sa;
		socklen_t salen = (socklen_t)sizeof(struct sockaddr_in);

		/* Network address */
                inet_ntop(AF_INET, &sain->sin_addr, addr, sizeof(addr));

		/* Network hostname */
		if ((options & F_NUMERIC) ||
		    (getnameinfo((struct sockaddr *)(const void *)sa, salen, hbuf, sizeof(hbuf),
				  NULL, 0, NI_NAMEREQD)))
			snprintf(out, 4096, "%s", addr);
		else
			snprintf(out, 4096, "%s (%s)", hbuf, addr);
					
		return out;
	}
        case AF_INET6: {
                static char addr[INET6_ADDRSTRLEN];
		static char hbuf[NI_MAXHOST];
                const struct sockaddr_in6 *sain6 = (const struct sockaddr_in6 *) sa;
		socklen_t salen = (socklen_t)sizeof(struct sockaddr_in6);

		/* Network address */
                inet_ntop(AF_INET6, &sain6->sin6_addr, addr, sizeof(addr));

		/* Network hostname */
		if ((options & F_NUMERIC) ||
		    (getnameinfo((struct sockaddr *)(const void *)sa, salen, hbuf, sizeof(hbuf),
				 NULL, 0, NI_NAMEREQD)))
			snprintf(out, 4096, "%s", addr);
		else
			snprintf(out, 4096, "%s (%s)", hbuf, addr);

		return out;
	}
	}
        return NULL;
}



/*
 *  Dump some info on a returned (via ICMP) IP packet.
 */
static void
pr_retip(struct ip *ip)
{
        int hlen;
        unsigned char *cp;

        hlen = ip->ip_hl << 2;
        cp = (unsigned char *) ip + hlen;

        if (ip->ip_p == IPPROTO_TCP) {
                printf("TCP: from port %d, to port %d (decimal)\n",
                       (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
        } else if (ip->ip_p == IPPROTO_UDP) {
                printf("UDP: from port %d, to port %d (decimal)\n",
                       (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
        }
}

/*
 *  Compare to integers. Used for sorting the packet array.
 */
 
int compare(const void* a, const void* b)
{
        return *(int *)a - *(int *)b;
}

/*
 *  Calculates the n percentile. arr has to be sorted.
 */

long int calculate_n_percentile(int *arr, int arr_len, int n)
{
        int mid;
        mid = arr_len*n/100;
        if(arr_len*n%100 == 0){
                if(mid==0)mid++;
                return (arr[mid]+arr[mid-1])/2;
        }else{
                return arr[mid];
        }
}

/*
 *  Calculate the amount of time to sleep between bursts for hourreport
 *  using X = - ln(1-U*(1-e^(-b/a)))*a
 *
 */

void poissonsleep(float pmean, int truncval)
{
	float X;
	float U = random()/((long double)RAND_MAX+1);
	X = (-logf(1-U*(1-exp(-truncval/pmean))))*pmean;

	if (options & F_VERBOSE)
		printf("\nMping: Sleeping for %.03f seconds\n\n", X);
	sleep(X);
}

/*
 * getdate() returns time of day when called on a predefined format
 *
 */

void prettydate(char *buffer, size_t buffsize) 
{ 
	struct tm *tp; 
	time_t t; 
	
	t = time(NULL); 
	tp = (struct tm *)localtime(&t); 
	strftime(buffer, buffsize, "%a %b %d %H:%M:%S %Z %Y", tp); 
} 


/*
 * llsqrt takes the square root of a long long int and returns a long int.
 * Used for stddev calculation.
 */
static long llsqrt(long long a)
{
        long long prev = ~((long long)1 << 63);
        long long x = a;

        if (x > 0) {
                while (x < prev) {
                        prev = x;
                        x = (x+(a/x))/2;
                }
        }
        return (long) x;
}
