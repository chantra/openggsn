/**
 * OpenGGSN - Gateway GPRS Support Node
 * Copyright (C) 2010 Emmanuel Bretelle <chantra@debuntu.org>
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/* ggsnmonitor.c
 *
 */

#include "../config.h"
#include <inttypes.h>

#include <unistd.h> /* getopt */
#include <getopt.h>


#include <pcap.h>

/**
 * #include <pcap/sll.h>
*/
#include "sll.h"

#include <syslog.h>

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> /* in_addr ... */
#include <netinet/if_ether.h> /* really, <net/ethernet.h> should be needed only */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h> /* inet_ntoa ... */

#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>

#include <signal.h>

#include "../lib/syserr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "../gtp/gtpie.h"

#include "gtp_packet.h"
#include "gtpie_utils.h"
#include "gtpdump_options.h"



#define FILTER_STRING "port 1812 or port 1813 or port 2123 or port 2152 or port 3386"

char short_optstr[] = "r:i:w:I:M:s:h";
struct option long_optstr[] = {
	{ "read", 1, 0, 'r' },
	{ "interface", 1, 0, 'i' },
	{ "write", 1, 0, 'w' },
	{ "imsi", 1, 0, 'I' },
	{ "msisdn", 1, 0, 'M' },
	{ "snaplen", 1, 0, 's' },
	{ "help", 0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int write_cnt = 0;
int read_cnt = 0;
/* datalink of capture */
int datalink = -1;
uint8_t continue_snif = 1;



struct pdp_ctx {
	struct ul255_t apn;/* The APN Network Identifier currently used. */
	uint64_t    imsi;     /* International Mobile Subscriber Identity.*/
  struct ul16_t msisdn; /* The basic MSISDN of the MS. */
  uint32_t    teic_own; /* (Own Tunnel Endpoint Identifier Control) */
  uint32_t    teid_own; /* (Own Tunnel Endpoint Identifier Data I) */
  uint32_t    teic_gn;  /* Tunnel Endpoint Identifier for the Gn and Gp interfaces. (Control plane) */
  uint32_t    teid_gn;  /* Tunnel Endpoint Identifier for the Gn and Gp interfaces. (Data I) */
  uint32_t    tei_iu;   /* Tunnel Endpoint Identifier for the Iu interface. */

	pcap_dumper_t *dumper;
};

void
usage(char *filename){
	char *f = strdup (filename);
	fprintf(stderr, "USAGE: %s [ -r file ] [ -w file ] [ -i interface ] [ -s snaplen ] [ -I imsi ] [ -M msisdn ]\n\
Extract GTP traffic (Control+Data) for a given MSISDN or IMSI.\n\
\n\
It can either capture directly from the network or from an input file.\n\
\t--read\n\t-r:\tRead from file (- for stdin)\n\n\
\t--write\n\t-w:\tWrite to file (- for stdout)\n\n\
", basename(f));
	free (f);
	return;
}


/**
 * ts_format... from tcpdump's util.c
 */
char *
ts_format(register int sec, register int usec){
  static char buf[sizeof("00:00:00.000000")];
  (void)snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06u",
    sec / 3600, (sec % 3600) / 60, sec % 60, usec);
  return buf;
}

char *
ip_format(u_char *ip){
	static char buf[sizeof("000.000.000.000")];
	(void)snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	return buf;
}

void
pcap_dump_and_flush (pcap_dumper_t *dumper, const struct pcap_pkthdr *h, const u_char *sp){
	write_cnt++;
	pcap_dump ((u_char *)dumper, h, sp);
	if (pcap_dump_flush (dumper) == -1){
		fprintf (stderr, "pcap_dump_flush: Could not flush to file\n");
	}
}

void
handle_gtpv0_packet (u_char *udata, uint32_t len, u_char *packet, const struct pcap_pkthdr *h, const u_char *sp){
	union gtp_packet *gp = (union gtp_packet *)packet;
	fprintf(stderr, "GTPv%d PROTOCOL: %d TYPE: 0x%2X LENGTH: %d\n", GTP_V(gp), GTP_PT(gp), GTP_TYPE(gp), GTP_LENGTH(gp));
}

void
handle_gtpv1_packet (u_char *udata, uint32_t len, u_char *packet, const struct pcap_pkthdr *h, const u_char *sp){
	struct pdp_ctx *pdp_ctx = (struct pdp_ctx *)udata;
	union gtp_packet *gp = (union gtp_packet *)packet;
	union gtpie_member* ie[GTPIE_SIZE];
	int hlen = GTP_HLEN(gp);

/*
	struct ul255_t apn_req;
*/
	struct ul16_t msisdn;
	uint64_t imsi;
	uint8_t cause;

	/*
	fprintf(stdout, "GTPv%d%s-%c TYPE: 0x%02X LENGTH: %d\n", GTP_V(gp), GTP_PT(gp) ? "" : "'", GTP_TYPE(gp) == 0xFF ? 'U' : 'C', GTP_TYPE(gp), GTP_LENGTH(gp));
	*/
	/* CREATE_PDP_CONTEXT_REQUEST */
	if (GTP_TYPE(gp) == GTP_CREATE_PDP_REQ || GTP_TYPE(gp) == GTP_UPDATE_PDP_REQ){
		if(gtpie_decaps (ie, GTP_V(gp), (u_char *)gp + hlen, len-hlen)){
			sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to decap GTPIE from GTPv1 packet");
			return;
		}
		if (gtpie_gettv0 (ie, GTPIE_IMSI, 0, &imsi, sizeof (imsi)) != 0){
			sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to find IMSI from %s payload!", GTP_TYPE(gp) == GTP_CREATE_PDP_REQ ? "CREATE_PDP_REQ" : "UPDATE_PDP_REQ");
			return;
		}
		if ((pdp_ctx->imsi && pdp_ctx->imsi == imsi)
					||
				(!pdp_ctx->imsi
						&& pdp_ctx->msisdn.l
						&& gtpie_gettlv(ie, GTPIE_MSISDN, 0, &msisdn.l, &msisdn.v, sizeof(msisdn.v)) == 0
						&& pdp_ctx->msisdn.l == msisdn.l
						&& memcmp( pdp_ctx->msisdn.v, msisdn.v, msisdn.l) == 0)
				) {
			/* first time we encounter this msisdn, save imsi */
			if (!pdp_ctx->imsi)
				pdp_ctx->imsi = imsi;
			/* there is an imsi and it is ours */
			/* save to dump file */
			if (pdp_ctx->dumper){
				pcap_dump_and_flush (pdp_ctx->dumper, h, sp);
			}
			if(gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp_ctx->teid_gn)){
				sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Missing TEID Data in PDP_CTX_REQ");
				return;
			}
			pdp_ctx->teid_gn = htonl( pdp_ctx->teid_gn );
			if(gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp_ctx->teic_gn)){
				sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Missing TEID CP in PDP_CTX_REQ");
				return;
			}
			pdp_ctx->teic_gn = htonl( pdp_ctx->teic_gn );
		}
	/* CREATE_PDP_CONTEXT_RESPONSE */
	}else if (GTP_TYPE(gp) == GTP_CREATE_PDP_RSP || GTP_TYPE(gp) == GTP_UPDATE_PDP_RSP){
		if (gp->gtp1s.h.tei == pdp_ctx->teic_gn){
			/* anyhow, we save packet */
			if (pdp_ctx->dumper){
				pcap_dump_and_flush (pdp_ctx->dumper, h, sp);
			}
			/* decapsulate packet */
			if(gtpie_decaps (ie, GTP_V(gp), (u_char *)gp + hlen, len-hlen)){
				sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to decap GTPIE from GTPv1 packet\n");
				return;
			}
			/* check cause = req accepted */
			if (gtpie_gettv1 (ie, GTPIE_CAUSE, 0, &cause)){
				sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Missing Cause in PDP_CTX_RESP");
				return;
			}
			if (GTPCAUSE_ACC_REQ == cause){
				/* It seems that when UPDATE_PDP_CTX_RESP, TEI_C might be missing */
				/* get teids */
				if (GTP_TYPE(gp) == GTP_CREATE_PDP_RSP || gtpie_exist(ie, GTPIE_TEI_DI, 0) == 1){
					if(gtpie_gettv4(ie, GTPIE_TEI_DI, 0, &pdp_ctx->teid_own)){
						sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Missing TEID Data in PDP_CTX_RESP");
						return;
					}
					pdp_ctx->teid_own = htonl( pdp_ctx->teid_own );
				}
				if (GTP_TYPE(gp) == GTP_CREATE_PDP_RSP || gtpie_exist(ie, GTPIE_TEI_C, 0) == 1){
					if(gtpie_gettv4(ie, GTPIE_TEI_C, 0, &pdp_ctx->teic_own)){
						sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Missing TEID CP in PDP_CTX_RESP");
						return;
					}
					pdp_ctx->teic_own = htonl( pdp_ctx->teic_own );
				}
			}
		}else{
			return;
		}
#if 0
	/* UPDATE_PDP_CONTEXT_REQUEST */
	}else if (GTP_TYPE(gp) == 0x12){
	/* UPDATE_PDP_CONTEXT_RESPONSE */
	}else if (GTP_TYPE(gp) == 0x13){
#endif
	/* DELETE_PDP_CONTEXT_REQUEST */
	}else if (GTP_TYPE(gp) == GTP_DELETE_PDP_REQ){
		if (gp->gtp1s.h.tei == pdp_ctx->teic_own){
			if (pdp_ctx->dumper){
				pcap_dump_and_flush (pdp_ctx->dumper, h, sp);
			}
		}
	/* DELETE_PDP_CONTEXT_RESPONSE */
	}else if (GTP_TYPE(gp) == GTP_DELETE_PDP_RSP){
		if (gp->gtp1s.h.tei == pdp_ctx->teic_gn){
			if (pdp_ctx->dumper){
				pcap_dump_and_flush (pdp_ctx->dumper, h, sp);
			}
		}
	}else if (GTP_TYPE(gp) == GTP_GPDU){
		/* check if teid is one of sgsn/ggsn data teid and keep the packet */
		if (gp->gtp1s.h.tei == pdp_ctx->teid_own || gp->gtp1s.h.tei == pdp_ctx->teid_gn){
			if (pdp_ctx->dumper){
				pcap_dump_and_flush (pdp_ctx->dumper, h, sp);
			}
		}
		/*
		if(gtpie_decaps (ie, GTP_V(gp), (u_char *)gp + hlen, len-hlen)){
			sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to decap GTPIE from GTPv1 packet\n");
			return;
		}
		fprintf(stdout, "HLEN: %d\n", hlen);
		if (gtpie_gettlv(ie, GTPIE_APN, 0, &apn_req.l, &apn_req.v, sizeof(apn_req.v)) == 0){
			fprintf (stdout, " APN: %s\n", gtpie_utils_apn_decode(apn_req));
		}
		if (gtpie_gettv0 (ie, GTPIE_IMSI, 0, &imsi, sizeof (imsi)) == 0){
			fprintf (stdout, " IMSI: %s\n", gtpie_utils_imsi_decode (imsi));
		}
		if (gtpie_gettlv(ie, GTPIE_MSISDN, 0, &msisdn.l, &msisdn.v, sizeof(msisdn.v)) == 0){
			fprintf (stdout, " MSISDN: %s\n", gtpie_utils_msisdn_decode (msisdn.v, msisdn.l));
		}
		*/
	}
}

void
handle_gtp_packet(u_char *udata, uint32_t len, u_char *packet, const struct pcap_pkthdr *h, const u_char *sp){
	union gtp_packet *gp = (union gtp_packet *)packet;
	if( (gp->flags & 0xe0) == 0x00){
		handle_gtpv0_packet (udata, len, packet, h, sp);
	}else if( (gp->flags & 0xe0) == 0x20){
		handle_gtpv1_packet (udata, len, packet, h, sp);
	}
}
void
pcap_callback (u_char *udata, const struct pcap_pkthdr *header, const u_char *packet){
	//struct timeval ts = header->ts;
	//bpf_u_int32	len = header->caplen;
	struct ip *ip = NULL;
	struct udphdr *udp = NULL;
	u_int16_t dport, sport;
	read_cnt++;
	/**
	* Get IP packet from different datalink type
	*/
	if (datalink == DLT_LINUX_SLL){
		/* Linux cooked packets */
		struct sll_header *sllh = (struct sll_header *)packet;
		if (ntohs(sllh->sll_protocol) != 0x0800){
			sys_err( LOG_ERR, __FILE__, __LINE__, 0, "Encountered a non IP packet\n");
			return;
		}
		ip = (struct ip *)(packet+SLL_HDR_LEN);
	}else if (datalink == DLT_EN10MB){
		/* Ethernet packet */
		struct ether_header *ether = (struct ether_header *)packet;
		if (ntohs(ether->ether_type) != 0x0800){
			sys_err( LOG_ERR, __FILE__, __LINE__, 0, "Encountered a non IP packet\n");
			return;
		}
		ip = (struct ip *)(packet+ETHER_HDR_LEN);
	}else{
		return;
	}

	if (ip == NULL){
		sys_err( LOG_ERR, __FILE__, __LINE__, 0, "IP payload is NULL\n");
		return;
	}
	if (ip->ip_p != IPPROTO_UDP){
		sys_err( LOG_ERR, __FILE__, __LINE__, 0, "Encountered a non UDP packet\n");
		return;
	}
	udp = (struct udphdr *)(((u_char *)ip)+4*(ip->ip_hl));
	sport = ntohs (udp->source);
	dport = ntohs (udp->dest);
/*
	fprintf (stdout, "%s", ts_format(ts.tv_sec % 86400, ts.tv_usec));
	fprintf( stdout, " IP %s.%d > ", inet_ntoa(ip->ip_src), sport);
	// or inet_ntoa(*(struct in_addr *)&(iph->saddr));
	fprintf(stdout, "%s.%d: UDP, length %d", inet_ntoa(ip->ip_dst), dport, ntohs (udp->len) - 8);
	fprintf(stdout, "\n");
*/
	if (dport == 2152 || dport == 2123 || sport == 2152 || sport == 2123){
		handle_gtp_packet( udata, ntohs (udp->len) - 8, ((u_char *)udp) + 8, header, packet);
	}
	return;
}

void
cleanup(int signum)
{
	fprintf(stderr, "Caught signal %s (%d), exiting!\n", strsignal (signum), signum);
	continue_snif = 0;
}
int
main (int argc, char **argv){

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = NULL;
	struct bpf_program fp;
	struct gtpdump_options options;
	int rc;
	int option_index;
	struct pdp_ctx pdp_ctx;


	/** handle options */
	/* init options */
	memset(&options, 0, sizeof( options ));
	/* pdp ctx init
	 * all to 0 except teis to 1
	 * so we dont catch useless DELETE PDP CTX*/
	memset(&pdp_ctx, 0, sizeof( pdp_ctx ));
	pdp_ctx.teid_gn = pdp_ctx.teid_own = pdp_ctx.teic_gn = pdp_ctx.teic_own = 0xFFFFFFFF;
	options.snaplen = DFT_SNAPLEN;

	while ( (rc = getopt_long (argc, argv, short_optstr, long_optstr, &option_index)) != -1){
		switch (rc){
			case 0:
				break;
			case 'r':
				options.read = optarg;
				break;
			case 'w':
				options.write = optarg;
				break;
			case 'i':
				options.interface = optarg;
				break;
			case 'I':
				options.imsi = optarg;
				if (gtpie_utils_imsi_encode (options.imsi, &pdp_ctx.imsi) != 0){
					fprintf (stderr, "Could not encode IMSI %s to binary format\n", options.imsi);
					return 1;
				}
				break;
			case 'M':
				options.msisdn = optarg;
				if (gtpie_utils_msisdn_encode (options.msisdn, &pdp_ctx.msisdn.v, &pdp_ctx.msisdn.l, sizeof (pdp_ctx.msisdn)) != 0){
					fprintf (stderr, "Could not encode MSISDN %s to binary format\n", options.msisdn);
					return 1;
				}
				break;
			case 's':
				;
				int snaplen = atoi(optarg);
				if (snaplen == 0 && optarg[0] == '0'){
					/* default to max snaplen */
					options.snaplen = 65535;
				}else if (snaplen < 0){
					fprintf (stderr, "Snaplen cannot be < 0, defaulting to default value!\n");
				}else if (snaplen == 0) {
					fprintf (stderr, "%s is not an integer, defaulting to default snaplen value!\n", optarg);
				}else{
					options.snaplen = snaplen;
				}
				break;
			case 'h':
				usage(argv[0]);
				return 1;
			case '?':
				fprintf(stderr, "Uknown or missing paraneter option %c\n", optopt);
				break;
			default:
				printf ("?? getopt returned character code 0%o ??\n", rc);
		}
	}
	/* make sure read XOR interface is set */
	if ((options.read == NULL) == (options.interface == NULL)){
		fprintf(stderr, "ERROR: You must supply either -r or -i!\n");
		usage(argv[0]);
		return 1;
	}

	/* make sure msisdn XOR imsi is set */
	if ((options.msisdn == NULL) == (options.imsi == NULL)){
		fprintf(stderr, "ERROR: You must supply either -M (msisdn) or -I (imsi)!\n");
		usage(argv[0]);
		return 1;
	}


	if (options.read){
		pcap_handle = pcap_open_offline (options.read, errbuf);
		if (pcap_handle == NULL){
			fprintf (stderr, "Could not open file %s, error: %s\n", options.read, errbuf);
			return 1;
		}
	}else{
		pcap_handle = pcap_open_live (options.interface, options.snaplen, 1, 1000, errbuf);
		if (pcap_handle == NULL){
      fprintf (stderr, "Could not open device %s, error: %s\n", options.interface, errbuf);
      return 1;
    }
	}

	if (pcap_compile (pcap_handle, &fp, FILTER_STRING, 0, 0) == -1 ){
		fprintf (stderr, "Couldn't parse filter %s: %s\n", FILTER_STRING, pcap_geterr(pcap_handle));
		return 1;
	}

	if (pcap_setfilter(pcap_handle, &fp) == -1 ){
		fprintf (stderr, "Couldn't install filter %s: %s\n", FILTER_STRING, pcap_geterr(pcap_handle));
		return 1;
	}

	if (options.write){
		if ( (pdp_ctx.dumper = pcap_dump_open (pcap_handle, options.write)) == NULL){
			fprintf (stderr, "Couldn't open dump file %s: %s\n", options.write, pcap_geterr(pcap_handle));
			return 1;
		}
	}
	pcap_freecode (&fp);

	datalink = pcap_datalink (pcap_handle);

	if (!(datalink == DLT_LINUX_SLL || datalink == DLT_EN10MB)){
		fprintf (stderr, "Unsupported Datalink [%d] %s (%s)\n", datalink, pcap_datalink_val_to_name (datalink), pcap_datalink_val_to_description (datalink));
		return 1;
	}

	/**
	 * set signal handlers
	 */
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGPIPE, cleanup);

	if (options.read)
		fprintf (stderr, "Reading from file %s", options.read);
	else
		fprintf (stderr, "listening on %s", options.interface);

	fprintf (stderr, ", link-type %s (%s)\n", pcap_datalink_val_to_name (datalink), pcap_datalink_val_to_description (datalink) );
	/* Read one packet until end of file */
	/*
	while (pcap_dispatch (pcap_handle, 1, pcap_callback, (u_char *)&pdp_ctx) == 1);
	*/
	while (continue_snif){
		rc = pcap_dispatch (pcap_handle, 1, pcap_callback, (u_char *)&pdp_ctx);
		if (rc == 0){
			if(options.read){
				/* reading from capture file and no more packet left */
				break;
			}else{
				/* reading from interface... timeout happened, read more */
				continue;
			}
		}
		if (rc == -1){
			fprintf (stderr, "pcap_dispatch returned -1: %s\n", pcap_geterr(pcap_handle));
			break; /* should we continue or exit?!?! */
		}
		if (rc == -2){
			/* pcap_breakloop was called... weird really :) as it is not used */
			break;
		}
	}
	/*
	while ( ( rc = pcap_loop (pcap_handle, 1, pcap_callback, (u_char *)&pdp_ctx))
	*/
	fprintf(stderr, "Read %d packets, Wrote %d packets\n", read_cnt, write_cnt);
	pcap_close (pcap_handle);
	if (pdp_ctx.dumper){
		pcap_dump_flush (pdp_ctx.dumper);
		pcap_dump_close (pdp_ctx.dumper);
	}
	return 0;
}
