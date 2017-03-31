/*
 * ftdparse.cc
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 **************************************************************************** 
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o ftdparse ftdparse.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip				Capture all IP packets.
 * tcp				Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"FTDparse"

#include "my_pcap.h"
using namespace std;

/*
 * print help text
 */
void
print_app_usage(void)
{
  cout << "Usage: " << APP_NAME << " [interface]" << endl;
  cout << "Options:" << endl;
  cout << "    interface    Listen on <interface> for packets." << endl;
  
  return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                  /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	cout << "Packet number: " << count << endl;
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
	  cout << "   * Invalid IP header length: " << size_ip << " bytes\n" << endl;
		return;
	}
 
	/* print source and destination IP addresses */
	cout << "       From: " << inet_ntoa(ip->ip_src) << endl;
	cout << "         To: " << inet_ntoa(ip->ip_dst) << endl;
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
		  cout << "   Protocol: TCP" << endl;
		  break;
		case IPPROTO_UDP:
		  cout << "   Protocol: UDP" << endl;
		  return;
		case IPPROTO_ICMP:
		  cout << "   Protocol: ICMP" << endl;
		  return;
		case IPPROTO_IP:
		  cout << "   Protocol: IP" << endl;
		  return;
		default:
		  cout << "   Protocol: unknown" << endl;
		  return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
	  cout << "   * Invalid TCP header length: "<< size_tcp << " bytes" << endl ;
	  return;
	}
	
	cout << "   Src port: " << ntohs(tcp->th_sport) << endl;
	cout << "   Dst port: " << ntohs(tcp->th_dport) << endl;
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
	  cout << "   Payload " << size_payload << " bytes)" << endl;
	  print_payload(payload, size_payload);
	}

return;
}


int main(int argc, char **argv)
{
  char *dev = NULL;			/* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
  pcap_t *handle;			/* packet capture handle */
  bpf_u_int32 net;                      /* IP address as integer */
  bpf_u_int32 mask;                     /* Subnet mask as integer */
  
  /* filter expression [3] */
  char filter_exp[] = "ip host 127.0.0.1 and dst port 7036";
  struct bpf_program fp;		/* compiled filter program (expression) */
    
  /* check for capture device name on command-line */
  if (argc == 2) {
    dev = argv[1];
  }
  else if (argc > 2) {
    cerr <<  "error: unrecognized command-line options" << endl << endl;
    print_app_usage();
    exit(EXIT_FAILURE);
  }
  else {
    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      cerr << "Couldn't find default device: " << errbuf << endl;
      exit(EXIT_FAILURE);
    }
    print_device_info(dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      cerr << "Couldn't get netmask for device: " << dev << ": " << errbuf << endl;
      net = 0;
      mask = 0;
    }
	
  }
   
  /* open capture device */
  handle = pcap_open_offline("alltraffic.pcap", errbuf);
  if (handle == NULL) {
    cerr << "Couldn't open file alltraffic.pcap: " << errbuf << endl;
    return(2);
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    cerr << "Couldn't parse filter" << filter_exp <<" : " << pcap_geterr(handle) << endl;
    return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    cerr << "Couldn't install filter" << filter_exp <<" : " << pcap_geterr(handle) << endl;
    return(2);
  }
  
  /* now we can set our callback function */
  //    pcap_loop(handle, -1, got_packet, NULL);
  //    pcap_loop(handle, -1, my_packet_handler, NULL);
  // start packet processing loop, just like live capture
  if (pcap_loop(handle, -1, got_packet, NULL) < 0) {
    cerr << "pcap_loop() failed: " << pcap_geterr(handle) << endl;
    return 1;
  }

  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);
  
  cout << endl << "Capture complete." << endl;
  
  return 0;
}
