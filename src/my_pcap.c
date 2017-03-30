#include "my_pcap.h"

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

int print_device_info(char *dev)
{
  char ip[13];
  char subnet_mask[13];
  bpf_u_int32 ip_raw;                  /* IP address as integer */
  bpf_u_int32 subnet_mask_raw;         /* Subnet mask as integer */
  int lookup_return_code;
  char error_buffer[PCAP_ERRBUF_SIZE]; /* error buffer */
  struct in_addr address;              /* Used for both ip & subnet */
  
  /* Get device info */
  lookup_return_code = pcap_lookupnet(dev,
				      &ip_raw,
				      &subnet_mask_raw,
				      error_buffer);
  if (lookup_return_code == -1) {
    printf("%s\n", error_buffer);
    return 1;
  }

  /*
    If you call inet_ntoa() more than once
    you will overwrite the buffer. If we only stored
    the pointer to the string returned by inet_ntoa(),
    and then we call it again later for the subnet mask,
    our first pointer (ip address) will actually have
    the contents of the subnet mask. That is why we are
    using a string copy to grab the contents while it is fresh.
    The pointer returned by inet_ntoa() is always the same.
    
    This is from the man:
    The inet_ntoa() function converts the Internet host address in,
    given in network byte order, to a string in IPv4 dotted-decimal
    notation. The string is returned in a statically allocated
    buffer, which subsequent calls will overwrite. 
  */
  
  /* Get ip in human readable form */
  address.s_addr = ip_raw;
  strcpy(ip, inet_ntoa(address));
  if (ip == NULL) {
    perror("inet_ntoa"); /* print error */
    return 1;
  }
  
  /* Get subnet mask in human readable form */
  address.s_addr = subnet_mask_raw;
  strcpy(subnet_mask, inet_ntoa(address));
  if (subnet_mask == NULL) {
    perror("inet_ntoa");
    return 1;
  }
  
  printf("Device: %s\n", dev);
  printf("IP address: %s\n", ip);
  printf("Subnet mask: %s\n", subnet_mask);
  
  return 0;
}
