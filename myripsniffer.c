#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <time.h>
#include <arpa/inet.h>
#include <regex.h>
#include <inttypes.h>


#define ETHERNET_DELKA 14
#define IPV4_DELKA 20
#define IPV6_DELKA 40
#define UDP_DELKA 8
#define DELKA_RIP_HLAVICKY 4
#define DELKA_RTE 20

int packet_counter = 0;

/***
*
*
*  STRUKTURY
*
*/
typedef struct ipv4_structure {
	uint8_t version;
	uint8_t differentiated_services_field;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_and_fragment_offset;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t header_checksum;
	struct in_addr source;
	struct in_addr destination;
} ipv4_structure;
typedef struct ipv6_structure {
	uint32_t version;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr source;
	struct in6_addr destination;
} ipv6_structure;
typedef struct udp_structure {
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length;
	uint16_t check_sum;
} udp_structure;
typedef struct rip_structure {
	uint8_t command;
	uint8_t version;
	uint16_t reserved;
} rip_structure;
typedef struct route_table_entry {
	struct in6_addr ipv6_prefix;
	uint16_t route_tag;
	uint8_t prefix_length;
	uint8_t metric;
} route_table_entry;
typedef struct authentication {
	uint16_t jednicky;
	uint8_t authentication_type;
	char password[16];
} authentication;
typedef struct ip_address {
	uint8_t address;
	uint8_t family;
	uint16_t route_tag;
	struct in_addr ip_adr;
	struct in_addr netmask;
	struct in_addr next_hop;
	uint8_t metric;
	uint8_t metric2;
	uint8_t metric3;
	uint8_t metric4;
} ip_address;

/**********************/

/*
*	FUNKCE PRO VYPIS
*/
int vypis_ipv4(ipv4_structure *tmp_ipv4, rip_structure *rip) {
	printf("*************** %d ***************\n", packet_counter);

	// zdroj, ze ktereho se paket poslal
	char *src; 
	src = inet_ntoa(tmp_ipv4->source);
	printf("Source: %s\n", src);
	src = NULL;
	// cilova adresa na kterou se paket poslal
	char *dest; 
	dest = inet_ntoa(tmp_ipv4->destination);
	printf("Destination: %s\n", dest);
	dest = NULL;
	
	
	// zjisteni a vypsani, zda se jedna o RIPv1 nebo RIPv2
	if(rip->version == 1) {
		printf("%s\n", "Version: RIPv1 (1)");
	}
	else if(rip->version == 2) {
		printf("%s\n", "Version: RIPv2 (2)");
	}
	else {
		fprintf(stderr, "Chyba: Neplatna verze RIP protokolu\n");
		return 1;
	}

	// zjisteni a vypis commandu - request / response
	if(rip->command == 1) {
		printf("%s\n", "Command: Request (1)");
	}
	else if(rip->command == 2) {
		printf("%s\n", 	"Command: Response (2)");
	}
	else {
		fprintf(stderr, "Chyba: nespravny command u RIP protokolu\n");
		return 1;
	}
	return 0;
}

int vypis_ipv4_zbytek(int rip_legth, ip_address *ipad) {
	// na zalade velikosti RIP casti vypocitame pocet IP adres
	int pocet_cyklu = rip_legth-4;
	if(pocet_cyklu != 0) {
		pocet_cyklu = pocet_cyklu/20;
		for(int j = 1; j <= pocet_cyklu; j++) {
			printf("\t  ****** IP ADDRESS ******\n");
			if(ipad->address == 0 && ipad->family == 0) {
				printf("\t  Address family: Unspecified (0)\n");
			}
			else if(ipad->family == 2) {
				printf("\t  Address family: IP (2)\n");
			}
			else {
				fprintf(stderr, "Chyba: Neplatna address family\n");
				return 1;
			}
			if(ipad->route_tag == 0x0000) {
				printf("\t  Route Tag: 0\n");
			}
			else {
				printf("\t  Route Tag: %02x\n", ipad->route_tag); // TODO
			}
			char *tmp; 
			tmp = inet_ntoa(ipad->ip_adr);
			printf("\t  IP Address: %s\n", tmp);
			tmp = inet_ntoa(ipad->netmask);
			printf("\t  Netmask: %s\n", tmp);
			tmp = inet_ntoa(ipad->next_hop);
			printf("\t  Next Hop: %s\n", tmp);
			printf("\t  Metric: %u\n", ipad->metric4);
			ipad = (ip_address*)((u_char*)ipad + DELKA_RTE);
		}
	}
	return 0;
}

int vypis_ipv4_zbytek_pro_rip1(int rip_legth, ip_address *ipad) {
	// na zalade velikosti RIP casti vypocitame pocet IP adres
	int pocet_cyklu = rip_legth-4;
	if(pocet_cyklu != 0) {
		pocet_cyklu = pocet_cyklu/20;
		for(int j = 1; j <= pocet_cyklu; j++) {
			printf("\t  ****** IP ADDRESS ******\n");
			if(ipad->address == 0 && ipad->family == 0) {
				printf("\t  Address family: Unspecified (0)\n");
			}
			else if(ipad->family == 2) {
				printf("\t  Address family: IP (2)\n");
			}
			else {
				fprintf(stderr, "Chyba: Neplatna address family\n");
				return 1;
			}
			char *tmp; 
			tmp = inet_ntoa(ipad->ip_adr);
			printf("\t  IP Address: %s\n", tmp);
			printf("\t  Metric: %u\n", ipad->metric4);
			ipad = (ip_address*)((u_char*)ipad + DELKA_RTE);
		}
	}
	return 0;
}

int vypis_ipv6(ipv6_structure *ip6_hdr, rip_structure *rip) {
	// vytahnuti a vypis zdroje, ze ktereho byl paket poslan
	char src[INET6_ADDRSTRLEN]; 
	inet_ntop(AF_INET6, &ip6_hdr->source, src, sizeof(src));
	
	// vytahnuti a vypis cile, kam byl paket poslan
	char dest[INET6_ADDRSTRLEN]; 
	inet_ntop(AF_INET6, &ip6_hdr->destination, dest, sizeof(dest));

	printf("*************** %d ***************\n", packet_counter);
	printf("Source: %s\n", src);
	printf("Destination: %s\n", dest);

	// vytahnuti a vypsani verze
	if(rip->version == 1) {
		printf("Version: 1\n");
	}
	else {
		printf("Version: %u\n", rip->version);
	}	

	// vytahnuti a vypsani commandu - request / response
	if(rip->command == 1) {
		printf("Command: Request (1)\n");
	}
	else if(rip->command == 2) {
		printf("Command: Response (2)\n");
	}
	else {
		fprintf(stderr, "Chyba: Neplatny command format RIPng protokolu\n");
		return 1;
	}
	return 0;
}

int vypis_ipv6_zbytek(int rip_legth, route_table_entry *rte) {
	// vypocitame pocet cyklu
	int pocet_cyklu = rip_legth-4;
	if(pocet_cyklu != 0) {
		pocet_cyklu = pocet_cyklu/20;
		for(int j = 1; j <= pocet_cyklu; j++) {
			printf("\t* Route table entry *\n");
			char prefix[INET6_ADDRSTRLEN]; 
			inet_ntop(AF_INET6, &rte->ipv6_prefix, prefix, sizeof(prefix));
			printf("\t   IPv6 Prefix: %s\n", prefix);
			printf("\t   Route Tag:\t0x%04x\n", rte->route_tag);
			printf("\t   Prefix len.:\t%u\n", rte->prefix_length);
			printf("\t   Metric:\t%u\n", rte->metric);
			rte = (route_table_entry*)((u_char*)rte + DELKA_RTE);
		}
	}	
	return 0;
}

/**********************/

// http://yuba.stanford.edu/~casado/pcap/section3.html
void packet_parser(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	(void) useless;
	(void) pkthdr;

	// zjistime aktualni cas potrebny pro vypis
	// https://stackoverflow.com/questions/5141960/get-the-current-time-in-c
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);

	// inkrementujeme pocitadlo paketu
	packet_counter++;

	// predpokladame, ze se jedna o paket s IPv4 strukturou
	struct ipv4_structure *tmp_ipv4 = (ipv4_structure*)(packet + ETHERNET_DELKA);
	struct udp_structure *udp;
	struct rip_structure *rip;
	// overime, ze se jedna o IPv4
	if((tmp_ipv4->version >> 4) == 4) {
		// musime preskocit 14 bytu ethernetu a 20 bytu IPv4 a jsme v sekci UDP
		udp = (udp_structure*)(packet + ETHERNET_DELKA + IPV4_DELKA);
		// v UDP nas zajima pouze velikost
		int delka = ntohs(udp->length);
		// vypocitame velikost RIP
		int rip_legth = delka - UDP_DELKA;
		// pokud je velikost RIP mensi nez 0, je neco spatne
		if(rip_legth < 0) {
			fprintf(stderr, "Chyba: Spatna delka RIP paketu\n");
			return;
		}
		else {
			// preskocime do casti RIP
			rip = (rip_structure*)(packet + ETHERNET_DELKA + IPV4_DELKA + UDP_DELKA);			
		}

		if(vypis_ipv4(tmp_ipv4, rip) == 1) {
			return;
		}


		struct ip_address *ipad = (ip_address*)(packet + ETHERNET_DELKA + IPV4_DELKA + UDP_DELKA + DELKA_RIP_HLAVICKY);
		struct authentication *auth = (authentication*)(packet + ETHERNET_DELKA + IPV4_DELKA + UDP_DELKA + DELKA_RIP_HLAVICKY);

		// pokud se jedna o response a RIP obsahuje authentication
		if(auth->jednicky == 0xFFFF) {
			// zjisteni hesla
			char pass[16];
			for(int j = 0; j < 16; j++) {
				pass[j] = auth->password[j];
			}
			pass[16] = '\0';
			printf("\t  **** AUTHENTICATION *****\n");
			printf("    Authentication type: Simple password (2)\n");
			printf("    Password:\t\t %s\n", pass);		
			ipad = (ip_address*)((u_char*)ipad + 20);		
			rip_legth = rip_legth - 20;	
		}	

		if(rip->version == 1) {
			if(vypis_ipv4_zbytek_pro_rip1(rip_legth, ipad) == 1) {
				return;
			}			
		}
		else {
			if(vypis_ipv4_zbytek(rip_legth, ipad) == 1) {
				return;
			}			
		}			

		// datum a cas - vypis
		printf("Date: \t %d/%d \nTime: \t %d:%d:%d\n", timeinfo->tm_mday, timeinfo->tm_mon, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
		printf("\n");
	}
	// pokud se jedna o IPv6
	else if((tmp_ipv4->version >> 4) == 6) {
		// musime pouzit strukturu IPv6
		struct ipv6_structure *tmp_ipv6 = (ipv6_structure*)(packet + ETHERNET_DELKA);
		
		// ze sekce UDP musime ziskat velikost
		udp = (udp_structure*)(packet + ETHERNET_DELKA + IPV6_DELKA); // TODO oddelat vsude packet
		int delka = ntohs(udp->length);
		// vypocitame delku RIP = delka ziskana z UDP - velikost UDP
		int rip_legth = delka - UDP_DELKA;
		// RIP delka nemuze byt zaporna
		if(rip_legth < 0) {
			fprintf(stderr, "Chyba: Spatna delka RIP paketu\n");
			return;
		}
		else {
			rip = (rip_structure*)(packet + ETHERNET_DELKA + IPV6_DELKA + UDP_DELKA);			
		}
		
		if(vypis_ipv6(tmp_ipv6, rip) == 1) {
			return;
		}

		struct route_table_entry *rte = (route_table_entry*)(packet + ETHERNET_DELKA + IPV6_DELKA + UDP_DELKA + DELKA_RIP_HLAVICKY);

		if(vypis_ipv6_zbytek(rip_legth, rte) == 1) {
			return;
		}
		// datum a cas - vypis
		printf("Date: \t %d/%d \nTime: \t %d:%d:%d\n", timeinfo->tm_mday, timeinfo->tm_mon, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
		printf("\n");
	}
	else {
		fprintf(stderr, "Chyba: sem by se to nemelo nikdy dostat - vzdy se musi jednat o IPv4 nebo IPv6\n");
		exit(1);
	}
}

/*
* regex, ktery overuje, zda se v stringu vyskytuje retezec .pcap nebo .cap
* https://stackoverflow.com/questions/1085083/regular-expressions-in-c-examples
*/
int regex_pripona(char *device) {
	regex_t regex;
	int re;
	re = regcomp(&regex, ".cap", 0);
	if(re) {
		fprintf(stderr, "Chyba ve funkci regcomp\n");
		return 2;
	}
	re = regexec(&regex, device, 0, NULL, 0);
	// regex prosel
	if (!re) {
		return 0;
	}
	// regex neprosel
	else if(re == REG_NOMATCH) {
		return 1;
	}	
	// chyba regexu
	else {
		fprintf(stderr, "Chyba ve funkci regexec\n");
		return 2;
	}	
}

int filtr_snifferu(pcap_t *p, bpf_u_int32 network_number) {
	// aplikace filtru
	// https://www.tcpdump.org/manpages/pcap-filter.7.html
	// https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
	struct bpf_program filtr;
	if(pcap_compile(p, &filtr, "(udp and port 520) or (udp and port 521)", 0, network_number) == 0) {
		if(pcap_setfilter(p, &filtr) == 0) {
			// loop - kdyz je -1, tak do nekonecna
			if(pcap_loop(p, -1, packet_parser, NULL) == PCAP_ERROR) {
				fprintf(stderr, "Chyba: ve funkci pcap_loop\n");
				return 1;
			}
		}
		else {
			fprintf(stderr, "Chyba: pcap_setfilter se nepodarilo provest\n");
			return 1;			
		}
	}
	else {
		fprintf(stderr, "Chyba: pcap_compile se nepodarilo provest\n");
		return 1;
	}
	return 0;
}

int connect_device(char *device) {
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	bpf_u_int32 netmask;
	bpf_u_int32 network_number;
	int tmp;

	// overime, jestli interface obsahuje priponu .pcap nebo .cap
	// ano-> nacitame offline ze souboru
	// ne -> pripojime interface realtime
	tmp = regex_pripona(device);
	if(tmp == 0) {
		p = pcap_open_offline(device, error_buffer);
		if(p == NULL) {
			fprintf(stderr, "Chyba: Soubor s rozhranim se nepodarilo nalezt\n");
			return 1;
		}
	}
	else if(tmp == 1) {
		if (pcap_lookupnet(device, &network_number, &netmask, error_buffer) == 0) {
			p = pcap_open_live(device, 500, 1, 500, error_buffer); // TODO upravit parametry - zjistit co znamenaji a jake tam maji byt hodnoty
			if(p == NULL) {
				fprintf(stderr, "Chyba: Ve funkci pcap_open_live\n");
				return 1;
			}		
		}
		else {
			fprintf(stderr, "Chyba: Nepodarilo se nalezt network number a netmask\n");
			return 1;
		}
	}
	else {
		return 1;
	}
	if(filtr_snifferu(p, network_number) == 1) {
		return 1;
	}
	pcap_close(p);
	return 0;
}

int main(int argc, char *argv[]) {
	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	char *device = NULL;

	// KONTROLA PARAMETRU
	if(argc != 3) {
		fprintf(stderr, "Chyba: Neodpovida pocet parametru\n");
		printf("Napoveda\n\t./myripsniffer -i <interface>\n");
		return 1;
	}
	else {
		if(strcmp(argv[1], "-i") == 0) {
			device = argv[2];
		}
	}
	if(device == NULL) {
		fprintf(stderr, "Chyba: Neplatny format rozhrani\n");
		printf("Napoveda\n\t./myripsniffer -i <interface>\n");
		return 1;
	}
	if(connect_device(device) == 1) {
		return 2;
	}
	return 0;
}