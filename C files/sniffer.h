#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <semaphore.h>
#include <signal.h>
#include <libconfig.h>
#include <math.h>
#include <sys/dir.h>

//#include "statistics.h"
#include "array.h"

#define DEBUG_VAR

/* max length of the file to create */
#define PATH_MAX 1024

/* default snap length (maxium bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* udp headers are always exactly 8 bytes */
#define SIZE_UDP 8


typedef struct Window{
	int index;
	int label;
	double timestamp;
	struct ether_addr *device;
	array(u_int) udpDLsizes,
		udpULsizes,
		tcpDLsizes,
		tcpULsizes,
		udpPayloadULsizes,
		udpPayloadDLsizes,
		tcpPayloadULsizes,
		tcpPayloadDLsizes,
		tcpPorts,
		udpPorts,
		remoteTCPPorts,
		remoteUDPPorts;

	array(double) udpDLtimes,
		udpULtimes,
		tcpDLtimes,
		tcpULtimes;

	array(unsigned long) remoteIps;

	int tcpDLpdf[16];
	int tcpULpdf[16];
	int udpDLpdf[16];
	int udpULpdf[16];

} Window;


/* Ethernet header */
struct sniff_ethernet {
    const struct ether_addr ether_dhost; /* destination host address */
    const struct ether_addr ether_shost; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;                      /* version << 4 | header length >> 2 */
    u_char ip_tos;                      /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
    #define IP_RF 0x8000                /* reserved fragment flag */
    #define IP_DF 0x4000                /* dont fragment flag */
    #define IP_MF 0x2000                /* more fragments flag */
    #define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                     /* time to live */
    u_char  ip_p;                       /* protocol */
    u_short ip_sum;                     /* checksum */
    struct  in_addr ip_src,ip_dst;      /* source and dest address */
};
#define     IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define     IP_V(ip)     (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;                   /* source port 16 bit*/
    u_short th_dport;                   /* destination port 16 bit*/
    tcp_seq th_seq;                     /* sequence number 32 bit*/
    tcp_seq th_ack;                     /* acknowledgement number 32 bit */
    u_char  th_offx2;                   /* data offset,rsvd 8 bit (4 for hlength, 4 for reserved)*/
    #define TH_OFF(th)       (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;			/* Tcp flags 8 bit */
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
#define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                     /* window 16 bit*/
    u_short th_sum;                     /* checksum 16 bit*/
    u_short th_urp;                     /* urgent pointer 16 bit*/
};

struct sniff_udp {
    u_short uh_sport;                   /* source port 16 bit*/
    u_short uh_dport;                   /* destination port 16 bit*/
    u_short uh_ulen;			/* udp header length*/

    u_short uh_sum;                     /* checksum 16 bit*/
};
struct timestamp{
	u_int ts_sec;
	u_int ts_usec;
};


int parse_arguments(int argc, char **argv);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_bits(u_short x);
double time_to_double(long long sec,long long usec);
void MakeFilename(char *buffer, char *orig_name, int cnt, int max_chars);
void printFeatureHeader(FILE * featureFile);
void printWindowFeatures(Window *window);
int getWindowIndex(struct ether_addr *mac);
int checkNetmask(struct in_addr ip);
void loadMacFromFile();
void loadConfigSettings();
struct ether_addr macStringToEtheraddr(char* macString);
Window* window_init();
Window* window_reinit(Window* window,double time);
void window_free(Window *window);
int checkIPBroadcast(struct in_addr ip);
int addDevice(struct ether_addr *dev);
void finalExport();
void printCurrentWindows();
void closeFiles();
void array_calculate_print_features_int(FILE *outfile,int *data,int length,int check);
void array_calculate_print_features_dbl(FILE *outfile,double *data,int length,int check);
int array_concat(void **array1, void *array2, void *array3,int size2,int size3);
int array_concat_int(int **array1, int *array2, int *array3, int size2, int size3);
void timesToInter(double **inter,double *array,int size);
int cmpdbl (const void * a, const void * b);
int cmpint (const void * a, const void * b);
void print_pdf_vector(FILE *file, int *vector, int size, int check);
void MakeFilename(char *buffer, char *orig_name, int cnt, int max_chars);

//here are the settings for the feature capture //import from file
char splitByMac = 0;
char addLabel = 1;
char printHeaders = 0;
char relativeTime = 0;
char macFromFile = 0;
double windowTime = 1;
int netmask=24;
unsigned long routerIp = 3232235778; //192.168.1.2
int *featureSelect;

int rotate, rotate_count,rotate_max; //flags for the time rotation
static double current_filetime;		/* The last time the dump file was rotated. */

char* filterString;
char* headerString;
int headerStringAllocated = 100;

FILE *currentFile = NULL;

///array(FILE*) filePerMac;
FILE **filePerMac;
char usedFiles = 0;
char lenFiles = 0;

array(Window*) allWindows;
double startingTime = -1;

#ifdef DEBUG_VAR



void printStdoutWindow(Window *win){
	printf("TS: %lf, DEVICE_PTR: %p\n",win->timestamp,ether_ntoa(win->device));
}
void printCurrentWindows(){
	printf("---------currentWindows:\n");
	for(int i=0; i<allWindows.used;i++)
		printf("device %d is %s winPointer %p macPointer %p\n",i,ether_ntoa(allWindows.data[i]->device),allWindows.data[i],allWindows.data[i]->device);
	
	printf("\n\n\n");

}

#endif

