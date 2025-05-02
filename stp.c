/* ================================================
 * Simple Spanning Tree Protocol (STP)
 * Implementation
 * Basde on IEEE 802.1D
 *
 * This Implmentation handles:
 * - BPDU generation and processing
 * - Root bridge election
 * - Port state transistions
 * - Topology change detection and handling
 *
 *  Author: Joshua Muthii
 *  Date: May 2nd 2025
 *  Goal: Become a better network software engineer
/* ================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

/* ================================================================================================
 *                              STP Protocol Constants and Definitions
 * ================================================================================================
 */


/* ================================================
 *   IEEE 802.1 Logical Link Control Headers
 * ================================================
 */
/* bit (0): individual (not group message) - bit (1-7): 21 for STP*/
#define STP_LLC_DSAP 0x42 /*Destination service access point for STP*/
#define STP_LLC_SSAP 0x42 /*Source service access point for STP*/
/*0x03 to indicate unnumbered format(connection-less and not acknowledgements)*/
#define STP_LLC_CTRL 0x03 /*LLC Control Field for STP*/

/* ================================================
 *   STP Protocol ID and version
 * ================================================
 */
 /*Protocol numbers for Spanning Tree Portocol*/
#define STP_PROTO_ID 0x0000 /*STP protocol ID (always 0)*/
#define STP_PROTO_VERSION 0x00 /*LLC Control Field for STP (0 for STP, 2 for Rapid STP)*/



/* ================================================
 *  802.1d STP BPDU Data Fields
 * ================================================
 */
#define STP_BPDU_TYPE_CONFIG 0x00 /*Configuartio BPDU type*/
#define STP_BPDU_TYPE_TCN 0x80 /*Topology Change Notification BPDU type*/

/* ================================================
 *  802.1d STP PORT ROLES
 * ================================================
 */
#define STP_ROLE_UNKOWN 0 /*Role not yet determined*/
#define STP_ROLE_ROOT 1 /*Root Port - best path to root bridge*/
#define STP_ROLE_DESIGNATED 2 /*Designated port - best port to LAN segment*/
#define STP_ROLE_ALTERNATE 3 /*Alternate port - alternate path to root (blocked) */
#define STP_ROLE_BACKUP 4 /*Backup port - backup port for segment (blocked)*/

/* ================================================
 *  802.1d STP PORT STATES
 * ================================================
 */
#define STP_STATE_DISABLED 0  /*Port is administratively disabled*/
#define STP_STATE_BLOCKING 1 /*Port is block frames to pervent loops*/
#define STP_STATE_LISTENING 2 /*Port is transitioning to learning (processing BPDUs)*/
#define STP_STATE_LEARNING 3 /*Port is learning MAC address but not forwarding*/
#define STP_STATE_FORWARDING 4 /*Port is fully operational*/

/* ================================================
 *  802.1d STP  DEFAULT TIMERS
 * ================================================
 */
#define STP_HELLO_TIME 2 /*Interval between BPDUs from root bridge*/
#define STP_MAX_AGE 20 /*Maximum age of BPDU information before discard*/
#define STP_FORWARD_DELAY 15  /*Delay before changing port states*/

/* ================================================
 *  802.1d STP BPDU Flags
 * ================================================
 */
#define STP_FLAG_TC (0x01 << 7 )
#define STP_FLAG_PROPOSAL (0x01 << 6 )
#define STP_FLAG_PORT_ROLE_UNKNOWN    (0x00)
#define STP_FLAG_PORT_ROLE_ALTERNATE  (0x01 << 4 )
#define STP_FLAG_PORT_ROLE_ROOT       (0x10 << 4 )
#define STP_FLAG_PORT_ROLE_DESIGNATED (0x11 << 4 )
#define STP_FLAG_LEARNING   ( 0x01 << 3 )
#define STP_FLAG_FORWARDING ( 0x01 << 2)
#define STP_FLAG_AGREEMENT( 0x01 << 1)
#define STP_FLAG_TC_ACK (0x01)

/*STP BPDU flags*/
//#define STP_FLAG_TC 0x01 /*Topology Change Flag*/
//#define STP_FLAG_TC_ACK 0x80 /*Topology Change Acknowledgement Flag*/

/* ================================================
 *  802.1d STP Defualt Priorities
 * ================================================
 */
#define STP_DEFAULT_BRIDGE_PRIORITY 32768 /*Default Bridge Priority*/
#define STP_DEFAULT_PORT_PRIORITY 128 /*Default Port Priority*/

/* ================================================================================================
 *                                      STP Data structures
 * ================================================================================================
 */

/*STP LLC header*/
typedef struct llc_header {
	uint8_t dsap; /*Destination Service Access point*/
	uint8_t ssap; /*Source Service Access point*/
	uint8_t ctrl; /*Control Field*/
} llc_header_t;

/*STP BPDU*/
/* ================================================
 *  802.1d STP  BPDU structure
 * ================================================
 */

/*All time fields should be given in units of 1/256 of a second*/
typedef struct stp_bpdu{
	uint16_t protocol_id; /*Always 0x0000 for STP*/
	uint8_t  protocol_version; /*Always 0x00 for STP*/
	uint8_t  bpdu_type; /*Configuration or topology change BPDU*/
	uint8_t  flags; /*Topology change flags*/
	uint8_t  root_id[8]; /*Root bridge ID (priority + MAC)*/
	uint32_t  root_path_cost; /*Cost to root*/
	uint8_t  bridge_id[8];  /*Sender bridge ID (priority + MAC)*/
	uint16_t  port_id; /*Sender port ID (Priority field - default 0x80- + port number)*/
	uint16_t message_age; /*Hop Count of BPDU Messages that are forwarded*/
	uint16_t max_age; /*Maximum BPDU age before discard (Default 20 seconds)*/
	uint16_t hello_time; /*hello time in 1/256 of a second - time between periodic transmission of of configuration frames*/
	uint16_t forward_delay; /*Port state transition delay*/

} stp_bpdu_t;

/* ================================================
 *  802.1d STP Port Structure
 * ================================================
 */
typedef struct stp_port{
	int index; /*Port index in the bridges port array*/
	char name[IFNAMESIZ] /*Interface name that will act as this port*/
	uint16_t id; /*Port ID (priority + number)*/
	uint8_t state; /*Current port state*/
	uint8_t role; /*Current port role*/
	uint32_t path_cost; /*Path cost of this port*/
	bool designated /*Is this port the designated port?*/
	stp_bpdu_t config_bpdu /*Last configuration BPDU sent/received on this port*/
	time_t last_bpdu_time /*Timestamp of last recieved bpdu*/
	bool topolgoy_change /*Topology change detected?*/
	int sockfd; /*Socket we are using to send out of this port*/
	struct sockaddr_ll addr; /*Link layer address structure*/
	uint8_t mac[ETH_ALEN]; /*Length of MAC addresss of this port*/
} stp_port_t;

/* ================================================
 *  802.1d STP Bridge Structure
 * ================================================
 */
typedef struct stp_bridge{
	uint8_t bridge_id[8]; /*Bridge ID (priority + MAC)*/
	uint8_t root_id[8]; /*Current root id*/
	uint16_t root_port; /*Id of the port leading to root*/
	uint32_t root_path_cost; /*Path cost to root*/
	bool is_root /*Is this bridge the root*/
	uint16_t hello_time; /*Hello time (in seconds)*/
	uint16_t max_age; /*Maximum age (in seconds)*/
	uint16_t forward_delay /*Forward delay (in seconds)*/
	stp_port_t *ports ;  /*Array of ports*/
	int num_ports; /*number of ports*/
	pthread_mutex_t /*Muted for thread safety*/
} stp_bridge_t;

/* ================================================
 *   Ethernet Header With LLC & BPDU
 * ================================================
 */
typedef struct eth_stp_frame{
	struct ethhdr eth; /*ethernet header*/
	struct llc_header llc; /*LLC header*/
	struct stp_bpdu_t bpdu /*STP BPDU*/
} eth_stp_frame_t __attribute__((packed));  // ensure no padding between fields

/* ================================================================================================
 *                                      Global Variables
 * ================================================================================================
 */
struct stp_bridge bridge; /*Global variable to represent the state of this bridge*/
int running = 1; /*Runnign state of STP on this bridge*/
int netlink_fd=-1; /*File descirptor for netlink socket (used to gather interface information)*/

static const uint8_t stp_multicast_addr[ETH_ALEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
/* ================================================================================================
 *                                      Function Prototypes
 * ================================================================================================
 */

/* ================================================
 *    stp helper functions
 * ================================================
 */
void stp_initialize(uint16_t bridge_priority, uint16_t hello_time, uint16_t max_age, uint16_t forward_delay);
int stp_add_port(const char* if_name, uint16_t port_priority);
void stp_start();
void stp_stop();
int compare_bridge_id(const uint8_t * id1,const uint8_t * id2);
void stp_create_config_bpdu(struct stp_port* port, struct stp_bpdu * bpdu);
void stp_process_bpdu(struct stp_port* port, struct stp_bpdu * received_bpdu);
void stp_send_config_bpdu(struct stp_port* port);
void stp_send_tcn_bpdu(struct stp_port *port);
void stp_timer_tick();
/*This should probably make sure that this is a valid transition as well*/
void stp_port_state_transition(struct stp_port* port, uint8_t new_state);
void stp_recalculate_roles();
void stp_print_state();
const char* stp_state_to_string(uint8_t state);
const char* stp_role_to_string(uint8_t role);
void print_bridge_id(const uint8_t* id);
/*handle kernel signals*/
void handle_signal(int signal);

/* ================================================
 *     Netlink Functions
 * ================================================
 */

int netlink_init();
void netlink_close();
int netlink_get_interfaces();
int netlink_get_mac_address(const char* if_name, uint8_t *mac);
uint32_t netlink_get_link_speed(const char* if_name);

/* ================================================
 *     Port BPDU record functions
 * ================================================
 */
void add_bpdu_record(struct stp_port * port, struct stp_bpdu* bpdu);
void cleanup_bpdu_record(struct stp_port * port);
struct port_bpdu_record* find_bpdu_record(struct stp_port*, const uint8_t* bridge_id);

/* ================================================================================================
 *                                      Implementation
 * ================================================================================================
 */

/* ================================================
 *   Signal Handling
 * ================================================
 */

/*Signal handler to gracefully exit*/
void handle_signal(int signal){
	printf("\033[1;33m[STP] \e[0m Received Signal %d, Shutting down..\n", signal);
	running  = 0;
}
/* ================================================
 *   Netlink Functions
 * ================================================
 */

/*
// Definition of the sockaddr_nl struct
struct sockaddr_nl{
	sa_famlily_t  nl_family; //AF_NETLINK
        usigned_short nl_pad; //zero
	pid_t         nl_pid // Port ID
	_u32          nl_groups //Multicast group mask

}
 nl_pid - is the unicast address of the netlink socket (0 for kernel, pid of the client user process).
	  Identifies a netlink socket and NOT a process

	 Setting nl_pid, if the user process sets nl_pid before calling bind, it is up to the application to
	 make sure that subsequent netlink sockets have a unique nl_pid. Otherwise if it is set to 0 before bind,
	 the kernel will make sure that the nl_pid is unique for subsequent netlink sockets
nl_groups -  is a bit mask with every bit representing a netlink group number
	     Each netlink family has a set of 32 netlink groups (5 bits?).
	     When bind is called on a socket, the nl_groups bit mask should be set to a bitmaks of the groups that
	     it wishes to listen to (0 meaning no groups).

	     A packet may multicast messagse by setting the to any of the multicast groups by setting nl_groups to a bitmask
	     of the groups it wishes to send to when it calls sendmsg() or does connect

	     Only processes iwth an effective UID for CAP_NET_ADMIN capability may send or listen to netlink multicast groups
*/

/*Opening netlink socket and binding to address*/
int netlink_init(){
	/*Defintio and a bit of info above*/
	struct sockaddr_nl nl_addr;

	netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	/*Make sure that address and por*/
	if(netlink_fd < 0){
		perror("\e[1;31m STP :\e[0m Could not create netlink socket...");
		return -1;
	}
	/*set netlink address information*/
	memset(&nl_addr, 0 sizeof(struct sockaddr_nl));
	nl_addr.nl_family = AF_NETLINK;
	nl_addr.nl_pid = getpid();
	if(bind(netlink_fd, (struct sockaddr*)&nl_addr, sizeof(sockaddr_nl)) < 0){
		perror("\e[1;31m STP:\e[0m Failed to bind to netlink socket...");
		close(netlink_fd);
		return -1;
	}

	return 0;
}

/*Closing netlink socket*/
void netlink_close(){
	if(netlink_fd > 0){
		close(netlink_fd);
		netlink_fd = -1;
	}
}
int netlink_get_interfaces(){
	/* Header of the netlink message to
	 * request interface information
	 */
	struct{
		struct nlmsghdr;
		struct ifinfomsg;
	}req;
	struct sockaddr_nl nl_addr;
	char buffer[NETLINK_BUFSIZE]; /*Buffer size of a netlink message?*/
	struct nlmsghdr* nlh;
	struct ifinfomsg* ifm;
	struct rtattr* rta;
	int len, ret;

	/*Perform a health check for the netlink socket*/
	if(netlink_fd< 0){
		fprintf(stderr, "\e[1;31m[STP]:\e[0m netlink_get_interfaces: netlink socket is down" );
		return -1;
	}

	/*Set fields for netlink request message*/
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_type =  RTM_GETLINK;
	req.nlh.nlmsg_len  = NLMSG_LEN(sizeof(struct ifinfomsg))
	req.nlh.nlmsg_flags= NLM_F_REQUEST | NLM_F_DUMP;
	req.ifm.ifi_family = AF_UNSPEC;

	/*Send Request*/
	/* Building netlink address to send to*/
	memset(&nl_addr, 0, sizeof(nl_addr));
	nl_addr.nl_famly = AF_NETLINK;
	ret = sendto(netlink_fd,
		     &req,
		     reg.nlh.nlmsg_len,
		     0,
		     (struct sockaddr*)&nl_addr,
		     sizeof(nl_addr));
	if(ret < 0){
		perror("\e[1;31m[STP]:\e[0m netlink_get_interfaces: Failed to send netlinkd message");
		return -1;
	}

	 /*Process response*/
	int interfaces_found = 0;
	while(1){
		len = recv(netlink_fd, buffer, NETLINK_BUFSIZE, 0);
		if(len < 0){
			perror("\e[1;31m[STP]:\e[0m failed to receive netlink message");
			return -1;
		}

	}

}
/* ================================================
 *   Bridge Operations
 * ================================================
 */

/*Initialize the STP bridge*/
void stp_initialize(uint16_t priority, uint16_t hello_time, uint16_t max_age, uint16_t forward_delay){
	struct ifreq ifr;//

}
/*utilit functions*/
/*@brief compare
 *
 *@param[in] const uint8_t * id1 id of the first bride to compare
 *@param[in] const uint8_t * id2 id of the second bride to compare
 * @return  positive value if id1> id2, negative value if id1<id2, 0 otherwise
 */
int compare_bridge_ids(const uint8_t *id1, const uint8_t * id2){
	return memcmp(id1, id2, sizeof(uint8_t));
}

/*Print the specified bridge ID*/
void print_bridge_id(uint8_t* id){
	printf("%02X%02X.%02X:%02X:%02X:%02X:%02X:%02X",
			id[0],id[1],id[2],id[3],id[4],id[5],id[6],id[7]);
}

/*Print the passed in port state to the console*/
void print_port_state(uint8_t state){
	switch(state){
		case STP_STATE_BLOCKING: printf("BLOCKING"); break;
		case STP_STATE_LISTENING: printf("LISTENING"); break;
		case STP_STATE_LEARNING: printf("LEARNING"); break;
		case STP_STATE_FORWARDING: printf("FORWARDING"); break;
		case STP_STATE_DISABLED: printf("DISABLED"); break;
		default: printf("print_port_state: error - unknown port state provided");
	}
	printf();
}

/*Print the passed in port role*/
void print_port_role(uint8_t role){
	switch(role){
		case STP_ROLE_DESIGNATED: printf("DESIGNATED"); break;
		case STP_ROLE_ROOT: printf("ROOT"); break;
		case STP_ROLE_ALTERNATE: printf("ALTERNATE"); break;
		case STP_ROLE_BACKUP: printf("BACKUP"); break;
		default: printf("UNKNOWN");break;
	}
}









