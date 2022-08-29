#ifndef _CVM_TSO_H__
#define _CVM_TSO_H__

#define TSO_SUCCESS  0
#define TSO_INVALID -1
#define TSO_FAILED  -2

/* worst case assuming you have to insert aura hdr before every gather ptr */
#define MAX_GATHER_BUFS_O3 7
#define MAX_PKO3_CMD_WORDS 15 //without send jmp

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

/* describes a single buffer along with this aura pki bufs dont carry aura info */
struct tso_gather_buf_o3 {
        cvmx_pko_buf_ptr_t buf;
        int aura;
};

/* struct to store all the gather bufs of a packet */
struct tso_pkt_desc_o3 {
        /* max descs is 14 without jmp, discount for one aura per ptr
 	 * ext hdrs etc
 	 * array of gather buffers
 	 */
	struct tso_gather_buf_o3 g_bufs[MAX_GATHER_BUFS_O3];
        /* number of buffers */
	int nbufs;
};

/* TODO: Need to add Tunnel headers support */
typedef struct tso_hdr {
	bool is_vlan;
	bool is_v6;
	uint32_t hdr_len;
	void *ethhdr;
	void *iphdr;
	struct tcphdr *tcp;
} tso_hdr_t;

typedef int (*tso_cb_func_t) (cvmx_wqe_t * wqe, uint16_t gso_segs,
			      uint8_t ip_offset, uint8_t l4_offset,
			      cvmx_buf_ptr_t * gather_list,
			      uint32_t * total_size, int ifidx, void *arg);
typedef int (*tso_tun_cb_func_t) (cvmx_wqe_t * wqe, cvmx_buf_ptr_t * buf,
				  int total_size, int seg, void *arg);

/* TODO: Need to add Tunnel headers support */
/* Information used for completing TSO */
typedef struct tso_info {
	uint16_t gso_size;
	uint32_t ethoff;	// offset of inner ethernet header
	uint32_t tun_hdr_len;	// size of tunnel hdr
	void *tun_hdr;		// pointer to tunnel header
	tso_tun_cb_func_t tun_hdr_cb;
	tso_cb_func_t cb;
	void *cb_arg;		// opaque pointer for use by cb functions
} tso_info_t;

int tso_process_pkt(cvmx_wqe_t * wqe, int front_size, tso_info_t *tso_info);
//int cvmcs_nic_handle_tso(cvmx_wqe_t * wqe, tso_info_t * tso_info, int ifidx);
int cvmcs_nic_send_gather_list_to_wire(cvmx_wqe_t * wqe, uint16_t gso_segs,
				       uint8_t ip_offset,
				       cvmx_buf_ptr_t * gather_list,
				       uint32_t * total_size, int ifidx);
int
cvmcs_tso_send_gather_list_to_wire_pko3(struct tso_pkt_desc_o3 *gather_list,
                                        int ifidx, uint32_t *total_size, cvmx_wqe_t *wqe,
                                        int gso_segs, uint8_t l3_offset, uint8_t
                                        l4_offset, int lport, int flag);

void
tso_free_lists_o3(struct tso_pkt_desc_o3  *gather_list, int start, int segs);

#endif /* _CVM_TSO_H__ */
