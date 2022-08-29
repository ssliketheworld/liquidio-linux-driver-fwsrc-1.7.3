#ifndef _CVM_LRO_H__
#define _CVM_LRO_H__

#define LRO_TIMER_TICKS_MS      (10 * 1000 / (NIC_TIMER_PERIOD_US))
#define LRO_IP_OFFSET           3
#define LRO_SEGMENT_THRESHOLD   9000
#define LRO_AGGREGATED          0
#define LRO_INVALID             -1
#define LRO_UNHANDLED           -2
#define LRO_TAG_MASK            0xffff
#define HASH_SIZE               (LRO_TAG_MASK + 1)

#define container_of(ptr, type, member) ({                  \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

typedef int (*lro_tun_cb_func_t) (cvmx_wqe_t * wqe, void *lro_context,
				  void *arg);
typedef struct lro_pkt_info {
	uint32_t ethoff;	// offset of inner ethernet header
	uint32_t tun_hdr_len;	// size of tunnel hdr
	void *tun_hdr;		// pointer to tunnel header
	lro_tun_cb_func_t tun_hdr_cb;
	bool is_ptp;
} lro_pkt_info_t;

typedef struct lro_context {
	bool is_psh;
	bool timer_pending;
	bool is_v6;
	bool is_ptp;	/* With ptp? */

	void *ethhdr;
	void *iphdr;
	struct tcphdr *tcp;

	uint64_t ptp_ts;

	uint32_t tcp_data_len;
	uint32_t tsval;
	uint32_t tsecr;
	uint32_t next_seq;
	uint32_t ack_seq;
	uint16_t window;
	uint16_t append_cnt;
	int32_t ifidx;

	cvmx_buf_ptr_t gather_list;
	cvmx_buf_ptr_t *glist_ptr;

	lro_tun_cb_func_t tun_hdr_cb;
	void *tun_cb_arg;
	uint8_t tun_hdr_len;
	uint8_t proto_hdr_len;

	cvmx_wqe_t *wqe;
	cvmx_wqe_t *timer_wqe;
	cvmx_tim_delete_t delete_info;

	struct list_head list;

	/* [saf] I added this field from tip code oct_nic_lro_desc structure */

	/* backpressure accumulated credits
	 * that need to be returned
	 */
	uint32_t bp_credits;

} lro_context_t;

static inline void lro_tag_sw_atomic(cvmx_wqe_t * wqe)
{
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
			     CVMX_POW_TAG_TYPE_ATOMIC, cvmx_wqe_get_grp(wqe));
	cvmx_pow_tag_sw_wait();
}

static inline void lro_tag_sw_order(cvmx_wqe_t * wqe)
{
	cvmx_pow_tag_sw_full(wqe, (cvmx_wqe_get_tag(wqe) & LRO_TAG_MASK),
			     CVMX_POW_TAG_TYPE_ORDERED, cvmx_wqe_get_grp(wqe));
}

void cvmcs_nic_flush_lro(cvmx_wqe_t * wqe, lro_context_t * lro_ctx,
			 int del_timer);
void oct_nic_lro_init(void);
int oct_nic_lro_process(cvmx_wqe_t * wqe);
int oct_nic_lro_receive_pkt(cvmx_wqe_t * wqe,
	lro_pkt_info_t * lro_pkt_info, int ifidx);

#endif
