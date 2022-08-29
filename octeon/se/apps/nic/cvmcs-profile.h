

#include "global-config.h"
#include "cvmcs-common.h"
#include "cvmcs-nic.h"

/* Turn this flag on use the cycle count profiling APIs in the NIC app. */
//#define ENABLE_PROFILING

#define MAX_PROFILES           32

#define PROF_RX_GET_IFIDX      0
#define PROF_RX_ERROR_CHECK    (PROF_RX_GET_IFIDX + 1)
#define PROF_RX_FILTER         (PROF_RX_ERROR_CHECK + 1)
#define PROF_RX_CSUM           (PROF_RX_FILTER + 1)
#define PROF_RX_VLAN_STRIP     (PROF_RX_CSUM + 1)
#define PROF_RX_RH_DONE        (PROF_RX_VLAN_STRIP + 1)
#define PROF_TX_HEADERS        (PROF_RX_RH_DONE + 1)
#define PROF_TX_BEFORE_PKO     (PROF_TX_HEADERS + 1)
#define PROF_TX_CSUM           (PROF_TX_BEFORE_PKO + 1)
#define PROF_TXRX_GOT_DESC     (PROF_TX_CSUM + 1)
#define PROF_TXRX_PDESC_XMIT   (PROF_TXRX_GOT_DESC + 1)
#define PROF_TX_DONE           (PROF_TXRX_PDESC_XMIT + 1)
#define PROF_RX_DONE           (PROF_TX_DONE + 1)

#define PROF_NVME_CMD_FETCH    (PROF_RX_DONE + 1)
#define PROF_NVME_READ_PROC    (PROF_NVME_CMD_FETCH + 1)
#define PROF_NVME_WRITE_PROC   (PROF_NVME_READ_PROC + 1)
#define PROF_NVME_READ_DMA     (PROF_NVME_WRITE_PROC + 1)
#define PROF_NVME_WRITE_DMA    (PROF_NVME_READ_DMA + 1)
#define PROF_NVME_PRP_LIST_TX  (PROF_NVME_WRITE_DMA + 1)

#ifdef ENABLE_PROFILING

extern uint64_t base_profile_cycle;

extern void cvmcs_profile_initialize(void);
extern void cvmcs_profile_init_local(void);
extern int  cvmcs_profile_create(int event_num, char *event_name);
extern void cvmcs_profile_mark_event(int event_num);
extern void cvmcs_profile_mark_timed_event(int event_num, uint64_t base_cycle);
extern void cvmcs_profile_print_stats(void);
extern uint64_t cvmcs_profile_start(void);

#else

static inline void cvmcs_profile_initialize(void) { return; }
static inline void cvmcs_profile_init_local(void) { return; }
static inline int  cvmcs_profile_create(int event_num, char *event_name) { return 0; }
static inline void cvmcs_profile_mark_event(int event_num) { return; }
static inline void cvmcs_profile_mark_timed_event(int event_num, uint64_t base_cycle) { return; }
static inline void cvmcs_profile_print_stats(void) { return; }
static inline uint64_t cvmcs_profile_start(void) { return 0; }



#endif

