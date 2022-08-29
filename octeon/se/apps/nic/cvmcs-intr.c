
#include "cvmx.h"
#include "cvmx-helper.h"
#include "cvmx-interrupt.h"
#include "cvmx-pemx-defs.h"
#include "cvm-driver-defs.h"
#include "cvmcs-nic.h"
#include "cvmx-error-arrays-cn78xx.h"

#define SLI_INSTN_MAJOR         0x1f
#define CVM_SLI_INTSN_M0P0_FLR  0x1f001
#define CVM_SLI_INTSN_M0V0_FLR  0x1f002
#define CVM_SLI_INTSN_M0P1_FLR  0x1f003
#define CVM_SLI_INTSN_M0V1_FLR  0x1f004
#define CVM_SSO_INTSN_AQ_THR_BASE 0x60000
#define SSO_HIGH_THRESHOLD 16384
#define SSO_LOW_THRESHOLD  12288

#define CVM_CIU_INTSN_WDOGX     0x1200

#define CVM_MAX_INTR_COUNT      37

#define cvm_intr_register(__intsn, __intr_handler) \
        do {                    \
            int32_t __index; \
            cvmx_ciu3_iscx_w1c_t    ciu_ctl_w1c; \
            __index = cvmx_atomic_fetch_and_add32(&cvm_intr_tbl_index, 1); \
            /* clear the raw bit prior to enabling intsn */ \
            ciu_ctl_w1c.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1C(__intsn)); \
            ciu_ctl_w1c.s.raw   = 1; \
            cvmx_write_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1C(__intsn), ciu_ctl_w1c.u64); \
            cvm_intr_handler_tbl[__index].irq.handler = __intr_handler;     \
            cvm_intr_handler_tbl[__index].intsn = __intsn;      \
            cvmx_interrupt_register(cvm_intr_handler_tbl[__index].intsn, &cvm_intr_handler_tbl[__index].irq);   \
            cvm_intr_handler_tbl[__index].irq.unmask(&cvm_intr_handler_tbl[__index].irq);    \
        } while(0);

#define cvm_intr_register_core(__intsn, __intr_handler, __core_id) \
        do {                    \
            int32_t __index; \
            __index = cvmx_atomic_fetch_and_add32(&cvm_intr_tbl_index, 1); \
            cvm_intr_handler_tbl[__index].irq.node = 0; \
            cvm_intr_handler_tbl[__index].irq.handler = __intr_handler;     \
            cvm_intr_handler_tbl[__index].intsn = __intsn;      \
            cvmx_interrupt_register(cvm_intr_handler_tbl[__index].intsn, &cvm_intr_handler_tbl[__index].irq);   \
            cvm_intr_handler_tbl[__index].irq.unmaskoncore(&cvm_intr_handler_tbl[__index].irq, __core_id);    \
        } while(0);


//extern CVMX_SHARED  cvm_oct_pci_func_info_t   *pci_func_info_ptr;

extern CVMX_SHARED octnic_dev_t *octnic;
extern CVMX_SHARED uint32_t     num_cores;
extern CVMX_SHARED    uint64_t  cpu_freq;

static int
cn73xx_schedule_flr_intr_handler_cont( cvmx_wqe_t *wqe, enum flr_bh_event event,
				int ifidx, uint64_t tstamp, int time_us);
static enum flr_bh_event
cn73xx_flr_intr_handler_bh_cont(int ifidx, enum flr_bh_event event, uint64_t tstamp, uint64_t latency);

#define CVM_SDK_CN73XX_ERR_TBL_SIZE              1534  
#define CVM_INTERNAL_CN73XX_ERR_TBL_SIZE  	 16	
#define INTR_DISPLAY_INTERVAL     		 1

typedef struct cvm_intr_tbl {
    struct cvmx_interrupt irq;
    uint32_t intsn;
} cvm_intr_handler_t;


typedef struct cvm_error_intr_tbl {
	uint32_t intsn;
	char 	*err_mesg;
	uint64_t address;
	uint16_t reg;
	uint16_t tblindex;  //index into sdk error_array_cn73xx 
	uint32_t count;
}cvm_error_intr_tbl_t;

struct cvm_error_intr_tbl cvm_error_array_cn73xx[CVM_INTERNAL_CN73XX_ERR_TBL_SIZE] = {
        { 0xe2102,   "Error: CVMX_BGX2_SPU000_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(0,2),2,0,0}      ,
        { 0xe2104,   "Error: CVMX_BGX2_SPU000_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(0,2),4,0,0}      ,
        { 0xe2142,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),2,0,0}      ,
        { 0xe2143,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),3,0,0}      ,
        { 0xe2144,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),4,0,0}      ,      
        { 0xe2145,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),5,0,0}      ,      
        { 0xe2147,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),7,0,0}      ,      
        { 0xe2148,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),8,0,0}      ,      
        { 0xe2149,   "Error: CVMX_BGX2_SPU001_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(1,2),9,0,0}      ,      
        { 0xe2182,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),2,0,0}      ,      
        { 0xe2183,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),3,0,0}      ,      
        { 0xe2184,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),4,0,0}      ,      
        { 0xe2185,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),5,0,0}      ,      
        { 0xe2187,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),7,0,0}      ,      
        { 0xe2188,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),8,0,0}      ,      
        { 0xe2189,   "Error: CVMX_BGX2_SPU002_INT[%llx][%u]",CVMX_BGXX_SPUX_INT(2,2),9,0,0}      ,      
};

CVMX_SHARED int32_t cvm_intr_tbl_index = 0;
CVMX_SHARED cvm_intr_handler_t  cvm_intr_handler_tbl[CVM_MAX_INTR_COUNT];

extern 
int cvmcs_common_add_task(uint64_t  interval, int (* fn)(void *), void *fn_arg);

int dump_cn73x_regs();

/* Used to handle special errors and take control from SDK.
 * This is to offset few issues like: CPU being hogged by the 
 * BGX syn-los and rcv-flt interrupts which for some reason
 * gets triggered lot of times on link pullout.
 */
void cvm_error_intr_handler(struct cvmx_interrupt *intr, uint64_t *registers)
{
	int index = 0;
	cvm_intr_handler_t *irq_handler;

	irq_handler = (cvm_intr_handler_t *)intr;
	for (index = 0; index < CVM_INTERNAL_CN73XX_ERR_TBL_SIZE; index++) {
		if (cvm_error_array_cn73xx[index].intsn == irq_handler->intsn) {
			/* keep track of count and all the bits */
			cvm_error_array_cn73xx[index].count++;
			return;
		}
	}

	/* if we are here, maybe its not ours */
	cvmx_error_intsn_display_v3(cvmx_get_node_num(), irq_handler->intsn); 
}

/* Clear the interrupts noted down earlier if last check time exceed the 
 * interval
 */
int cvm_handle_pending_error_intr(uint64_t cur_cycle)
{
	char error_msg[512];
	int index = 0;
	cvm_error_intr_tbl_t  *err_tbl = NULL;
	int table_size = 0;
	static uint64_t last_check_time = 0;

	if ((cur_cycle - last_check_time) <= (cpu_freq * INTR_DISPLAY_INTERVAL))
		return 0;

	last_check_time = cur_cycle;

	if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {	
		err_tbl = cvm_error_array_cn73xx; 
		table_size = CVM_INTERNAL_CN73XX_ERR_TBL_SIZE;	
	}

	/* go through all the errors and clear them */
	for(index = 0; index < table_size; index++) {
		/* if pending count is not zero and interrupt display time
		 * has exceeded, print
		 */
		if (err_tbl[index].count) {
			snprintf(error_msg, sizeof(error_msg),
				 err_tbl[index].err_mesg,
				 err_tbl[index].address,
				 err_tbl[index].reg);
			DBG2("%s count %d\n", error_msg, err_tbl[index].count);

			err_tbl[index].count = 0;

			/* clear the interrupt */
			cvmx_write_csr_node(cvmx_get_node_num(),
					    cvm_error_array_cn73xx[index].address,
					    1ull << cvm_error_array_cn73xx[index].reg);
		}
	}

	return 0;
}

/*
 * This is the main handler function for FLR BH processing.
 * The interrupt handler (i.e. Top-Half) for FLR's is 'cn73xx_intr_handler()'.
 *
 * The FLR handling occurs in multiple stages.
 * When the FLR first occurs, it invokes the handler 'cn73xx_intr_handler()'.
 * Here, the first stage is scheduled in 'cn73xx_schedule_flr_intr_handler_bh',
 * which specifies event 'FLR_BH_START' (and eventually invokes THIS handler).
 *
 * For this event, the interface is marked as 'rx_on=0'
 * (see 'cvmcs_nic_if_reset_start'); then, a suitable delay (~95ms) is executed
 * to allow in-flight packets to be flushed.
 *
 * NOTE: this delay is implemented using a timer.
 * That is, after the interface is marked as OFF, a timer is scheduled
 * (see 'cn73xx_schedule_flr_intr_handler_cont').
 *
 * After the timer expires, THIS handler is again invoked
 * (with event 'FLR_BH_CONTINUE_INACTIVE/FLR_BH_CONTINUE_ACTIVE').
 * Then, the 2nd stage of the FLR BH executes 
 * (see 'cn73xx_flr_intr_handler_bh_cont')
 *
 * If the port was active at time of FLR (i.e. event 'FLR_BH_CONTINUE_ACTIVE'),
 * the interface reset is completed (see 'cvmcs_nic_if_reset_complete').
 *
 * For a PHYSICAL function (PF vs VF), one additional step is required to 
 * restore the device ID, which will have been reset as part of the FLR.
 * Per Greg Green (h/w team), the device will exit FLR between 66ms and 99ms
 * after FLR invocation.  This means that we must restore the device ID 99ms
 * after the FLR invocation.  To achieve this, another (final) event is used,
 * 'FLR_BH_FINALIZE'.
 *
 * So, this handler is [re]invoked with event 'FLR_BH_FINALIZE'.
 * This event is handled by 'cn73xx_flr_intr_handler_bh_cont'.
 * In the case of a VF, this event is ignored.
 *
 * NOTE: even though nothing is done in 'FLR_BH_FINALIZE' for a VF, the event
 * is still executed to maintain a consistent sequence of events (i.e. this
 * is the final event of an FLR and can therefore be used to 'cleanup').
 *
 * Finally, the STOPREQ bit is cleared to complete the FLR.
 *
 * This multi-stage implementation fixes the problem which occurs if too many 
 * FLRs occur in quick succession.  In such a case, using a 'spinning' wait
 * (i.e. cvmx_wait_usec) will stall some of the FLRs because all the cores are
 * spinning, completing their own FLR.
 * 
 * The stalled FLRs thus incur latency which extends the duration of the FLR,
 * which can cause problems because the host expects FLRs to complete within
 * 100ms (per PCIe spec). 
 *
 * NOTE: a spinning wait is used to deliver 'FLR_BH_FINALIZE' at the correct
 * time (due to insufficient timer resolution).  However, this does not cause
 * any problems because it is only used for PFs; therefore, the aforementioned
 * problem of too many simultaneous FLRs does not exist.
 *
 */
void cn73xx_flr_intr_handler_bh(cvmx_wqe_t * wqe)
{
#define adjust_wait_usecs_per_elapsed(_us, _start_cycles, _cycles_per_usec) \
	_us -= ((cvmx_clock_get_count(CVMX_CLOCK_CORE) - _start_cycles) / _cycles_per_usec);\
	_us++;

	uint32_t intsn;
	uint64_t pfx_flr_vf_int, tstamp;
	int pf_num, vf_num, ret, ifidx;
	uint32_t wait_usecs;
	cvmx_raw_inst_front_t *front;
	uint64_t cycles_per_usec;
	enum flr_bh_event bh_event;

	cycles_per_usec = cvmx_clock_get_rate(CVMX_CLOCK_CORE) / 1000000;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		front = (cvmx_raw_inst_front_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	/* return data area used to hold event timestamp */
	tstamp = front->rdp.u64;

	/* this holds an 'enum flr_bh_event', which determines the event to process */
	bh_event = front->irh.s.ossp;

	switch (bh_event) {
		case FLR_BH_START:
			/* this is the INITIAL BH event; continue in this function */
			break;

		case FLR_BH_CONTINUE_INACTIVE:
		case FLR_BH_CONTINUE_ACTIVE:
			/* this is a SUBSEQUENT BH event; invoke next function */
			if (cn73xx_flr_intr_handler_bh_cont((int)front->ossp[0], 
						bh_event, tstamp, front->ossp[1]) ==
			    FLR_BH_FINALIZE)
			{
				/* Here, we need to schedule the FINALIZE event.
				 * Normally, we would just schedule a timer to do this.
				 * However, the 'FINALIZE' event needs to be scheduled
				 * very accurately and our timer resolution is too
				 * low (see 'NIC_TIMER_PERIOD_US').
				 * So, we fill-in the WQE appropriately for scheduling
				 * the event, then wait (i.e. spin) the correct
				 * amount of time.  Afterwards, we manually re-invoke
				 * ourselves to execute the event.
				 * Using a spin instead of an interrupt doesn't cause
				 * any problems because this is only done for PFs,
				 * not for VFs (see FLR description above).
				 */

				wait_usecs = 99 * 1000;
				adjust_wait_usecs_per_elapsed(wait_usecs, tstamp, cycles_per_usec);
				if ((int32_t)wait_usecs < 1)
					wait_usecs = 0;
			} else {
				/* Here, we schedule the FLR_BH_FINALIZE event SOLELY
				 * for the purpose of maintaining a single event flow
				 * (even though the VF doesn't need it, we use it to
				 * perform 'cleanup').
				 */
				wait_usecs = 0;
			}

			ifidx = front->ossp[0];
			/* Invoke the scheduling routine with a time of 0 in order to
			 * [only] setup the WQE appropriately. */
			cn73xx_schedule_flr_intr_handler_cont( wqe, FLR_BH_FINALIZE,
								ifidx, tstamp, 0);

			/* If a delay is needed, wait here (see description above function) */
			if (wait_usecs)
				cvmx_wait_usec(wait_usecs);

			/* Finally, re-invoke ourselves to execute the next event */
			cn73xx_flr_intr_handler_bh(wqe);
			return;

		case FLR_BH_FINALIZE:
			cn73xx_flr_intr_handler_bh_cont((int)front->ossp[0], 
						bh_event, tstamp, front->ossp[1]);
			cvmx_fpa_free(wqe, CVMX_FPA_SMALL_BUFFER_POOL, 0);
			return;

		default:
			printf("Error: UNKNOWN FLR BH event! (0x%x)\n", bh_event);
			cvmx_fpa_free(wqe, CVMX_FPA_SMALL_BUFFER_POOL, 0);
			return;
	}

	intsn = front->ossp[0];
	pfx_flr_vf_int = front->ossp[1];

	/* PCIe requires FLR to complete in 100 ms (i.e. before clearing the STOPREQ bit).
	 * The 2nd half of FLR BH requires ~1-2ms (see cvmcs_nic_if_reset_complete()),
	 * so to be safe, we wait 95ms, which is MORE than sufficient to flush any
	 * in-flight packets.
	 */
	wait_usecs = 95 * 1000;

	switch (intsn) {

	case CVM_SLI_INTSN_M0P0_FLR: /* PF0 */
	case CVM_SLI_INTSN_M0P1_FLR: /* PF1 */
		pf_num = (intsn == CVM_SLI_INTSN_M0P0_FLR) ? 0 : 1;
		ifidx = OCT_NIC_PORT_IDX(pf_num, 0);
		ret = cvmcs_nic_if_reset_start(ifidx);
		bh_event = (ret == 0) ? FLR_BH_CONTINUE_ACTIVE : FLR_BH_CONTINUE_INACTIVE;
		adjust_wait_usecs_per_elapsed(wait_usecs, tstamp, cycles_per_usec);
		/* Fix for firmware crash when 'ESC' pressed during PXE boot.
		 * Ensure we don't get a negative (or huge positive) value; this could
		 * occur if 'cvmcs_nic_if_reset_start()' took longer than 95ms to execute
		 */
		if ((int32_t)wait_usecs < 1)
			wait_usecs = 0;
		ret = cn73xx_schedule_flr_intr_handler_cont( wqe, bh_event,
							ifidx, tstamp, wait_usecs);
		/* If wait time is 0 (see above) OR unable to schedule timer, manually
		 * re-invoke ourselves to process next stage/event (in WQE).
		 * In case of 'wait_time==0', the delay is a no-op.
		 */
		if ((wait_usecs == 0) || ret) {
			cvmx_wait_usec(wait_usecs);
			cn73xx_flr_intr_handler_bh(wqe);
		}
		break;

	case CVM_SLI_INTSN_M0V0_FLR: /* PF0's VFs */
	case CVM_SLI_INTSN_M0V1_FLR: /* PF1's VFs */
		pf_num = (intsn == CVM_SLI_INTSN_M0V0_FLR) ? 0 : 1;
		for (vf_num = 1; pfx_flr_vf_int; vf_num++, pfx_flr_vf_int >>= 1) {
			if (pfx_flr_vf_int & 1ULL) {
				ifidx = OCT_NIC_PORT_IDX(pf_num, vf_num);
				ret = cvmcs_nic_if_reset_start(ifidx);
				bh_event = (ret == 0) ? FLR_BH_CONTINUE_ACTIVE : FLR_BH_CONTINUE_INACTIVE;
				adjust_wait_usecs_per_elapsed(wait_usecs, tstamp, cycles_per_usec);
				/* Ensure we don't get a negative (or huge positive) value; this could
				 * occur if 'cvmcs_nic_if_reset_start()' took longer than 95ms to execute
				 */
				if ((int32_t)wait_usecs < 1)
					wait_usecs = 0;
				ret = cn73xx_schedule_flr_intr_handler_cont( wqe, bh_event,
									ifidx, tstamp, wait_usecs);
				/* If wait time is 0 (see above) OR unable to schedule timer, manually
				 * re-invoke ourselves to process next stage/event (in WQE).
				 * In case of 'wait_time==0', the delay is a no-op.
				 */
				if ((wait_usecs == 0) || ret) {
					cvmx_wait_usec(wait_usecs);
					cn73xx_flr_intr_handler_bh(wqe);
				}
			}
		}
		/* As part of the FLR, BP has been disabled for the VF's rings.
		 * Do not [re]enable BP via the SLI_PKT_OUT_BP_EN_W1S register here.
		 * We cannot write SLI_PKT registers because they require access to 
		 * SLI_PKT_CSR_CONTROL (which requires a lock).
		 * BP [re]enablement is handled when i/f is configured (cvmcs_nic_cfg_ioqueues)
		 */
		break;
	}
}

/* NOTE: if this routine changes, be sure to test failing cases (i.e. when return value != 0)
 *
 * This is used by the stage1 FLR BH to schedule the stage2 BH.
 *
 * on entry,
 *         wqe:     WQE to use for scheduling timer
 *         event:   the particular event to schedule
 *         ifidx:   interface
 *         tstamp:  original FLR timestamp
 *         time_us: amount of time in future to schedule next BH (delay time in usecs)
 *                  If 0, simply fill-in the wqe and return; used by the caller to immediately
 *                  execute next BH (i.e don't schedule it).
 *
 * returns,
 *         0: OK
 *         1: error scheduling timer for BH 2nd-stage
 */
static int
cn73xx_schedule_flr_intr_handler_cont(cvmx_wqe_t *wqe, enum flr_bh_event event,
				int ifidx, uint64_t tstamp, int time_us)
{	
	cvmx_raw_inst_front_t *front;
	uint64_t expiration, latency;

	latency = cvmx_clock_get_count(CVMX_CLOCK_CORE) - tstamp;

	if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
		front = (cvmx_raw_inst_front_t *)cvmx_phys_to_ptr(cvmx_wqe_get_pki_pkt_ptr(wqe).addr);
	else
		front = (cvmx_raw_inst_front_t *)wqe->packet_data;

	memset(front, 0, sizeof(cvmx_raw_inst_front_t));
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_FLR_BH_OP;
	front->irh.s.ossp = event;
	front->ossp[0] = ifidx;
	front->ossp[1] = latency;
	/* Return data area used to hold event timestamp.
	 * This is to be consistent with 'FLR_BH_START'.
	 */
	front->rdp.u64 = tstamp;

	/* caller specified NOT to schedule, simply return with wqe filled-in */
	if (time_us == 0)
		return 0;

	expiration = (time_us / NIC_TIMER_PERIOD_US);
	if (cvmx_tim_add_entry(wqe, expiration, NULL) != CVMX_TIM_STATUS_SUCCESS) {
		printf("FLR timer add failed\n");
		return 1;
	}

	return 0;
}

/*
 * This implements the 2nd stage of the FLR BH.
 *
 * on entry,
 *        ifidx:    interface
 *        event:    FLR_BH_CONTINUE_ACTIVE or FLR_BH_CONTINUE_INACTIVE
 *                  this indicates whether the interface was active or inactive at the time of FLR
 *         tstamp:  original FLR timestamp
 *         latency: latency between FLR interrupt and scheduling of BH event
 */
static enum flr_bh_event 
cn73xx_flr_intr_handler_bh_cont(int ifidx, enum flr_bh_event event, uint64_t tstamp, uint64_t latency)
{
	int pf_num, vf_num;
	uint64_t val, elapsed_us, cycles_per_usec;

	cycles_per_usec = cvmx_clock_get_rate(CVMX_CLOCK_CORE) / 1000000;
	elapsed_us = 0;

	pf_num = OCT_NIC_PORT_PF(ifidx);
	if (OCT_NIC_IS_PF(ifidx)) {
		if (event == FLR_BH_CONTINUE_ACTIVE)
			cvmcs_nic_if_reset_complete(ifidx);

		if ((event == FLR_BH_CONTINUE_ACTIVE) ||
		    (event == FLR_BH_CONTINUE_INACTIVE)) {

			elapsed_us = (cvmx_clock_get_count(CVMX_CLOCK_CORE) - tstamp) / cycles_per_usec;

			/* instruct caller to schedule an FLR continuation event */
			return FLR_BH_FINALIZE;

		} else if (event == FLR_BH_FINALIZE)
		{

			cvmcs_nic_if_reset_finalize(ifidx);

			elapsed_us = (cvmx_clock_get_count(CVMX_CLOCK_CORE) - tstamp) / cycles_per_usec;
			cvmx_write_csr_node(cvmx_get_node_num(),
						CVMX_SPEMX_FLR_PF_STOPREQ(0),
						1ULL << pf_num);

			/* 
			 * Clear the RINFO register BEFORE 'cvm_drv_restart_pf'.
			 * The RINFO reg can be evaluated during the 'cvm_drv_restart_pf' callback.
			 */
			cvmx_write_csr(CVMX_PEXP_SLI_PKT_MACX_PFX_RINFO(pf_num, 0), 0ULL);

			/* invoke the core restart function LAST */
			cvm_drv_restart_pf(pf_num);
		} else {
			/* should NEVER get here! */
			printf("Error: unknown FLR BH continuation event %u\n", event);
		}
	} else {
		/* nothing is done for a VF in this phase, return. */
		if (event == FLR_BH_FINALIZE)
			return FLR_BH_COMPLETED;

		if (event == FLR_BH_CONTINUE_ACTIVE)
			cvmcs_nic_if_reset_complete(ifidx);

		elapsed_us = (cvmx_clock_get_count(CVMX_CLOCK_CORE) - tstamp) / cycles_per_usec;
		vf_num = OCT_NIC_PORT_VF(ifidx);
		val = 1ULL << (vf_num-1);
		if (pf_num == 0) {
			cvmx_write_csr_node(cvmx_get_node_num(),
					CVMX_SPEMX_FLR_PF0_VF_STOPREQ(0), val);
		} else {
			cvmx_write_csr_node(cvmx_get_node_num(),
					CVMX_SPEMX_FLR_PF1_VF_STOPREQ(0), val);
		}

		/* As part of the FLR, BP has been disabled for the VF's rings.
		 * Do not [re]enable BP via the SLI_PKT_OUT_BP_EN_W1S register here.
		 * We cannot write SLI_PKT registers because they require access to 
		 * SLI_PKT_CSR_CONTROL (which requires a lock).
		 * BP [re]enablement is handled when i/f is configured (cvmcs_nic_cfg_ioqueues)
		 */
	}

	/* display warning message to catch code changes
	 * which increase FLR duration beyond PCIe max 100ms */
	if ((int)elapsed_us > 100000) {
		printf("Error: FLR duration %uus exceeded maximum\n",
			(int)elapsed_us);
	}

	return FLR_BH_COMPLETED;
}

/*
 * This schedules the stage1 FLR BH upon receipt of an FLR interrupt.
 * A WQE with OPCODE_NIC/OCT_NIC_FLR_BH_OP will be queued, and will subsequently
 * be handled by 'cn73xx_flr_intr_handler_bh().'
 */
static void
cn73xx_schedule_flr_intr_handler_bh(uint32_t intsn, uint64_t pfx_flr_vf_int, uint64_t tstamp)
{
	cvmx_raw_inst_front_t *front;
	cvmx_wqe_78xx_t *wqe_o3;

	wqe_o3 = cvmx_fpa_alloc(CVMX_FPA_SMALL_BUFFER_POOL);
	if (!wqe_o3) {
		cvmcs_printf("%s: cvmx_fpa_alloc failed; cannot schedule bottom half\n", __FUNCTION__);
		return;
	}

	wqe_o3->word2.software = 1;
	front = (cvmx_raw_inst_front_t *)wqe_o3->wqe_data;
	wqe_o3->packet_ptr.packet_outside_wqe = 0;
	wqe_o3->packet_ptr.addr = cvmx_ptr_to_phys(front);
	wqe_o3->word0.bufs = 0;
	wqe_o3->word0.aura = CVMX_FPA_SMALL_BUFFER_POOL;
	front->irh.s.opcode = OPCODE_NIC;
	front->irh.s.subcode = OCT_NIC_FLR_BH_OP;
	front->irh.s.ossp = FLR_BH_START;
	front->ossp[0] = intsn;
	front->ossp[1] = pfx_flr_vf_int;
	/* use return data area to pass timestamp */
	front->rdp.u64 = tstamp;

	/* TODO: set these appropriately */
	cvmx_wqe_set_qos((cvmx_wqe_t *)wqe_o3, 0);
	cvmx_wqe_set_tt((cvmx_wqe_t *)wqe_o3, CVMX_POW_TAG_TYPE_NULL);
	cvmx_wqe_set_tag((cvmx_wqe_t *)wqe_o3, 0);
	cvmx_wqe_set_grp((cvmx_wqe_t *)wqe_o3, 0);

	CVMX_SYNCWS;

	cvmx_pow_work_submit((cvmx_wqe_t *)wqe_o3,
				cvmx_wqe_get_tag((cvmx_wqe_t *)wqe_o3),
				cvmx_wqe_get_tt((cvmx_wqe_t *)wqe_o3),
				cvmx_wqe_get_qos((cvmx_wqe_t *)wqe_o3),
				cvmx_wqe_get_grp((cvmx_wqe_t * )wqe_o3));
}

void
cn73xx_sso_intr_handler(struct cvmx_interrupt *intr, uint64_t *registers)
{
	cvm_intr_handler_t *irq_handler;
	uint32_t intsn;
	uint32_t group;
	uint64_t prev_threshold;
	int channels_per_pkind = 64;
	int i, pkind, style;
	int num_clusters =2;
	int interface, index, cluster;
	cvmx_pki_clx_pkindx_style_t pkind_cfg_style;

	irq_handler = (cvm_intr_handler_t *)intr;
	intsn = irq_handler->intsn;
	group = intsn - CVM_SSO_INTSN_AQ_THR_BASE;
	/* only worry about group 0 */
	if (group != 0) {
		cvmcs_printf("%s: error invalid group number\n", __FUNCTION__);
		return;
	}

	prev_threshold = cvmx_read_csr(CVMX_SSO_GRPX_AQ_THR(group));
	if (prev_threshold == SSO_HIGH_THRESHOLD) {
		cvmcs_printf("%s: sso high threshold\n", __FUNCTION__);
		cvmx_write_csr(CVMX_SSO_GRPX_AQ_THR(group),
			       SSO_LOW_THRESHOLD);
		/* drop DPI */
		for ( i = 0; i < 2; i++) {
			pkind = cvmx_helper_get_pknd(cvmx_helper_get_interface_num(0x100), i*channels_per_pkind);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr(CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;
				cvmx_write_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster),
					       ((cvmx_read_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster))) |
					        (0x1ULL << 20)));
			}
		}
		/* drop BGX */
		for ( i = 0; i < 2; i++) {
			interface = cvmx_helper_get_interface_num(0xa00 + (i << 4));
			index = cvmx_helper_get_interface_index_num(0xa00 + (i << 4));
			pkind = cvmx_helper_get_pknd(interface, index);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr(CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;
				cvmx_write_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster),
					       ((cvmx_read_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster))) |
					        (0x1ULL << 20)));
			}
		}
		cvmx_write_csr(CVMX_SSO_GRPX_INT(group), 0x1ULL);
		return;
	} else if (prev_threshold == SSO_LOW_THRESHOLD) {
		cvmcs_printf("%s: sso low threshold\n", __FUNCTION__);
		cvmx_write_csr(CVMX_SSO_GRPX_AQ_THR(group),
			       SSO_HIGH_THRESHOLD);
		/* Enable DPI */
		for ( i = 0; i < 2; i++) {
			pkind = cvmx_helper_get_pknd(cvmx_helper_get_interface_num(0x100), i*channels_per_pkind);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr(CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;
				cvmx_write_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster),
					       ((cvmx_read_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster))) &
					        (~(0x1ULL << 20))));
			}
		}
		/* Enable BGX */
		for ( i = 0; i < 2; i++) {
			interface = cvmx_helper_get_interface_num(0xa00 + (i << 4));
			index = cvmx_helper_get_interface_index_num(0xa00 + (i << 4));
			pkind = cvmx_helper_get_pknd(interface, index);
			for (cluster = 0; cluster < num_clusters; cluster++) {
				/* Get STYLE for the PKIND */
				pkind_cfg_style.u64 = cvmx_read_csr(CVMX_PKI_CLX_PKINDX_STYLE(pkind, cluster));
				style = pkind_cfg_style.s.style;
				cvmx_write_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster),
					       ((cvmx_read_csr(CVMX_PKI_CLX_STYLEX_CFG(style, cluster))) &
					        (~(0x1ULL << 20))));
			}
		}
		cvmx_write_csr(CVMX_SSO_GRPX_INT(group), 0x1ULL);
		return;
	}
	/* should not come here */
	cvmcs_printf("%s: error invalid threshold value\n", __FUNCTION__);
}

void
cn73xx_intr_handler(struct cvmx_interrupt *intr, uint64_t *registers)
{
#define CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER cvmx_write_csr_node(cvmx_get_node_num(), CVMX_ADD_IO_SEG(0x00011F0000027100ull), 1ULL<<(intsn&0xf));
	cvm_intr_handler_t *irq_handler;
	uint32_t intsn;
	uint64_t pf0_flr_vf_int, pf1_flr_vf_int;
	uint64_t cycles;

	cycles = cvmx_clock_get_count(CVMX_CLOCK_CORE);

	pf0_flr_vf_int = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(0,0));
	pf1_flr_vf_int = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(1,0));

	irq_handler = (cvm_intr_handler_t *)intr;
	intsn = irq_handler->intsn;

	switch (intsn) {
	case CVM_SLI_INTSN_M0P0_FLR: /* PF0 */
	case CVM_SLI_INTSN_M0P1_FLR: /* PF1 */
		CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER;
		cn73xx_schedule_flr_intr_handler_bh(intsn, 0, cycles);
		break;

	case CVM_SLI_INTSN_M0V0_FLR: /* PF0's VFs */
		if (pf0_flr_vf_int) {
			CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER;
			cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(0,0), pf0_flr_vf_int);
			cn73xx_schedule_flr_intr_handler_bh(intsn, pf0_flr_vf_int, cycles);
		} else {
			CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER;
			cvmcs_printf("SLI_MAC0_PF0_FLR_VF_INT is 0. I don't know which VF did an FLR.\n");
		}
		break;

	case CVM_SLI_INTSN_M0V1_FLR: /* PF1's VFs */
		if (pf1_flr_vf_int) {
			CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER;
			cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(1,0), pf1_flr_vf_int);
			cn73xx_schedule_flr_intr_handler_bh(intsn, pf1_flr_vf_int, cycles);
		} else {
			CLEAR_BIT_IN_SLI_CIU_INT_SUM_REGISTER;
			cvmcs_printf("SLI_MAC0_PF1_FLR_VF_INT is 0. I don't know which VF did an FLR.\n");
		}
		break;
	}
}

void
cn73xx_wdog_intr_handler(struct cvmx_interrupt *intr, uint64_t *registers)
{
	extern void cvmcs_nic_fwdump_after_watchdog_timeout(uint64_t *registers);
	cvmcs_nic_fwdump_after_watchdog_timeout(registers);
	while (1) {}
}

void
cn73xx_intr_config( void)
{
    unsigned core_num;
    int __attribute__ ((unused)) intsn = 0, index = 0, i;
    cvmx_sli_ciu_int_enb_t  sli_ciu_int_enb;
#ifdef OCTEON_DEBUG_LEVEL
    cvmx_ciu3_iscx_ctl_t    ciu_ctl;
    cvmx_ciu3_iscx_w1s_t    ciu_ctl_w1s;
#endif
	cvmx_spemx_flr_pf_stopreq_t cvmx_pf_stopreq;

	/* Fix for DPDK driver when using vfio-pci; the vfio-pci driver
	 * will issue an FLR before our firmware is loaded.  This
	 * results in the STOPREQ bit being set, which will prevent
	 * the host driver from bus-mastering using the PF.
	 * This was seen on CentOS 7.1/7.2.
	 *
	 * Check for PF0/PF1 STOPREQ; if set, clear it.
	 *
	 */
	cvmx_pf_stopreq.u64 =
		cvmx_read_csr_node(cvmx_get_node_num(), CVMX_SPEMX_FLR_PF_STOPREQ(0));
	if (cvmx_pf_stopreq.s.pf0_stopreq || cvmx_pf_stopreq.s.pf1_stopreq) {
		cvmx_pf_stopreq.u64 = 0;
		cvmx_pf_stopreq.s.pf0_stopreq = cvmx_pf_stopreq.s.pf1_stopreq = 1;
		cvmx_write_csr_node(cvmx_get_node_num(), CVMX_SPEMX_FLR_PF_STOPREQ(0), cvmx_pf_stopreq.u64);
		printf("Found PF0/1 STOPREQ set (0x%x); clearing...\n", (int)cvmx_pf_stopreq.u64);
	}

#if 0
    cvmx_ciu3_iscx_w1c_t    ciu_ctl_w1c;
    DBG_PRINT(DBG_FLOW, "%s; Before Configuring the CIU int regs for sli\n", __FUNCTION__);
    for(intsn = CVM_SLI_INTSN_M0P0_FLR; intsn <= CVM_SLI_INTSN_M0V1_FLR ;  intsn++) { 
        ciu_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_CTL(intsn));
        ciu_ctl_w1c.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1C(intsn));
        ciu_ctl_w1s.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1S(intsn));
        DBG_PRINT(DBG_FLOW, "Before: intsn: 0x%016x, ctl: 0x%016lx, w1c: 0x%016lx, w1s: 0x%016lx\n", intsn, ciu_ctl.u64, ciu_ctl_w1c.u64, ciu_ctl_w1s.u64);
    }
#endif

    //Register handlers for CIU interrupts for SLI.
    cvm_intr_register(CVM_SLI_INTSN_M0P0_FLR, cn73xx_intr_handler);

    cvm_intr_register(CVM_SLI_INTSN_M0V0_FLR, cn73xx_intr_handler);

    cvm_intr_register(CVM_SLI_INTSN_M0P1_FLR, cn73xx_intr_handler);

    cvm_intr_register(CVM_SLI_INTSN_M0V1_FLR, cn73xx_intr_handler);

    //Enable the in the ciu_int_enb registers
    //sli_ciu_int_enb.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_CIU_INT_ENB);
    sli_ciu_int_enb.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_ADD_IO_SEG(0x00011F0000027110ull));  //Addr for SLI_CIU_INT_ENB as per HRM 
    sli_ciu_int_enb.s.m0p0_flr = 1;
    sli_ciu_int_enb.s.m0v0_flr = 1;
    sli_ciu_int_enb.s.m0p1_flr = 1;
    sli_ciu_int_enb.s.m0v1_flr = 1;
    //cvmx_write_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_CIU_INT_ENB, sli_ciu_int_enb.u64);
    cvmx_write_csr_node(cvmx_get_node_num(), CVMX_ADD_IO_SEG(0x00011F0000027110ull), sli_ciu_int_enb.u64);

#ifdef OCTEON_DEBUG_LEVEL
    DBG_PRINT(DBG_FLOW, "%s: After Configuring the CIU int regs for sli\n", __FUNCTION__);
    for(intsn = CVM_SLI_INTSN_M0P0_FLR; intsn <= CVM_SLI_INTSN_M0V1_FLR ;  intsn++) { 
        ciu_ctl.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_CTL(intsn));
        ciu_ctl_w1c.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1C(intsn));
        ciu_ctl_w1s.u64 = cvmx_read_csr_node(cvmx_get_node_num(), CVMX_CIU3_ISCX_W1S(intsn));
        DBG_PRINT(DBG_FLOW, "intsn: 0x%016x, ctl: 0x%016lx, w1c: 0x%016lx, w1s: 0x%016lx\n", intsn, ciu_ctl.u64, ciu_ctl_w1c.u64, ciu_ctl_w1s.u64);
    }

    DBG_PRINT(DBG_FLOW, "SLI_CIU_INT_ENB: 0x%016lx\n",
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_ADD_IO_SEG(0x00011F0000027110ull)));
    DBG_PRINT(DBG_FLOW, "SLI_CIU_INT_SUM: 0x%016lx\n",
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_ADD_IO_SEG(0x00011F0000027100ull)));
    DBG_PRINT(DBG_FLOW, "FLR_PF_STOP_REQ[0x%016llx]: 0x%016lx\n",
	      CVMX_SPEMX_FLR_PF_STOPREQ(0),
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_SPEMX_FLR_PF_STOPREQ(0)));
    DBG_PRINT(DBG_FLOW, "PEM_FLR_PF1_STOP_REQ[0x%016llx]: 0x%016lx\n",
	      CVMX_SPEMX_FLR_PF1_VF_STOPREQ(0),
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_SPEMX_FLR_PF1_VF_STOPREQ(0)));
    DBG_PRINT(DBG_FLOW, "PEM_FLR_PF0_STOP_REQ[0x%016llx]: 0x%016lx\n",
	      CVMX_SPEMX_FLR_PF0_VF_STOPREQ(0),
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_SPEMX_FLR_PF0_VF_STOPREQ(0)));
    DBG_PRINT(DBG_FLOW, "PF0_SLI_VF_INT[0x%016llx]: 0x%016lx\n",
	      CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(0,0),
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(0,0)));
    DBG_PRINT(DBG_FLOW, "PF0_SLI_VF_INT[0x%016llx]: 0x%016lx\n",
	      CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(1,0),
	      cvmx_read_csr_node(cvmx_get_node_num(), CVMX_PEXP_SLI_MACX_PFX_FLR_VF_INT(1,0)));
#endif

#if defined(OVS_IPSEC)
    for (core_num=2; core_num < 12; core_num++)
#else
#if defined (VSWITCH)
    for (core_num=(unsigned)CVMCS_FIRST_CORE; core_num <= (unsigned)CVMCS_LAST_CORE; core_num++)
#else
    for (core_num=0; core_num < num_cores; core_num++)
#endif
#endif
        cvm_intr_register_core(CVM_CIU_INTSN_WDOGX + core_num, cn73xx_wdog_intr_handler, core_num);

    /* change handlers for certain interrupts to handle them better */
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
	    for(index=0; index<CVM_INTERNAL_CN73XX_ERR_TBL_SIZE; index++) {
		    /* register for the interrupt */ 
		    cvm_intr_register(cvm_error_array_cn73xx[index].intsn,
				      cvm_error_intr_handler);
	    }
    }
    /* SSO AQ interrupt thresholds for group 0*/
    cvmx_write_csr(CVMX_SSO_GRPX_AQ_THR(0), SSO_HIGH_THRESHOLD);
    cvm_intr_register(CVM_SSO_INTSN_AQ_THR_BASE, cn73xx_sso_intr_handler);
}


/* This is run on every core. */
void
cn73xx_local_intr_config( void)
{
    int index = 0, cn73xx_errindex = 0;

    /* change handlers for certain interrupts to handle them better */
    if (OCTEON_IS_MODEL(OCTEON_CN73XX)) {
	    for(index=0; index<CVM_INTERNAL_CN73XX_ERR_TBL_SIZE; index++) {
		    /* Find the error table and modify it. Otherwise the
		     * interrupts will be re-routed to ip4 whenever
		     * cvmx_helper_link_autoconf occurs.
		     */
		    for(; cn73xx_errindex<CVM_SDK_CN73XX_ERR_TBL_SIZE; cn73xx_errindex++) {
			    if(cvm_error_array_cn73xx[index].intsn == error_array_cn73xx[cn73xx_errindex].intsn) {
				    cvm_error_array_cn73xx[index].tblindex = cn73xx_errindex;
				    error_array_cn73xx[cn73xx_errindex].error_group = CVMX_ERROR_GROUP_INTERNAL;
				    break;
			    }
		    }
	    }
    }
}

/***********************  Reg Dump Functions ****************************/
static inline void
__print_regs_in_range(unsigned long long  start,
                      unsigned long long  end,
                      int                 offset,
                      char               *str)
{
	uint64_t  reg = start;
	int node = cvmx_get_node_num();
	while(reg <= end) {
		printf("%s[0x%016lx]:  0x%016lx\n", str, reg,
			 cvmx_read_csr_node(node, CVMX_ADD_IO_SEG(reg)));
		reg += offset;
	}
}

int 
dump_cn73xx_dpi_regs() 
{
    unsigned long long  base = 0x0001df0000000000ULL;
    printf("\n ---- Dumping CN73xx DPI registers \n");

    __print_regs_in_range(base, base + 0xc80, 0x8, "DPI");   

    return 0;
}   

int
dump_cn73x_regs()
{
    dump_cn73xx_dpi_regs();
return 0;
}    
