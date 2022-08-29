
#include "cvmcs-profile.h"

#if defined(ENABLE_PROFILING)

#define MAX_PROFILE_NAME_LEN 32

/* Profile names are not part of the structure monitoring the cycle count
   and iterations. This helps keep the critical structure compact. */
static CVMX_SHARED char profile_name[MAX_PROFILES][MAX_PROFILE_NAME_LEN] __attribute__((__aligned__(128) ));


struct cvmcs_profile {

	uint64_t iter;
	uint64_t cycles;

};


/* This is a per-core structure. Each core will have MAX_PROFILES entries.
 */
struct cvmcs_profiles {

	struct cvmcs_profile          prof[MAX_PROFILES];

} __attribute__((__aligned__(128) ));



/* The profiling structure */
CVMX_SHARED  struct cvmcs_profiles      nic_profiles[MAX_CORES];
CVMX_SHARED  int64_t prof_core_mask = 0;

/* Per-core base cycle counter. This needs to be initialized for
   every iteration. */
uint64_t base_profile_cycle = 0;
uint64_t prof_core_id = -1;


static inline int profile_enabled_for_core(int core_id)
{
	return ((uint64_t)cvmx_atomic_get64(&prof_core_mask) & (1 << core_id));
}



/* All profiling for a packet starts after the base cycle is noted. Call this
 * function to set the start time for the profiling of a packet. This value
 * is not retained for the packet if it switches context via a tag switch, PKO
 * send etc. */
uint64_t cvmcs_profile_start(void)
{
	base_profile_cycle = cvmx_get_cycle();
	return base_profile_cycle;
}




/* Routine to track a profiling event. 
 * Counts the amount of time between now and base_cycle provided.
 * NOTE: This function itself takes about 10 cycles.
 */
void cvmcs_profile_mark_timed_event(int event_num, uint64_t base_cycle)
{
	if(prof_core_id != (uint64_t)-1 && prof_core_id < MAX_CORES) {
		nic_profiles[prof_core_id].prof[event_num].cycles += cvmx_get_cycle() - base_cycle;
		nic_profiles[prof_core_id].prof[event_num].iter++;
	}

	/* Assumes there is a CVMX_SYNCWS later */
}




/* Routine to track a profiling event. 
 * Counts the amount of time between now and base_cycle, when we got the WQE.
 * NOTE: This function itself takes about 10 cycles.
 */
void cvmcs_profile_mark_event(int event_num)
{
	if(prof_core_id != (uint64_t)-1 && prof_core_id < MAX_CORES) {
		nic_profiles[prof_core_id].prof[event_num].cycles += cvmx_get_cycle() - base_profile_cycle;
		nic_profiles[prof_core_id].prof[event_num].iter++;
	}

	/* Assumes there is a CVMX_SYNCWS later */
}




/* Routine to print statistics collected via profiling. 
 */
void cvmcs_profile_print_stats()
{
	unsigned i, j;
	uint64_t result, cnt;

	for (i=0; i < MAX_PROFILES; i++) {
		if(strlen(profile_name[i]) == 0)
			continue;

		DBG2("%s: ", profile_name[i]);

		for (j=0; j < MAX_CORES; j++) {
			if (profile_enabled_for_core(j)) {
				cnt = nic_profiles[j].prof[i].iter;
				if (cnt)
					result = nic_profiles[j].prof[i].cycles / cnt;
				else
					result = 0;
				nic_profiles[j].prof[i].cycles = 0;
				nic_profiles[j].prof[i].iter = 0;
				if (result)
					DBG2("%d:%3u ", j, (unsigned)result);
			}
		}
		DBG2("\n");
	}
}




/* Routine to create a profile event to be tracked for this application
 */
int cvmcs_profile_create(int event_num, char *event_name)
{
	unsigned int i;

	if(event_num >= MAX_PROFILES) {
		printf("%s:%d: Failed to create profile [event num %d exceeds max %d]\n",
		        __FUNCTION__, __LINE__, event_num, MAX_PROFILES);
		return 1;
	}

	printf("%s:%d: [event num %d event_name %s]\n",
		__FUNCTION__, __LINE__, event_num, event_name);
	strncpy(profile_name[event_num], event_name, MAX_PROFILE_NAME_LEN);

	for (i = 0; i < MAX_CORES; i++) {
		nic_profiles[i].prof[event_num].iter = 0;
		nic_profiles[i].prof[event_num].cycles = 0;
	}

	CVMX_SYNCWS;

	return 0;
}



/* Every core participating in the profiling should call this function before
 * tracking the profiling events. 
 */
void cvmcs_profile_init_local(void)
{
	prof_core_id = cvmx_get_core_num();
	cvmx_atomic_fetch_and_bset64_nosync((uint64_t *)&prof_core_mask, (1 << prof_core_id));
	CVMX_SYNCWS;
}


void cvmcs_profile_initialize(void)
{
	memset(nic_profiles, 0, sizeof(nic_profiles));
	memset(profile_name, 0, MAX_PROFILES * MAX_PROFILE_NAME_LEN);
}

#endif
