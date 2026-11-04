// SPDX-License-Identifier: GPL-2.0-or-later
/* Verify that instance deletion cancels the tier-two GR selection timer. */

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>

#include "command.h"
#include "frr_pthread.h"
#include "frrevent.h"
#include "memory.h"
#include "privs.h"
#include "vrf.h"
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"

/* Satisfy libbgp link requirements. */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static bool tier2_fired;
static bool done;

static void tier2_expired(struct event *event)
{
	struct afi_safi_info *info = EVENT_ARG(event);

	tier2_fired = true;
	XFREE(MTYPE_TMP, info);
}

static void stop_loop(struct event *event)
{
	(void)event;
	done = true;
}

int main(void)
{
	as_t asn = 64512;
	struct bgp *bgp = NULL;
	struct afi_safi_info *info;
	struct event event;
	struct event *stop = NULL;

	qobj_init();
	cmd_init(1);
	zlog_aux_init("NONE: ", LOG_ERR);
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_option_set(BGP_OPT_NO_ZEBRA);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();
	zclient_stop(bgp_zclient);
	event_cancel(&bm->t_bgp_start_label_manager);
	event_cancel(&bm->t_bgp_sync_label_manager);

	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
		       ASNOTATION_PLAIN) == BGP_CREATED);
	info = XCALLOC(MTYPE_TMP, sizeof(*info));
	info->bgp = bgp;
	info->afi = AFI_IP6;
	info->safi = SAFI_UNICAST;
	info->tier2_gr = true;
	event_add_timer_msec(master, tier2_expired, info, 0,
			     &bgp->gr_info[AFI_IP6][SAFI_UNICAST].t_select_deferral_tier2);

	/* Keep the event's stored reference valid even when deletion misses it. */
	bgp_lock(bgp);
	assert(bgp_delete(bgp) == 0);
	assert(CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS));

	/* A later timer proves dispatch has passed the deleted instance's timer. */
	event_add_timer_msec(master, stop_loop, NULL, 1, &stop);
	while (!done) {
		assert(event_fetch(master, &event));
		event_call(&event);
	}
	assert(!tier2_fired);
	bgp_unlock(bgp);
	bgp_pthreads_finish();
	bgp_zebra_destroy();
	puts("deleted instance cancels tier-two GR timer: OK");
	return 0;
}
