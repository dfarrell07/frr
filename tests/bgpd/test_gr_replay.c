// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exercise GR completion against real NHT, processing and Zebra handlers.
 * Copyright (C) 2026 Daniel Farrell
 */
#include <zebra.h>
#include "command.h"
#include "debug.h"
#undef DEBUG_ON
#include "frr_pthread.h"
#include "frrevent.h"
#include "network.h"
#include "northbound.h"
#include "privs.h"
#include "workqueue.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nht.c"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static struct bgp *bgp;
static int reader;
static struct {
	uint8_t data[65536];
	size_t used, parsed;
	unsigned int adds, deletes, completes;
	bool route_after_complete;
} capture;

static void read_messages(void)
{
	ssize_t n;

	while ((n = recv(reader, capture.data + capture.used,
			 sizeof(capture.data) - capture.used, MSG_DONTWAIT)) > 0)
		capture.used += n;
	assert(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
	while (capture.used - capture.parsed >= ZEBRA_HEADER_SIZE) {
		struct zmsghdr h;
		uint16_t length, command;

		memcpy(&h, capture.data + capture.parsed, sizeof(h));
		length = ntohs(h.length);
		assert(length >= ZEBRA_HEADER_SIZE);
		if (length > capture.used - capture.parsed)
			break;
		command = ntohs(h.command);
		if (command == ZEBRA_ROUTE_ADD || command == ZEBRA_ROUTE_DELETE) {
			capture.route_after_complete |= capture.completes != 0;
			if (command == ZEBRA_ROUTE_ADD)
				capture.adds++;
			else
				capture.deletes++;
		} else if (command == ZEBRA_CLIENT_CAPABILITIES) {
			uint32_t capability, afi;

			assert(length >= ZEBRA_HEADER_SIZE + 8);
			memcpy(&capability, capture.data + capture.parsed + ZEBRA_HEADER_SIZE, 4);
			memcpy(&afi, capture.data + capture.parsed + ZEBRA_HEADER_SIZE + 4, 4);
			if (ntohl(capability) == ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE &&
			    ntohl(afi) == AFI_IP6)
				capture.completes++;
		}
		capture.parsed += length;
	}
}

static bool stop;

static void stop_period(struct event *event)
{
	(void)event;
	stop = true;
}

static void pump(unsigned int ms)
{
	struct event event;
	struct event *timer = NULL;

	stop = false;
	event_add_timer_msec(master, stop_period, NULL, ms, &timer);
	while (!stop) {
		read_messages();
		assert(event_fetch(master, &event));
		event_call(&event);
	}
	read_messages();
}

static void attach_socket(void)
{
	int sockets[2], size = 4096;

	zclient_stop(bgp_zclient);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	assert(set_nonblocking(sockets[0]) == 0 && set_nonblocking(sockets[1]) == 0);
	assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
	bgp_zclient->sock = sockets[0];
	reader = sockets[1];
}

static void unused_deadline(struct event *event)
{
	(void)event;
}

static void fixture(void)
{
	as_t asn = 64512;
	struct graceful_restart_info *gr;

	bgp = NULL;
	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT,
		       "64512", ASNOTATION_PLAIN) == BGP_CREATED);
	attach_socket();
	memset(&capture, 0, sizeof(capture));
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	gr->select_defer_over = gr->af_enabled = true;
	bgp->gr_route_sync_pending = true;
	event_add_timer(master, unused_deadline, NULL, 30, &gr->t_select_deferral);
}

static void cancel_timer(struct event **timer)
{
	if (*timer) {
		void *info = EVENT_ARG(*timer);

		XFREE(MTYPE_TMP, info);
	}
	event_cancel(timer);
}

static void finish(void)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		cancel_timer(&bgp->gr_info[afi][safi].t_select_deferral);
		cancel_timer(&bgp->gr_info[afi][safi].t_select_deferral_tier2);
		cancel_timer(&bgp->gr_info[afi][safi].t_route_select);
	}
	assert(bgp_delete(bgp) == 0);
	zclient_stop(bgp_zclient);
	close(reader);
}

static struct bgp_dest *destination(const char *text)
{
	struct prefix prefix;

	assert(str2prefix(text, &prefix));
	return bgp_node_get(bgp->rib[AFI_IP6][SAFI_UNICAST], &prefix);
}

static void complete(void)
{
	bgp_process_gr_deferral_complete(bgp, AFI_IP6, SAFI_UNICAST);
	read_messages();
}

static void test_registration(void)
{
	struct bgp_nexthop_cache nht = {};
	struct zapi_route response = {.type = ZEBRA_ROUTE_CONNECT, .safi = SAFI_UNICAST};

	fixture();
	nht.bgp = bgp;
	LIST_INIT(&nht.paths);
	assert(str2prefix("2001:db8::1/128", &nht.prefix));
	response.prefix = nht.prefix;
	register_zebra_rnh(&nht);
	assert(CHECK_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING));
	bgp_process_nexthop_update(&nht, &response, false);
	assert(!CHECK_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING) && nht.last_update);
	/* A previous response does not answer a new registration. */
	unregister_zebra_rnh(&nht);
	register_zebra_rnh(&nht);
	assert(CHECK_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING) && nht.last_update);
	finish();
	puts("new and repeated NHT registration passed");
}

static void test_nht(bool reachable, bool fib)
{
	struct bgp_nexthop_cache nht = {.flags = BGP_NEXTHOP_INITIAL_PENDING};
	struct bgp_path_info path = {.nexthop = &nht};
	struct zapi_route response = {.type = ZEBRA_ROUTE_CONNECT, .safi = SAFI_UNICAST};
	struct graceful_restart_info *gr;
	struct bgp_dest *dest;
	struct event *deadline, *retry;

	fixture();
	nht.bgp = bgp;
	LIST_INIT(&nht.paths);
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	deadline = gr->t_select_deferral;
	dest = destination("2001:db8:1::/64");
	bgp_dest_set_bgp_path_info(dest, &path);
	complete();
	assert(!gr->route_sync_tier2 && !capture.completes);
	retry = gr->t_route_select;
	assert(retry);
	if (fib) {
		SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING);
		bgp_zebra_update_fib_install_pending(dest, bgp, true);
		bgp_zebra_update_fib_install_pending(dest, bgp, false);
		assert(!gr->gr_route_fib_install_pending_cnt);
		assert(gr->t_select_deferral == deadline && !gr->route_sync_tier2);
	}
	response.prefix = *bgp_dest_get_prefix(dest);
	if (reachable) {
		response.nexthop_num = 1;
		response.nexthops[0].type = NEXTHOP_TYPE_IFINDEX;
		response.nexthops[0].ifindex = 1;
	}
	bgp_process_nexthop_update(&nht, &response, false);
	assert(!CHECK_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING));
	assert(!!CHECK_FLAG(nht.flags, BGP_NEXTHOP_VALID) == reachable);
	complete();
	/* Repeated callbacks share the existing retry and its work budget. */
	assert(gr->t_route_select == retry && !gr->route_sync_tier2 && !capture.completes);
	pump(1200);
	assert(gr->route_sync_tier2 && capture.completes == 1);
	assert(!gr->t_select_deferral);
	bgp_dest_set_bgp_path_info(dest, NULL);
	bgp_dest_unlock_node(dest);
	bnc_nexthop_free(&nht);
	finish();
	puts(fib ? "FIB notification preserves initial NHT deadline passed"
		 : reachable ? "positive initial NHT response passed"
			     : "negative initial NHT response passed");
}

static void test_processing(void)
{
	struct bgp_dest *dest;

	fixture();
	dest = destination("2001:db8:2::/64");
	SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER | BGP_NODE_PROCESS_SCHEDULED);
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].gr_deferred = 1;
	bgp_table_lock(bgp_dest_table(dest));
	bgp_dest_lock_node(dest);
	assert(other_route_process(bgp, dest) == 0);
	/* Queued work can exist after its deferred-route count reaches zero. */
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].gr_deferred = 0;
	complete();
	assert(!capture.completes && bgp->mq->size == 1);
	bgp->process_queue->spec.workfunc(bgp->process_queue, bgp->mq);
	assert(!bgp->mq->size);
	UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
	complete();
	pump(1200);
	assert(capture.completes == 1);
	bgp_dest_unlock_node(dest);
	finish();
	puts("BGP processing before completion passed");
}

static void test_deferred(void)
{
	struct bgp_nexthop_cache nht = {.flags = BGP_NEXTHOP_INITIAL_PENDING};
	struct attr attr = {};
	struct bgp_path_info path = {.nexthop = &nht, .attr = &attr, .lock = 1};
	struct bgp_path_info alternate = {.flags = BGP_PATH_VALID};
	struct zapi_route response = {.type = ZEBRA_ROUTE_CONNECT, .safi = SAFI_UNICAST};
	struct bgp_dest *dest;
	struct graceful_restart_info *gr;

	fixture();
	nht.bgp = bgp;
	path.peer = bgp->peer_self;
	LIST_INIT(&nht.paths);
	dest = destination("2001:db8:6::/64");
	bgp_dest_set_bgp_path_info(dest, &path);
	SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	gr->gr_deferred = 1;
	/* An unanswered alternate must not hold back a usable local path. */
	alternate.peer = bgp->peer_self;
	path.next = &alternate;
	assert(!bgp_dest_initial_nht_pending(dest));
	UNSET_FLAG(alternate.flags, BGP_PATH_VALID);
	assert(bgp_dest_initial_nht_pending(dest));
	path.next = NULL;
	assert(bgp_deferred_path_selection(bgp, AFI_IP6, SAFI_UNICAST,
					   bgp_dest_table(dest), 0, NULL, false) == 0);
	assert(gr->gr_deferred == 1 && CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER));
	response.prefix = *bgp_dest_get_prefix(dest);
	bgp_process_nexthop_update(&nht, &response, false);
	bgp_dest_set_bgp_path_info(dest, NULL);
	assert(bgp_deferred_path_selection(bgp, AFI_IP6, SAFI_UNICAST,
					   bgp_dest_table(dest), 0, NULL, false) == 1);
	assert(!gr->gr_deferred && !CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER));
	read_messages();
	assert(!capture.completes);
	complete();
	assert(capture.completes == 1);
	bgp_dest_unlock_node(dest);
	finish();
	puts("deferred selection waits for initial NHT passed");
}

static void test_zebra(bool early)
{
	struct attr attr = {};
	struct bgp_path_info path = {.attr = &attr, .lock = 1};
	struct bgp_dest *dest;

	fixture();
	dest = destination("2001:db8:3::/64");
	if (early)
		SET_FLAG(dest->flags, BGP_NODE_ZEBRA_ANNOUNCE_EARLY);
	/* Selection still owns the route while it queues the announcement. */
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].gr_deferred = 1;
	bgp_zebra_route_install(dest, &path, bgp, false, NULL, false);
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].gr_deferred = 0;
	assert(bgp->zebra_announce_queue_cnt == 1);
	assert(zebra_announce_count(early ? &bm->zebra_announce_early_head
					: &bm->zebra_announce_head) == 1);
	complete();
	assert(!capture.completes);
	pump(50);
	assert(!bgp->zebra_announce_queue_cnt && capture.deletes == 1);
	complete();
	pump(1200);
	assert(capture.completes == 1 && !capture.route_after_complete);
	assert(path.lock == 1 && !dest->za_inode);
	bgp_dest_unlock_node(dest);
	finish();
	puts(early ? "early Zebra announcements before completion passed"
		   : "normal Zebra announcements before completion passed");
}

static void test_buffered(void)
{
	struct zapi_route route = {.type = ZEBRA_ROUTE_BGP, .safi = SAFI_UNICAST};
	bool buffered = false;

	fixture();
	assert(str2prefix("2001:db8:4::/64", &route.prefix));
	SET_FLAG(route.message, ZAPI_MESSAGE_NEXTHOP);
	route.nexthop_num = 1;
	route.nexthops[0].type = NEXTHOP_TYPE_IFINDEX;
	route.nexthops[0].ifindex = 1;
	for (unsigned int i = 0; i < 512; i++) {
		enum zclient_send_status status;

		status = zclient_route_send(ZEBRA_ROUTE_ADD, bgp_zclient, &route);

		assert(status != ZCLIENT_SEND_FAILURE);
		buffered |= status == ZCLIENT_SEND_BUFFERED;
	}
	assert(buffered);
	bgp_process_gr_deferral_complete(bgp, AFI_IP6, SAFI_UNICAST);
	assert(bgp->gr_info[AFI_IP6][SAFI_UNICAST].route_sync_tier2);
	pump(300);
	assert(capture.adds == 512 && capture.completes == 1 && !capture.route_after_complete);
	finish();
	puts("buffered ZAPI routes before completion passed");
}

static void test_failure(void)
{
	struct graceful_restart_info *gr;

	fixture();
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	close(reader);
	bgp_process_gr_deferral_complete(bgp, AFI_IP6, SAFI_UNICAST);
	assert(!gr->route_sync_tier2 && gr->t_route_select);
	attach_socket();
	pump(1200);
	assert(gr->route_sync_tier2 && capture.completes == 1);
	finish();
	puts("failed completion send and retry passed");
}

static void test_deadline(void)
{
	struct bgp_nexthop_cache nht = {.flags = BGP_NEXTHOP_INITIAL_PENDING};
	struct bgp_path_info path = {.nexthop = &nht};
	struct graceful_restart_info *gr;
	struct bgp_dest *dest;
	struct event *deadline;
	afi_t afi;
	safi_t safi;

	fixture();
	nht.bgp = bgp;
	dest = destination("2001:db8:5::/64");
	bgp_dest_set_bgp_path_info(dest, &path);
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	cancel_timer(&gr->t_select_deferral);
	bgp->select_defer_time = 1;
	bgp_gr_start_all_deferral_timers(bgp);
	FOREACH_AFI_SAFI (afi, safi) {
		if (afi == AFI_IP6 && safi == SAFI_UNICAST)
			continue;
		cancel_timer(&bgp->gr_info[afi][safi].t_select_deferral);
		bgp->gr_info[afi][safi].af_enabled = false;
	}
	deadline = gr->t_select_deferral;
	bgp_gr_check_path_select(bgp, AFI_IP6, SAFI_UNICAST);
	assert(gr->t_select_deferral == deadline && !gr->route_sync_tier2);
	for (unsigned int i = 0; i < 3; i++) {
		complete();
		assert(gr->t_select_deferral == deadline);
	}
	pump(500);
	assert(!gr->route_sync_tier2 && !capture.completes && gr->t_select_deferral == deadline);
	pump(1000);
	assert(gr->route_sync_tier2 && capture.completes == 1 && !gr->t_select_deferral);
	bgp_dest_set_bgp_path_info(dest, NULL);
	bgp_dest_unlock_node(dest);
	finish();
	puts("original selection deadline forces progress passed");
}

static void test_delete_live_timer(void)
{
	fixture();
	bgp->gr_multihop_peer_exists = true;
	bgp->select_defer_time = 1;
	bgp_start_tier2_deferral_timer(bgp, AFI_IP6, SAFI_UNICAST);
	assert(bgp->gr_info[AFI_IP6][SAFI_UNICAST].t_select_deferral_tier2);
	/* Unlike fixture cleanup, leave the live timer for bgp_delete to retire. */
	assert(bgp_delete(bgp) == 0);
	pump(1200);
	assert(!capture.completes);
	zclient_stop(bgp_zclient);
	close(reader);
	puts("deleted instance retires live selection timer passed");
}

static void test_new_cycle(void)
{
	struct graceful_restart_info *gr;
	struct bgp_dest *dest;

	fixture();
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	dest = destination("2001:db8:7::/64");
	SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
	gr->gr_deferred = 1;
	cancel_timer(&gr->t_select_deferral);
	complete();
	assert(gr->t_route_select);
	bgp->select_defer_time = 30;
	bgp_gr_start_all_deferral_timers(bgp);
	assert(!gr->select_defer_over);
	/* An old retry must not retire this cycle's prefix before its EOR. */
	pump(1200);
	assert(gr->gr_deferred == 1 && CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER));
	assert(!gr->route_sync_tier2 && !capture.completes);
	UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
	gr->gr_deferred = 0;
	bgp_dest_unlock_node(dest);
	finish();
	puts("new selection cycle retires old retry passed");
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	cmd_init(1);
	debug_init();
	zlog_aux_init("GR replay: ", LOG_DEBUG);
	zprivs_preinit(&bgpd_privs);
	zprivs_init(&bgpd_privs);
	master = event_master_create(NULL);
	nb_init(master, NULL, 0, false, false);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	assert(bgp_option_set(BGP_OPT_NO_LISTEN) == 0);
	assert(bgp_option_set(BGP_OPT_NO_ZEBRA) == 0);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();
	zclient_stop(bgp_zclient);
	event_cancel(&bm->t_bgp_start_label_manager);
	event_cancel(&bm->t_bgp_sync_label_manager);
#define RUN(name, call) \
	do { \
		if (argc == 1 || !strcmp(argv[1], name)) \
			call; \
	} while (0)
	RUN("registration", test_registration());
	RUN("positive", test_nht(true, false));
	RUN("negative", test_nht(false, false));
	RUN("fib", test_nht(false, true));
	RUN("deferred", test_deferred());
	RUN("processing", test_processing());
	RUN("zebra-normal", test_zebra(false));
	RUN("zebra-early", test_zebra(true));
	RUN("buffered", test_buffered());
	RUN("failure", test_failure());
	RUN("deadline", test_deadline());
	RUN("delete-timer", test_delete_live_timer());
	RUN("new-cycle", test_new_cycle());
#undef RUN
	bgp_pthreads_finish();
	bgp_zebra_destroy();
	return 0;
}
