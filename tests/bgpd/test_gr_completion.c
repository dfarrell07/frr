// SPDX-License-Identifier: GPL-2.0-or-later
/* Regression checks for initial NHT readiness and finite GR queue fences. */
#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "privs.h"
#include "stream.h"
#include "workqueue.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"

/* Exercise the actual initial-response handler without a test-only API. */
#include "bgpd/bgp_nht.c"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static struct bgp bgp;
static char bgp_name[sizeof("GR test")] = "GR test";
static struct bgp_dest *jobs[32];
static unsigned int job_count;

static void invalidate(struct graceful_restart_info *gr)
{
#ifdef BGP_NODE_GR_COMPLETION_MARKER
	gr->generation++;
	gr->completion_queued = false;
#else
	(void)gr;
#endif
}

static void cancel_retry(void)
{
	struct event *t = bgp.gr_info[AFI_IP6][SAFI_UNICAST].t_route_select;

	if (t) {
		void *arg = EVENT_ARG(t);

		XFREE(MTYPE_TMP, arg);
	}
	event_cancel(&bgp.gr_info[AFI_IP6][SAFI_UNICAST].t_route_select);
}

static void fixture_init(void)
{
	memset(&bgp, 0, sizeof(bgp));
	bgp.name_pretty = bgp_name;
	bgp.peer = list_new();
	bgp.rib[AFI_IP][SAFI_UNICAST] = bgp_table_init(&bgp, AFI_IP, SAFI_UNICAST);
	bgp.rib[AFI_IP6][SAFI_UNICAST] = bgp_table_init(&bgp, AFI_IP6, SAFI_UNICAST);
	bgp.gr_info[AFI_IP6][SAFI_UNICAST].select_defer_over = true;
	bgp_process_queue_init(&bgp);
	job_count = 0;
}

static void step(void)
{
	assert(bgp.mq->size);
	bgp.process_queue->spec.workfunc(bgp.process_queue, bgp.mq);
}

static void fixture_finish(void)
{
	while (bgp.mq->size)
		step();
	work_queue_free_and_null(&bgp.process_queue);
	bgp_meta_queue_free(bgp.mq);
	for (unsigned int i = 0; i < job_count; i++) {
		UNSET_FLAG(jobs[i]->flags, BGP_NODE_SELECT_DEFER | BGP_NODE_PROCESS_SCHEDULED);
		bgp.gr_info[AFI_IP][SAFI_UNICAST].gr_deferred--;
		bgp_dest_unlock_node(jobs[i]);
	}
	assert(!bgp.gr_info[AFI_IP][SAFI_UNICAST].gr_deferred);
	bgp_table_finish(&bgp.rib[AFI_IP][SAFI_UNICAST]);
	bgp_table_finish(&bgp.rib[AFI_IP6][SAFI_UNICAST]);
	cancel_retry();
	list_delete(&bgp.peer);
}

static struct bgp_dest *queue_job(bool early)
{
	struct prefix p;
	struct bgp_table *table = bgp.rib[AFI_IP][SAFI_UNICAST];
	struct bgp_dest *dest;
	char text[32];

	assert(job_count < array_size(jobs));
	snprintf(text, sizeof(text), "192.0.2.%u/32", job_count + 1);
	assert(str2prefix(text, &p));
	dest = bgp_node_get(table, &p);
	jobs[job_count++] = dest;
	/* Run the real queue handler, but bypass unrelated policy/FIB setup. */
	SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER | BGP_NODE_PROCESS_SCHEDULED);
	bgp.gr_info[AFI_IP][SAFI_UNICAST].gr_deferred++;
	bgp_table_lock(table);
	bgp_dest_lock_node(dest);
	if (early)
		early_route_process(&bgp, dest);
	else
		other_route_process(&bgp, dest);
	return dest;
}

static void test_frontier(bool causal)
{
	struct graceful_restart_info *gr;

	fixture_init();
	gr = &bgp.gr_info[AFI_IP6][SAFI_UNICAST];
	queue_job(true);
	queue_job(false);
	bgp_process_gr_deferral_complete(&bgp, AFI_IP6, SAFI_UNICAST);
	assert(!STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	if (causal) {
		/* A causal child must not readmit an unrelated post-fence job. */
		queue_job(false);
#ifdef BGP_NODE_GR_COMPLETION_MARKER
		bgp.mq->in_process = true;
		queue_job(false);
		bgp.mq->in_process = false;
#endif
	}
	/* Make the marker obsolete so this scheduling test needs no Zebra socket. */
	invalidate(gr);
	for (unsigned int i = 0; i < (causal ? 4U : 3U); i++) {
		queue_job(true);
		step();
	}
	assert(STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	assert(!zebra_announce_count(&bm->zebra_announce_head));
	assert(!STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EARLY_ROUTE]));
	assert(!causal || !STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_OTHER_ROUTE]));
	assert(bgp.mq->size); /* Later unrelated work did not prevent completion. */
	fixture_finish();
}

static void test_coalesced_frontiers(void)
{
#ifdef BGP_NODE_GR_COMPLETION_MARKER
	struct graceful_restart_info *gr1, *gr2;
	struct bgp_eoiu_info *first, *second;
	struct bgp_dest *marker1, *marker2, *old, *late, *target;

	fixture_init();
	gr1 = &bgp.gr_info[AFI_IP6][SAFI_UNICAST];
	gr2 = &bgp.gr_info[AFI_L2VPN][SAFI_EVPN];
	gr2->select_defer_over = true;
	old = queue_job(false);
	bgp_process_gr_deferral_complete(&bgp, AFI_IP6, SAFI_UNICAST);
	marker1 = STAILQ_FIRST(bgp.mq->subq[META_QUEUE_EOIU_MARKER]);
	assert(marker1);
	late = queue_job(false);
	target = queue_job(false);
	bgp_process_gr_deferral_complete(&bgp, AFI_L2VPN, SAFI_EVPN);
	marker2 = STAILQ_NEXT(marker1, pq);
	assert(marker2);
	queue_job(false); /* Unrelated work after the second frontier. */
	first = bgp_dest_get_bgp_eoiu_info(marker1);
	second = bgp_dest_get_bgp_eoiu_info(marker2);
	bgp.mq->in_process = true;
	bgp_process(&bgp, target, NULL, AFI_IP, SAFI_UNICAST);
	bgp_process(&bgp, target, NULL, AFI_IP, SAFI_UNICAST);
	bgp.mq->in_process = false;
	assert(STAILQ_FIRST(bgp.mq->subq[META_QUEUE_OTHER_ROUTE]) == old);
	assert(STAILQ_NEXT(old, pq) == target);
	assert(STAILQ_NEXT(target, pq) == late);
	assert(first->process_tail[META_QUEUE_OTHER_ROUTE] == target);
	assert(second->process_tail[META_QUEUE_OTHER_ROUTE] == late);
	invalidate(gr1);
	invalidate(gr2);
	for (unsigned int i = 0; i < 3; i++) {
		queue_job(true);
		step();
	}
	assert(STAILQ_FIRST(bgp.mq->subq[META_QUEUE_EOIU_MARKER]) == marker2);
	for (unsigned int i = 0; i < 2; i++) {
		queue_job(true);
		step();
	}
	assert(STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	assert(!zebra_announce_count(&bm->zebra_announce_head));
	assert(!STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EARLY_ROUTE]));
	assert(!STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_OTHER_ROUTE]));
	fixture_finish();
#else
	assert(!"GR completion marker unavailable");
#endif
}

static void unused_deadline(struct event *event)
{
	(void)event;
}

static void test_pending(bool reachable)
{
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_nexthop_cache nht = {.bgp = &bgp};
	struct zapi_route response = {.type = ZEBRA_ROUTE_CONNECT, .safi = SAFI_UNICAST};
	struct bgp_path_info path = {.nexthop = &nht};
	struct graceful_restart_info *gr;

	fixture_init();
	gr = &bgp.gr_info[AFI_IP6][SAFI_UNICAST];
#ifdef BGP_NEXTHOP_INITIAL_PENDING
	SET_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING);
#endif
	assert(str2prefix("2001:db8::/64", &p));
	dest = bgp_node_get(bgp.rib[AFI_IP6][SAFI_UNICAST], &p);
	bgp_dest_set_bgp_path_info(dest, &path);
	event_add_timer(master, unused_deadline, NULL, 30, &gr->t_select_deferral);
	/* This prefix is intentionally absent from gr_deferred, as when it was
	 * already PROCESS_SCHEDULED before the initial NHT query was issued.
	 */
	assert(!gr->gr_deferred);
	bgp_process_gr_deferral_complete(&bgp, AFI_IP6, SAFI_UNICAST);
	assert(!gr->route_sync_tier2);
	assert(STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	assert(gr->t_select_deferral);
	cancel_retry();
	LIST_INIT(&nht.paths);
	response.prefix = p;
	if (reachable) {
		response.nexthop_num = 1;
		response.nexthops[0].type = NEXTHOP_TYPE_IFINDEX;
		response.nexthops[0].ifindex = 1;
	}
	bgp_process_nexthop_update(&nht, &response, false);
#ifdef BGP_NEXTHOP_INITIAL_PENDING
	assert(!CHECK_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING));
#endif
	assert(!!CHECK_FLAG(nht.flags, BGP_NEXTHOP_VALID) == reachable);
	assert(nht.last_update);
	/* An actual first response is sufficient even when VALID remains false. */
	bgp_process_gr_deferral_complete(&bgp, AFI_IP6, SAFI_UNICAST);
	assert(!STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	invalidate(gr);
	event_cancel(&gr->t_select_deferral);
	step();
	assert(STAILQ_EMPTY(bgp.mq->subq[META_QUEUE_EOIU_MARKER]));
	assert(!zebra_announce_count(&bm->zebra_announce_head));
	bgp_dest_set_bgp_path_info(dest, NULL);
	bgp_dest_unlock_node(dest);
	bnc_nexthop_free(&nht);
	fixture_finish();
}

static bool deadline_timed_out;

static void deadline_watchdog(struct event *event)
{
	(void)event;
	deadline_timed_out = true;
}

static void expect_ipv6_complete(int socket)
{
	uint8_t data[1024];
	size_t used = 0, offset = 0;
	unsigned int completes = 0;
	ssize_t n;

	while ((n = recv(socket, data + used, sizeof(data) - used, MSG_DONTWAIT)) > 0)
		used += n;
	assert(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
	while (offset < used) {
		struct zmsghdr header;
		uint32_t capability, afi;

		assert(used - offset >= ZEBRA_HEADER_SIZE);
		memcpy(&header, data + offset, sizeof(header));
		assert(ntohs(header.length) >= ZEBRA_HEADER_SIZE);
		assert(ntohs(header.length) <= used - offset);
		if (ntohs(header.command) == ZEBRA_CLIENT_CAPABILITIES) {
			assert(ntohs(header.length) >= ZEBRA_HEADER_SIZE + 8);
			memcpy(&capability, data + offset + ZEBRA_HEADER_SIZE, 4);
			memcpy(&afi, data + offset + ZEBRA_HEADER_SIZE + 4, 4);
			if (ntohl(capability) == ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE &&
			    ntohl(afi) == AFI_IP6)
				completes++;
		}
		offset += ntohs(header.length);
	}
	assert(completes == 1);
}

static void test_original_deadline(void)
{
	afi_t afi;
	safi_t safi;
	struct bgp_nexthop_cache nht = {.bgp = &bgp};
	struct bgp_path_info path = {.nexthop = &nht};
	struct graceful_restart_info *gr;
	struct bgp_dest *dest;
	struct prefix p;
	struct event *deadline, *watchdog = NULL;
	struct event event;
	struct timespec start, finish;
	int sockets[2];
	double elapsed;

	fixture_init();
	assert(str2prefix("2001:db8:dead::/64", &p));
	dest = bgp_node_get(bgp.rib[AFI_IP6][SAFI_UNICAST], &p);
	bgp_dest_set_bgp_path_info(dest, &path);
#ifdef BGP_NEXTHOP_INITIAL_PENDING
	SET_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING);
#endif
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	assert(set_nonblocking(sockets[0]) == 0);
	assert(set_nonblocking(sockets[1]) == 0);
	bgp_zclient = zclient_new(master, &zclient_options_default, NULL, 0);
	bgp_zclient->sock = sockets[0];
	bgp.select_defer_time = 1;
	bgp_gr_start_all_deferral_timers(&bgp);
	FOREACH_AFI_SAFI (afi, safi) {
		if (afi == AFI_IP6 && safi == SAFI_UNICAST)
			continue;
		struct event **t = &bgp.gr_info[afi][safi].t_select_deferral;

		if (*t) {
			void *arg = EVENT_ARG(*t);

			XFREE(MTYPE_TMP, arg);
			event_cancel(t);
		}
		bgp.gr_info[afi][safi].af_enabled = false;
	}
	gr = &bgp.gr_info[AFI_IP6][SAFI_UNICAST];
	deadline = gr->t_select_deferral;
	assert(deadline);
	clock_gettime(CLOCK_MONOTONIC, &start);
	bgp_gr_check_path_select(&bgp, AFI_IP6, SAFI_UNICAST);
	assert(gr->t_select_deferral == deadline);
	assert(!gr->route_sync_tier2);
	for (unsigned int i = 0; i < 3; i++) {
		bgp_process_gr_deferral_complete(&bgp, AFI_IP6, SAFI_UNICAST);
		assert(gr->t_select_deferral == deadline);
	}
	deadline_timed_out = false;
	event_add_timer(master, deadline_watchdog, NULL, 3, &watchdog);
	while (!gr->route_sync_tier2 && !deadline_timed_out) {
		assert(event_fetch(master, &event));
		event_call(&event);
	}
	clock_gettime(CLOCK_MONOTONIC, &finish);
	elapsed = finish.tv_sec - start.tv_sec + (finish.tv_nsec - start.tv_nsec) / 1e9;
	assert(!deadline_timed_out && elapsed >= 0.9 && elapsed < 3.0);
	assert(!gr->t_select_deferral);
	expect_ipv6_complete(sockets[1]);
	event_cancel(&watchdog);
	bgp_dest_set_bgp_path_info(dest, NULL);
	bgp_dest_unlock_node(dest);
	fixture_finish();
	close(sockets[0]);
	close(sockets[1]);
	zclient_free(bgp_zclient);
	bgp_zclient = NULL;
}

static void test_alternate(void)
{
#ifdef BGP_NODE_GR_COMPLETION_MARKER
	struct bgp owner = {};
	struct peer peer = {.bgp = &owner};
	struct bgp_nexthop_cache nht = {.flags = BGP_NEXTHOP_INITIAL_PENDING};
	struct bgp_path_info alternate = {.peer = &peer, .flags = BGP_PATH_VALID};
	struct bgp_path_info pending = {.peer = &peer, .nexthop = &nht, .next = &alternate};
	struct bgp_dest dest = {};

	owner.peer_self = &peer;
	bgp_dest_set_bgp_path_info(&dest, &pending);
	assert(!bgp_dest_initial_nht_pending(&dest));
	alternate.nexthop = &nht;
	assert(bgp_dest_initial_nht_pending(&dest));
	SET_FLAG(pending.flags, BGP_PATH_REMOVED);
	SET_FLAG(alternate.flags, BGP_PATH_REMOVED);
	assert(!bgp_dest_initial_nht_pending(&dest));
#else
	assert(!"initial NHT completion guard unavailable");
#endif
}

int main(int argc, char **argv)
{
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	if (argc == 1 || !strcmp(argv[1], "frontier")) {
		test_frontier(false);
		puts("finite frontier passed");
	}
	if (argc == 1 || !strcmp(argv[1], "causal")) {
		test_frontier(true);
		puts("causal frontier passed");
	}
	if (argc == 1 || !strcmp(argv[1], "coalescing")) {
		test_coalesced_frontiers();
		puts("coalesced frontiers passed");
	}
	if (argc == 1 || !strcmp(argv[1], "positive")) {
		test_pending(true);
		puts("positive NHT response passed");
	}
	if (argc == 1 || !strcmp(argv[1], "negative")) {
		test_pending(false);
		puts("negative NHT response passed");
	}
	if (argc == 1 || !strcmp(argv[1], "deadline")) {
		test_original_deadline();
		puts("NHT deadline passed");
	}
	if (argc == 1 || !strcmp(argv[1], "alternate")) {
		test_alternate();
		puts("alternate and withdrawal passed");
	}
	return 0;
}
