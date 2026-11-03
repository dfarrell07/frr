// SPDX-License-Identifier: GPL-2.0-or-later
/* Real BGP deletion and nonblocking ZAPI completion controls. */
#include <zebra.h>
#include "command.h"
#include "debug.h"
#undef DEBUG_ON /* bgpd supplies its own macro. */
#include "frr_pthread.h"
#include "frrevent.h"
#include "northbound.h"
#include "privs.h"
#include "qobj.h"
#include "workqueue.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_zebra.h"
/* Keep the actual registration and interface-initial callbacks under test. */
#include "bgpd/bgp_nht.c"
#include "bgpd/bgp_evpn_private.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

struct capture {
	uint8_t data[65536];
	size_t used, parsed;
	unsigned int adds, deletes, completes;
	bool bad_order;
};

static void capture_read(int fd, struct capture *c)
{
	ssize_t n;

	while ((n = recv(fd, c->data + c->used, sizeof(c->data) - c->used, MSG_DONTWAIT)) > 0)
		c->used += n;
	assert(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
	while (c->used - c->parsed >= ZEBRA_HEADER_SIZE) {
		struct zmsghdr h;
		uint16_t length, command;

		memcpy(&h, c->data + c->parsed, sizeof(h));
		length = ntohs(h.length);
		assert(length >= ZEBRA_HEADER_SIZE);
		if (length > c->used - c->parsed)
			break;
		command = ntohs(h.command);
		if (command == ZEBRA_ROUTE_ADD) {
			c->bad_order |= c->completes != 0;
			c->adds++;
		} else if (command == ZEBRA_ROUTE_DELETE) {
			c->bad_order |= c->completes != 1;
			c->deletes++;
		} else if (command == ZEBRA_CLIENT_CAPABILITIES) {
			uint32_t capability, afi;

			assert(length >= ZEBRA_HEADER_SIZE + 8);
			memcpy(&capability, c->data + c->parsed + ZEBRA_HEADER_SIZE, 4);
			memcpy(&afi, c->data + c->parsed + ZEBRA_HEADER_SIZE + 4, 4);
			if (ntohl(capability) == ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE &&
			    ntohl(afi) == AFI_IP6)
				c->completes++;
		}
		c->parsed += length;
	}
}

static bool period_done;

static void end_period(struct event *event)
{
	(void)event;
	period_done = true;
}

static void pump(unsigned int ms, int fd, struct capture *capture,
		 uint64_t deleted_id, uintptr_t deleted_address)
{
	struct event event;
	struct event *stop = NULL;

	period_done = false;
	event_add_timer_msec(master, end_period, NULL, ms, &stop);
	while (!period_done) {
		if (capture)
			capture_read(fd, capture);
		assert(event_fetch(master, &event));
		if (event.func == bgp_nht_ifp_initial &&
		    (uintptr_t)EVENT_ARG(&event) == deleted_address) {
			fprintf(stderr, "NHT callback after deletion: qobj=%" PRIu64 " alive=%d\n",
				deleted_id, QOBJ_GET_TYPESAFE(deleted_id, bgp) != NULL);
			/* Detect the dangling callback before executing unsafe code. */
			assert(QOBJ_GET_TYPESAFE(deleted_id, bgp));
		}
		event_call(&event);
	}
	if (capture)
		capture_read(fd, capture);
	assert(!stop);
}

static struct bgp *router(void)
{
	struct bgp *bgp = NULL;
	as_t asn = 64512;

	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT,
		       "64512", ASNOTATION_PLAIN) == BGP_CREATED);
	assert(bgp && QOBJ_GET_TYPESAFE(QOBJ_ID(bgp), bgp) == bgp);
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].select_defer_over = true;
	bgp->gr_info[AFI_IP6][SAFI_UNICAST].af_enabled = true;
	bgp->gr_route_sync_pending = true;
	return bgp;
}

static int attach_socket(void)
{
	int sockets[2], size = 4096;

	zclient_stop(bgp_zclient);
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
	assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
	bgp_zclient->sock = sockets[0];
	return sockets[1];
}

static void enqueue_marker(struct bgp *bgp, bool zebra)
{
	bgp_process_gr_deferral_complete(bgp, AFI_IP6, SAFI_UNICAST);
	assert(!STAILQ_EMPTY(bgp->mq->subq[META_QUEUE_EOIU_MARKER]));
	if (zebra) {
		bgp->process_queue->spec.workfunc(bgp->process_queue, bgp->mq);
		assert(zebra_announce_count(&bm->zebra_announce_head) == 1);
	}
}

static void delete_router(struct bgp *bgp, uint64_t id)
{
	assert(bgp_delete(bgp) == 0);
	/* bgp_free unregisters this ID, after asynchronous references retire. */
	assert(!QOBJ_GET_TYPESAFE(id, bgp));
	assert(!zebra_announce_count(&bm->zebra_announce_head));
}

static void test_delete_marker(bool zebra)
{
	struct bgp *old = router(), *fresh;
	uint64_t old_id = QOBJ_ID(old);
	uintptr_t old_address = (uintptr_t)old;
	struct graceful_restart_info *gr = &old->gr_info[AFI_IP6][SAFI_UNICAST];
	struct capture capture = {};
	int fd = attach_socket();

	/* Exercise the real retry allocation and its deletion cleanup too. */
	gr->gr_deferred = 1;
	bgp_process_gr_deferral_complete(old, AFI_IP6, SAFI_UNICAST);
	assert(gr->t_route_select);
	gr->gr_deferred = 0;
	enqueue_marker(old, zebra);
	delete_router(old, old_id);
	pump(100, fd, &capture, old_id, old_address);
	assert(capture.completes == 0);
	fresh = router();
	enqueue_marker(fresh, false);
	pump(150, fd, &capture, old_id, old_address);
	assert(capture.completes == 1);
	delete_router(fresh, QOBJ_ID(fresh));
	zclient_stop(bgp_zclient);
	close(fd);
	puts(zebra ? "delete Zebra marker passed" : "delete processing marker passed");
}

static enum zclient_send_status route_message(unsigned int i, bool add)
{
	struct zapi_route route = {.type = ZEBRA_ROUTE_BGP, .safi = SAFI_UNICAST};
	char prefix[64];

	snprintf(prefix, sizeof(prefix), "2001:db8:%x::/64", i);
	assert(str2prefix(prefix, &route.prefix));
	SET_FLAG(route.message, ZAPI_MESSAGE_NEXTHOP);
	route.nexthop_num = 1;
	route.nexthops[0].type = NEXTHOP_TYPE_IFINDEX;
	route.nexthops[0].ifindex = 1;
	return zclient_route_send(add ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
				 bgp_zclient, &route);
}

static void test_buffered_order(void)
{
	struct bgp *bgp = router();
	struct capture capture = {};
	bool buffered = false;
	int fd = attach_socket();

	for (unsigned int i = 0; i < 512; i++) {
		enum zclient_send_status status = route_message(i, true);

		assert(status != ZCLIENT_SEND_FAILURE);
		buffered |= status == ZCLIENT_SEND_BUFFERED;
	}
	assert(buffered);
	enqueue_marker(bgp, true);
	/* Leave the reader blocked while the real marker enters the write FIFO. */
	pump(50, -1, NULL, 0, 0);
	assert(bgp->gr_info[AFI_IP6][SAFI_UNICAST].route_sync_tier2);
	assert(route_message(0, false) != ZCLIENT_SEND_FAILURE);
	pump(300, fd, &capture, 0, 0);
	assert(capture.adds == 512 && capture.completes == 1 && capture.deletes == 1);
	assert(!capture.bad_order && capture.parsed == capture.used);
	delete_router(bgp, QOBJ_ID(bgp));
	zclient_stop(bgp_zclient);
	close(fd);
	puts("buffered ADD COMPLETE WITHDRAW ordering passed");
}

static void test_failed_send(void)
{
	struct bgp *bgp = router();
	struct graceful_restart_info *gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	struct capture capture = {};
	int fd = attach_socket();

	enqueue_marker(bgp, true);
	close(fd);
	pump(100, -1, NULL, 0, 0);
	assert(!gr->route_sync_tier2 && gr->t_route_select);
	fd = attach_socket();
	pump(1500, fd, &capture, 0, 0);
	assert(gr->route_sync_tier2 && capture.completes == 1);
	bgp_process_gr_deferral_complete(bgp, AFI_IP6, SAFI_UNICAST);
	pump(100, fd, &capture, 0, 0);
	assert(capture.completes == 1);
	delete_router(bgp, QOBJ_ID(bgp));
	zclient_stop(bgp_zclient);
	close(fd);
	puts("failed completion send and retry passed");
}

static void test_deleted_nht_callback(void)
{
	struct bgp *bgp = router();
	struct bgp_nexthop_cache *bnc;
	struct peer_connection connection = {};
	char ifname[] = "test";
	struct peer peer = {.bgp = bgp, .connection = &connection, .conf_if = ifname};
	struct prefix prefix;
	uint64_t id = QOBJ_ID(bgp);
	uintptr_t address = (uintptr_t)bgp;

	assert(str2prefix("fe80::1234/128", &prefix));
	bnc = bnc_new(&bgp->nexthop_cache_table[AFI_IP6], &prefix, 0, 1234);
	bnc->bgp = bgp;
	bnc->afi = AFI_IP6;
	register_zebra_rnh(bnc);
	connection.su.sin6.sin6_family = AF_INET6;
	connection.su.sin6.sin6_addr = prefix.u.prefix6;
	connection.su.sin6.sin6_scope_id = 1234;
	bgp_nht_interface_events(&peer);
	delete_router(bgp, id);
	pump(100, -1, NULL, id, address);
	puts("deleted NHT callback retired passed");
}

static void test_new_arm(void)
{
	struct bgp *bgp = router();
	struct graceful_restart_info *gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	struct bgp_nexthop_cache nht = {.bgp = bgp};
	struct bgp_path_info path = {.nexthop = &nht};
	struct zapi_route response = {.type = ZEBRA_ROUTE_CONNECT, .safi = SAFI_UNICAST};
	struct prefix prefix;
	struct bgp_dest *old, *fresh;
	struct event *deadline;
	struct capture capture = {};
	uint64_t generation;
	int fd = attach_socket();

	bgp->select_defer_time = 30;
	bgp_start_tier2_deferral_timer(bgp, AFI_IP6, SAFI_UNICAST);
	assert(gr->t_select_deferral_tier2 && !gr->t_select_deferral);
	assert(str2prefix("2001:db8:0dd::/64", &prefix));
	old = bgp_node_get(bgp->rib[AFI_IP6][SAFI_UNICAST], &prefix);
	bgp_dest_set_bgp_path_info(old, &path);
	SET_FLAG(nht.flags, BGP_NEXTHOP_INITIAL_PENDING);
	bgp_gr_check_path_select(bgp, AFI_IP6, SAFI_UNICAST);
	assert(gr->t_route_select);
	LIST_INIT(&nht.paths);
	response.prefix = prefix;
	bgp_process_nexthop_update(&nht, &response, false);
	enqueue_marker(bgp, false);
	generation = gr->generation;
	bgp_gr_start_all_deferral_timers(bgp);
	deadline = gr->t_select_deferral;
	assert(deadline && !gr->t_select_deferral_tier2);
	assert(gr->generation == generation + 1 && !gr->select_defer_over);
	assert(!gr->route_sync && !gr->route_sync_tier2);
	bgp_gr_start_all_deferral_timers(bgp);
	assert(gr->t_select_deferral == deadline && gr->generation == generation + 1);
	bgp_dest_set_bgp_path_info(old, NULL);
	bgp_dest_unlock_node(old);
	assert(str2prefix("2001:db8:feed::/64", &prefix));
	fresh = bgp_node_get(bgp->rib[AFI_IP6][SAFI_UNICAST], &prefix);
	SET_FLAG(fresh->flags, BGP_NODE_SELECT_DEFER);
	gr->gr_deferred = 1;
	pump(1200, fd, &capture, 0, 0);
	assert(gr->t_select_deferral == deadline && !gr->select_defer_over);
	assert(gr->gr_deferred == 1 && CHECK_FLAG(fresh->flags, BGP_NODE_SELECT_DEFER));
	assert(capture.completes == 0 && !zebra_announce_count(&bm->zebra_announce_head));
	bgp_gr_check_path_select(bgp, AFI_IP6, SAFI_UNICAST);
	pump(150, fd, &capture, 0, 0);
	assert(gr->gr_deferred == 0 && !CHECK_FLAG(fresh->flags, BGP_NODE_SELECT_DEFER));
	assert(gr->route_sync_tier2 && capture.completes == 1);
	bgp_dest_unlock_node(fresh);
	delete_router(bgp, QOBJ_ID(bgp));
	zclient_stop(bgp_zclient);
	close(fd);
	puts("new arm retires old marker and retry passed");
}

static void test_direct_retirement(void)
{
	struct bgp *bgp = router();
	struct graceful_restart_info *gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	struct bgp_dest *dest;
	struct prefix prefix;
	struct capture capture = {};
	int fd = attach_socket();

	assert(str2prefix("2001:db8:fade::/64", &prefix));
	dest = bgp_node_get(bgp->rib[AFI_IP6][SAFI_UNICAST], &prefix);
	SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
	gr->gr_deferred = 1;
	assert(bgp_deferred_path_selection(bgp, AFI_IP6, SAFI_UNICAST,
					   bgp->rib[AFI_IP6][SAFI_UNICAST], 0, NULL, false) == 1);
	assert(!gr->gr_deferred);
	/* Only the outer walk may request completion after all derived work. */
	assert(STAILQ_EMPTY(bgp->mq->subq[META_QUEUE_EOIU_MARKER]));
	assert(!zebra_announce_count(&bm->zebra_announce_head));
	enqueue_marker(bgp, false);
	pump(150, fd, &capture, 0, 0);
	assert(gr->route_sync_tier2 && capture.completes == 1);
	bgp_dest_unlock_node(dest);
	delete_router(bgp, QOBJ_ID(bgp));
	zclient_stop(bgp_zclient);
	close(fd);
	puts("direct retirement waits for outer completion passed");
}

int main(int argc, char **argv)
{
	/* Same real daemon setup as test_peer_attr; no listener or Zebra server. */
	signal(SIGPIPE, SIG_IGN);
	cmd_init(1);
	debug_init();
	zlog_aux_init("GR lifetime: ", LOG_DEBUG);
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
	if (argc == 1 || !strcmp(argv[1], "process"))
		test_delete_marker(false);
	if (argc == 1 || !strcmp(argv[1], "zebra"))
		test_delete_marker(true);
	if (argc == 1 || !strcmp(argv[1], "buffered"))
		test_buffered_order();
	if (argc == 1 || !strcmp(argv[1], "failure"))
		test_failed_send();
	if (argc == 1 || !strcmp(argv[1], "rearm"))
		test_new_arm();
	if (argc == 1 || !strcmp(argv[1], "retirement"))
		test_direct_retirement();
	if (argc == 1 || !strcmp(argv[1], "nht"))
		test_deleted_nht_callback();
	bgp_pthreads_finish();
	bgp_zebra_destroy();
	return 0;
}
