// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exercise End-of-RIB during deferred configured startup selection.
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
#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_packet.c"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

enum startup_expiry { STARTUP_ACTIVE, EXPIRE_AFTER_DIRECT, EXPIRE_BEFORE_DIRECT };

static void test_multihop_eor(enum startup_expiry expiry)
{
	struct peer_connection direct_connection = {.status = Established};
	struct peer_connection multihop_connection = {.status = Established};
	char direct_name[] = "direct", multihop_name[] = "multihop";
	struct peer direct = {.connection = &direct_connection, .host = direct_name,
		.sort = BGP_PEER_EBGP, .ttl = 1, .local_as = 64512, .as = 64513,
		.as_type = AS_SPECIFIED};
	struct peer multihop = {.connection = &multihop_connection, .host = multihop_name,
		.sort = BGP_PEER_EBGP, .ttl = 2, .local_as = 64512, .as = 64513,
		.as_type = AS_SPECIFIED};
	struct graceful_restart_info *gr;
	struct bgp *bgp = NULL;
	as_t asn = 64512;
	int sockets[2];

	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT,
		       "64512", ASNOTATION_PLAIN) == BGP_CREATED);
	/* Allow actual completion writes without a Zebra daemon or event pump. */
	zclient_stop(bgp_zclient);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	assert(set_nonblocking(sockets[0]) == 0 && set_nonblocking(sockets[1]) == 0);
	bgp_zclient->sock = sockets[0];

	direct.bgp = multihop.bgp = bgp;
	direct_connection.peer = &direct;
	multihop_connection.peer = &multihop;
	direct.flags = multihop.flags = PEER_FLAG_CONFIG_NODE | PEER_FLAG_GRACEFUL_RESTART;
	direct.afc[AFI_IP6][SAFI_UNICAST] = multihop.afc[AFI_IP6][SAFI_UNICAST] = 1;
	direct.af_sflags[AFI_IP6][SAFI_UNICAST] = PEER_STATUS_GR_WAIT_EOR;
	multihop.af_sflags[AFI_IP6][SAFI_UNICAST] = PEER_STATUS_GR_WAIT_EOR;
	listnode_add(bgp->peer, &direct);
	listnode_add(bgp->peer, &multihop);
	bgp->gr_multihop_peer_exists = true;
	bgp->select_defer_time = 30;
	assert(bgp->t_startup && !CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART));
	bgp_gr_start_all_deferral_timers(bgp);
	gr = &bgp->gr_info[AFI_IP6][SAFI_UNICAST];
	assert(gr->t_select_deferral);

	/* The real startup-expiry callback only logs; cancel to model its state. */
	if (expiry == EXPIRE_BEFORE_DIRECT)
		event_cancel(&bgp->t_startup);
	bgp_update_receive_eor(&direct_connection, AFI_IP6, SAFI_UNICAST);
	assert(gr->select_defer_over && gr->select_defer_tier2_required &&
	       !gr->select_defer_over_tier2 && !gr->route_sync_tier2 &&
	       gr->t_select_deferral_tier2);
	if (expiry == EXPIRE_AFTER_DIRECT)
		event_cancel(&bgp->t_startup);
	bgp_update_receive_eor(&multihop_connection, AFI_IP6, SAFI_UNICAST);
	assert(CHECK_FLAG(multihop.af_sflags[AFI_IP6][SAFI_UNICAST], PEER_STATUS_EOR_RECEIVED));
	assert(gr->select_defer_over_tier2 && gr->route_sync_tier2 &&
	       !gr->t_select_deferral_tier2);

	listnode_delete(bgp->peer, &direct);
	listnode_delete(bgp->peer, &multihop);
	assert(bgp_delete(bgp) == 0);
	zclient_stop(bgp_zclient);
	close(sockets[1]);
	if (expiry == EXPIRE_BEFORE_DIRECT)
		puts("first EOR after startup expiry passed");
	else if (expiry == EXPIRE_AFTER_DIRECT)
		puts("multihop EOR after startup expiry passed");
	else
		puts("multihop EOR during configured startup passed");
}

int main(int argc, char **argv)
{
	cmd_init(1);
	debug_init();
	zlog_aux_init("Startup EOR: ", LOG_DEBUG);
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
	if (argc == 1 || !strcmp(argv[1], "active"))
		test_multihop_eor(STARTUP_ACTIVE);
	if (argc == 1 || !strcmp(argv[1], "expired"))
		test_multihop_eor(EXPIRE_AFTER_DIRECT);
	if (argc == 1 || !strcmp(argv[1], "late-first"))
		test_multihop_eor(EXPIRE_BEFORE_DIRECT);
	bgp_pthreads_finish();
	bgp_zebra_destroy();
	return 0;
}
