# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Daniel Farrell
import frrtest


class TestGRReplay(frrtest.TestMultiOut):
    program = "./test_gr_replay"


for check in (
    "new and repeated NHT registration passed",
    "positive initial NHT response passed",
    "negative initial NHT response passed",
    "FIB notification preserves initial NHT deadline passed",
    "deferred selection waits for initial NHT passed",
    "BGP processing before completion passed",
    "normal Zebra announcements before completion passed",
    "early Zebra announcements before completion passed",
    "buffered ZAPI routes before completion passed",
    "failed completion send and retry passed",
    "original selection deadline forces progress passed",
    "deleted instance retires live selection timer passed",
    "new selection cycle retires old retry passed",
):
    TestGRReplay.onesimple(check)
