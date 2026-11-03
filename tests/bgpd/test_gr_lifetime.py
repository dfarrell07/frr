# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestGRLifetime(frrtest.TestMultiOut):
    program = "./test_gr_lifetime"


for check in (
    "delete processing marker passed",
    "delete Zebra marker passed",
    "buffered ADD COMPLETE WITHDRAW ordering passed",
    "failed completion send and retry passed",
    "new arm retires old marker and retry passed",
    "direct retirement waits for outer completion passed",
    "ordinary startup multihop EOR passed",
    "multihop EOR after startup expiry passed",
    "deleted NHT callback retired passed",
):
    TestGRLifetime.onesimple(check)
