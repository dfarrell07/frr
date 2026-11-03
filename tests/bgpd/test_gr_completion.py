# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestGRCompletion(frrtest.TestMultiOut):
    program = "./test_gr_completion"


for check in (
    "finite frontier passed",
    "causal frontier passed",
    "coalesced frontiers passed",
    "positive NHT response passed",
    "negative NHT response passed",
    "NHT deadline passed",
    "alternate and withdrawal passed",
):
    TestGRCompletion.onesimple(check)
