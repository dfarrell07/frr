# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpDelete(frrtest.TestMultiOut):
    program = "./test_bgp_delete"


TestBgpDelete.okfail("deleted instance cancels tier-two GR timer")
