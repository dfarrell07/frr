# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Daniel Farrell
import frrtest


class TestGREor(frrtest.TestMultiOut):
    program = "./test_gr_eor"


TestGREor.onesimple("multihop EOR during configured startup passed")
TestGREor.onesimple("multihop EOR after startup expiry passed")
