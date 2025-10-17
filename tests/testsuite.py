#!/usr/bin/env python3

import unittest
import os
import glob
# from string_bug.web_none_stack_alignment import TestWebNoneStackAlignment
from string_bug.binary_none_stack_alignment import TestBinaryNoneStackAlignment
from bof.binary_f_ni_ch10 import TestBinaryOverflowNiF
from bof.binary_stdin_ni_ch15 import TestBinaryOverflowNiStdin
from bof.binary_arg_ni_ch33 import TestBinaryOverflowNiArg

def suite():
    suite = unittest.TestSuite()
    # suite.addTest(TestWebNoneStackAlignment("FindOffsetTest"))
    # suite.addTest(TestWebNoneStackAlignment("ForgetConnectTest"))
    # suite.addTest(TestWebNoneStackAlignment("FindStackAddresses"))
    suite.addTest(TestBinaryNoneStackAlignment("FindOffsetTest"))
    suite.addTest(TestBinaryNoneStackAlignment("GetStackAddresses"))
    suite.addTest(TestBinaryNoneStackAlignment("GetStackAddressesRange"))
    suite.addTest(TestBinaryNoneStackAlignment("GetStackAddressesDoubleRange"))
    suite.addTest(TestBinaryNoneStackAlignment("PrintStackAddresses"))
    suite.addTest(TestBinaryNoneStackAlignment("PrintAsciiStackAddresses"))
    suite.addTest(TestBinaryNoneStackAlignment("FindStringInStack"))
    suite.addTest(TestBinaryNoneStackAlignment("FindNotPresentStringInStack"))
    suite.addTest(TestBinaryNoneStackAlignment("Resolution"))
    suite.addTest(TestBinaryOverflowNiF("FindOffsetTest"))
    suite.addTest(TestBinaryOverflowNiStdin("FindOffsetTest"))
    suite.addTest(TestBinaryOverflowNiArg("FindOffsetTest"))
    return suite

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    result = runner.run(suite())
    # Remove all core dumps generated during the tests
    for core_file in glob.glob("/tmp/core*"):
        try:
            os.remove(core_file)
        except OSError as e:
            print(f"Error removing core file {core_file}: {e}")
    for core_file in glob.glob(os.getcwd() + "/core*"):
        try:
            os.remove(core_file)
        except OSError as e:
            print(f"Error removing core file {core_file}: {e}")
    if not result.wasSuccessful():
        exit(1)
