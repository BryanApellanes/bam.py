"""Runs the tests for CI, from the tests directory, and holds the run to more than "nothing failed".

    cd tests && python ../tools/run_tests.py

The run fails when a test fails, when no tests ran (Python before 3.12 reports an empty run as a
success), and when a test is skipped anywhere but Windows. The only skip by design is the key file
mode test, which is a Unix test, so a skip on Linux means that test has quietly stopped running.
"""
import sys
import unittest


def main():
    suite = unittest.defaultTestLoader.discover(".")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        return 1
    if result.testsRun == 0:
        print("FAILED: no tests ran.")
        return 1
    if result.skipped and sys.platform != "win32":
        print("FAILED: %d test(s) skipped on %s: %s" % (
            len(result.skipped), sys.platform, ", ".join(str(test) for test, _ in result.skipped)))
        return 1
    print("%d tests ran, %d skipped." % (result.testsRun, len(result.skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
