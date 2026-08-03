# Superseded suites

These split one example into several tests — apply, SSIDs up, associate — which
applied the same config three or four times and made a single example appear as
several unrelated results.

`tests/regression/test_examples.py` replaces them: one test per example per
band, with those checks as ordered steps and a single result.

Kept for reference; not collected (outside `testpaths`).
