#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the renamed native execution engine."""
import sys
import native_exchange

if __name__ == "__main__":
    native_exchange.main()
else:
    # Preserve one module state, including patched transports, during migration.
    sys.modules[__name__] = native_exchange
