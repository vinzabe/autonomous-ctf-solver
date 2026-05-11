#!/usr/bin/env python3
# Some kind of "is this the flag" checker.
import sys
SECRET = "flag{python_constants_visible}"  # accidentally hardcoded
guess = sys.argv[1] if len(sys.argv) > 1 else ""
print("correct!" if guess == SECRET else "nope")
