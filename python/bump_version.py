"""Bump build number in VERSION file."""
import os
import sys

def bump():
    ver_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
    ver = open(ver_file).read().strip()
    parts = ver.split(".")
    if len(parts) == 3:
        parts[2] = str(int(parts[2]) + 1)
    else:
        parts = ["1", "0", "1"]
    new_ver = ".".join(parts)
    open(ver_file, "w").write(new_ver + "\n")
    print(new_ver)

if __name__ == "__main__":
    bump()
