#!/usr/bin/env python3

import sys

# Constants
EXCEPTIONS = []


def main():
    host = init()
    # Change code below here, using the host variable


# Do not change this function
def init():

    # Check for one argument
    if len(sys.argv) == 2:

        # Get host argument
        host = sys.argv[1]

        # Check if subnet in exceptions
        if host in EXCEPTIONS:
            exit(1)
        return host

    else:
        print("Only argument is host")
        exit(1)


if __name__ == "__main__":
    main()
