import sys

from pwn import *

# Constants
EXCEPTIONS = []


def main():
    host = init()
    # Change code below here, using the host variable

    # Create the connection (change 6969 to appropriate port)
    r = remote(host, 6969)

    # Receive some data
    r.recvuntil(":")

    # Send some data
    r.sendline("exploit")

    # Get the flag and close the connection
    print(r.recvuntil("}"))
    r.close()


# Do not change this function
def init():
    # Make pwntools less verbose
    context.log_level = "error"

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
