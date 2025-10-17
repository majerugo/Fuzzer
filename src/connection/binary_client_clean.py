import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from glob import glob
from multiprocessing import context, process
from subprocess import Popen
from tools.enable_core_dump import enable_core_dumps
from pwn import *
from printer import print_error, print_success, print_info
import subprocess
import glob
import os

PARSE_ERROR_FOR_FILE = [b"Usage", b"help"]
TMP_EXPLOIT_FILE = "/tmp/exploit_file"

class BinaryClient:
    def __init__(self, config: dict[str, str | bool | int]):
        """
        Initialize the BinaryClient with the binary path and type.
        :param config: Configuration dictionary
        """

        ## Process variables ##
        self.p = None
        self.elf = None

        ## Parse config
        self.binary_path = config.get("binary", "")
        self.verbose = config.get("verbose", False)
        self.aslr = config.get("ASLR", True)
        self.sendline = config.get("sendline", False)
        self.timeout = config.get("timeout", 5)
        # Type of binary: True for interactive, False for non-interactive
        self.process_interactive = config.get("process_interactive", None)
        # Type of input: "stdin" for stdin, "f" for file as arg, "arg" for argument, "a" for automatic
        self.type_input = config.get("type_input", None)

        if self.type_input is None:
            self.setup_type()
    
        if self.verbose:
            context.log_level = 'debug'
        else:
            context.log_level = 'error'
        ## CHECKS ##

        # Check if the binary path is set
        if not self.binary_path:
            raise ValueError("Binary path is not set.")
        
        # Check if the binary file exists
        if not os.path.isfile(self.binary_path):
            raise FileNotFoundError(f"Binary file not found: {self.binary_path}")
        
        # Check if the type_input are valid
        if self.type_input not in ["stdin", "f", "arg"]:
            raise ValueError("Invalid type_input. Must be 'stdin', 'f', or 'arg'.")

        # Check if the process_interactive is valid
        if self.process_interactive not in [True, False]:
            raise ValueError("Invalid process_interactive. Must be True (interactive) or False (non-interactive).")

        pwd = os.getcwd()
        if not pwd in self.binary_path:
            self.binary_path = pwd + "/" + self.binary_path


    def aslr_enabled(self) -> bool:
        """
        Check if ASLR is enabled for the binary.
        :return: True if ASLR is enabled, False otherwise
        """
        return self.elf.pie != 0

    def pie_enabled(self) -> bool:
        """
        Check if PIE is enabled for the binary.
        :return: True if PIE is enabled, False otherwise
        """
        return self.elf.pie != 0
    
    def get_arch(self) -> bool:
        """
        Get the architecture of the binary.
        :return: architecture of the binary
        """
        return self.elf.arch

    def is_infinite_loop(self) -> bool:
        """
        Check if the process is in an infinite loop.
        :return: True if in infinite loop, False otherwise
        """
        return self.type_input == "stdin" and self.process_interactive

    def setup_type(self):
        """
        Setup the type of binary and input based on the binary path.
        This method is called after the binary client is initialized.
        """
        print_info("There are 3 types of input for the binary: 'stdin' for standard input (stdin), 'f' for file as arg (file is passed as an argument to the binary) and 'arg' for argument (binary is run with exploitable arguments).")
        input_str = input("Enter the type of input (stdin/f/arg): ").strip().lower()
        if input_str in ["stdin", "f", "arg"]:
            self.type_input = input_str
        else:
            raise ValueError("Invalid type_input. Must be 'stdin', 'f', or 'arg'.")
        
        
    ### CHECKS ###

    def process_alive(self) -> bool:
        """
        Check if the binary process is alive.
        :return: True if the process is alive, False otherwise
        """
        if self.p is not None:
            return self.p.poll() is None
        return False
    
    def is_connected(self) -> bool:
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        return self.p is not None and self.p.connected()
    
    
    ### CONNECTIONS ###

    def connect(self) -> None:
        """
        Connect to the binary process.
        :return: None
        """
        
        self.elf = ELF(self.binary_path)
        if self.type_input != "f" and self.type_input != "arg":
            self.p = process(self.binary_path, aslr=self.aslr)
            self.p.settimeout(self.timeout)
        else:
            if self.verbose:
                print("[!] Binary is the type 'f' or 'arg' so no need to connect.")
        if self.verbose:
            print(f"Connected to binary: {self.binary_path}")

    ### SEGFAULTS ###

    def get_address_segfault(self, command):
        """
        Get the core file path
        :param command: Command to send to the binary process
        :return: Tuple of the address of the segmentation fault and if still alive
        Note: Enable verbose to see all the core dumps and the address of the segmentation fault.
        """

        # Ensure core dumps are enabled and configured to be saved in /tmp
        core_pattern = "/proc/sys/kernel/core_pattern"
        if os.path.exists(core_pattern):
            with open(core_pattern, 'r') as f:
                if f.read().strip() != "core":
                    print_error("[!] Core pattern is not set to 'core'.")
                    raise RuntimeError("Core pattern is not set to 'core'.")
        else:
            print_error("[!] Core pattern file not found.")
            raise FileNotFoundError("Core pattern file not found.")

        ## SEND COMMAND ##

        # Run the binary with the command and capture the core dump
        with enable_core_dumps("/tmp"):

            # Check for null bytes in command for argument input
            if b'\x00' in command and self.type_input == "arg":
                if self.verbose:
                    print_error("[-] Null byte detected in command for argument input. Cannot proceed.")
                return None, False

            if self.verbose:
                print_info(f"Connecting to binary: {self.binary_path} with argument: {command}")

            # Connect and send the command
            self.connect()
            ret = self.send_request(command, get_return=True)
            if self.verbose:
                print_success(f"[+] Command sent, process returned with code: {ret}")

            # Close the process
            self.close()

            if self.verbose:
                print(f"[+] Process exited with return code {ret}, checking for core dump...")

            # Check if the process is still alive
            if ret is None:
                if self.verbose:
                    print_error("[-] Process is still alive, no segmentation fault detected.")
                return None, True

            # Check if segmentation fault occurred
            if ret != 139 and ret != -11:
                if self.verbose:
                    print_error(f"[-] No segmentation fault detected for size {len(command)}.")
                return None, False

            # Read the core dump file

            core_files = glob.glob("/tmp/core*")

            if not core_files:
                raise RuntimeError("Aucun core dump trouvé dans /tmp.")
            else:
                if self.verbose:
                    print("[+] Core dump trouvé :", core_files[0])

                core = Coredump(core_files[0])

                os.remove(core_files[0])

                return hex(core.eip), False

    ### REQUESTS AND RESPONSES ###

    def send_request(self, command: str, get_return: bool = True) -> int | None:
        """
        Send a command to the binary process
        :param command: Command to send to the binary process
        :param get_return: Whether to get the return code of the process after sending the command
        :return: The return code of the binary process or None if the process is still alive
        """

        ## SEND COMMAND ##
        # Binary with stdin input
        if self.type_input == "stdin":
            # Interactive binary
            if self.verbose:
                print("Process is stdin, sending command as input.")
            if self.sendline:
                self.p.sendline(command)
            else:
                self.p.send(command)
        # Binary with file as input
        elif self.type_input == "f":
            f = open(TMP_EXPLOIT_FILE, "wb")
            f.write(command)
            f.close()
            if self.verbose:
                print("Process is a file, sending command as argument.")
            self.p = process([self.binary_path, TMP_EXPLOIT_FILE], aslr=self.aslr)
            self.p.settimeout(self.timeout)
        # Binary with argument input
        elif self.type_input == "arg":
            if self.verbose:
                print("Process is an argument, sending command as argument.")
            self.p = process([self.binary_path, command], aslr=self.aslr)
            self.p.settimeout(self.timeout)
        ## RETURN CODE ##
        if get_return:
            # Check if the process is alive
            if not self.process_alive():
                if self.verbose:
                    print("Process is not alive, returning return code.")
                
                if self.type_input == "f":
                    os.remove(TMP_EXPLOIT_FILE)
                return self.p.returncode
            else:
                if self.verbose:
                    print("Process is still alive")

                if not self.process_interactive:
                    self.p.wait()
                    if self.type_input == "f":
                        os.remove(TMP_EXPLOIT_FILE)
                    return self.p.returncode
                else:
                    return None

    def receive_response(self, arg : int | str = 4096) -> bytes | None:
        """
        Receive a response from the binary process
        :param arg: Number of bytes to receive, default is 4096 or 'line' to receive until a newline or a specific string to receive until
        :type arg: int or str
        :return: The response received from the binary process
        """
        if type(arg) == int:
            response = self.p.recv(arg)
        elif type(arg) == str and arg == 'line':
            response = self.p.recvline()
        elif type(arg) == str:
            response = self.p.recvuntil(arg.encode())
        else:
            raise ValueError("Argument must be an integer or a string ('line' or any other string to recvuntil).")
        return response

    def interactive(self) -> None:
        """
        Start an interactive session with the binary process.
        :return: None
        """
        if self.p is None:
            print("Connection not established. Call connect() first.")
            return
        if self.verbose:
            print("Starting interactive session with the binary process.")
        self.p.interactive()

    def close(self) -> None:
        """
        Close the connection to the binary process.
        :return: None
        """
        if self.verbose:
            print("Closing binary client connection.")
        if self.p:
            self.p.close()
        if self.verbose:
            print("Connection closed.")
