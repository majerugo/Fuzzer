from connection.ssh_client import SSHClient
from connection.web_client import WebClient
from connection.binary_client_clean import BinaryClient
from tools.pattern_tools import extract_tokens
from printer import print_info, print_success
import os

class Dispatcher:
    def __init__(self, config):

        self.config = config
        self.client = None

        # Template for injecting payloads.
        # Exemple :
        #  send_payload_template: "username=__PAYLOAD__"
        self.send_payload_template = self.config.get("send_payload_template", None)

        # Template for extracting information from received payloads.
        # Exemple :
        #  receive_payload_template: "Welcome user at address __EXTRACT__"
        self.receive_payload_template = self.config.get("receive_payload_template", None).encode() if self.config.get("receive_payload_template", None) else None

        # Initial instructions to execute before starting the exploit
        # Exemple :
        #  init_instructions:
        #    - ["recv", 1024]
        #    - ["send", "username=admin"]
        #    - ["recv", "Password:"]
        #    - ["send", "password=admin"]
        self.init_instructions = config.get("init_instructions", None)

        # If set to True, the process will be kept open after sending a command and will handle multiple send/receives.
        # Useful for interactive sessions
        self.process_interactive = self.config.get("process_interactive", None)

        if self.process_interactive is None:
            self.setup_type()

        self.verbose = config.get("verbose", False)
        
        # NOT REALLY IMPLEMENTED
        if self.config["mode"] == "ssh":
            self.client = SSHClient(
                self.config["ssh"]["host"],
                self.config["ssh"].get("port", 22),
                self.config["ssh"]["user"],
                self.config["ssh"].get("password", None),
                verbose=self.config.get("verbose", False)
            )
        # NOT REALLY IMPLEMENTED
        elif self.config["mode"] == "web":
            self.client = WebClient(
                self.config["url"],
                self.config["port"],
                verbose=self.config.get("verbose", False)
            )
        # TRY IMPLEMENTED
        elif self.config["mode"] == "binary":
            self.client = BinaryClient(self.config)
        else:
            raise ValueError("Unsupported mode: {}".format(self.config["mode"]))

        self.cmd_to_send = config.get("cmd_to_send", b"")
    def aslr_enabled(self) -> bool:
        """
        Check if ASLR is enabled for the binary.
        :return: True if ASLR is enabled, False otherwise
        """
        if self.client and hasattr(self.client, 'aslr_enabled'):
            return self.client.aslr_enabled()
        else:
            raise ValueError("Client does not support ASLR check or is not initialized")

    def pie_enabled(self) -> bool:
        """
        Check if PIE is enabled for the binary.
        :return: True if PIE is enabled, False otherwise
        """
        if self.client and hasattr(self.client, 'pie_enabled'):
            return self.client.pie_enabled()
        else:
            raise ValueError("Client does not support PIE check or is not initialized")

    def get_arch(self) -> bool:
        """
        Get the architecture of the binary.
        :return: architecture string (e.g. 'x86', 'x86_64', 'arm', 'aarch64')
        """
        if self.client and hasattr(self.client, 'get_arch'):
            return self.client.get_arch()
        else:
            raise ValueError("Client does not support architecture check or is not initialized")
        
    def is_infinite_loop(self) -> bool:
        """
        Check if the process is in an infinite loop.
        :return: True if in infinite loop, False otherwise
        """
        if self.client and hasattr(self.client, 'is_infinite_loop'):
            return self.client.is_infinite_loop()
        else:
            raise ValueError("Client does not support infinite loop check or is not initialized")


    def is_connected(self):
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        if self.client:
            return self.client.is_connected()
        else:
            raise ValueError("Client not initialized")
        
    def is_interactive(self):
        """
        Check if the client is interactive.
        :return: True if interactive, False otherwise
        """
        if self.process_interactive != None:
            return self.process_interactive
        else:
            raise ValueError("Process interactivity not set.\nSet `process_interactive` in config.\nCheck README for more information.")

    def setup_type(self):
        """
        Setup the process interactivity based on the user input.
        :param process_interactive: True if the process is interactive, False otherwise
        :return: None
        """
        print_info("There are 2 types of process: 'i' for interactive (while True loop) and 'ni' for non-interactive (send a command and the process exits).")
        input_str = input("Enter the type of process (i/ni): ").strip().lower()
        if input_str in ["i", "ni"]:
            self.process_interactive = input_str == "i"
            self.config["process_interactive"] = self.process_interactive
        else:
            raise ValueError("Invalid type_process. Must be 'i' or 'ni'.")

    def connect(self):
        if self.client:
            if self.init_instructions:
                self.client.connect()
                self.parse_instructions(self.init_instructions)
            else:
                self.client.connect()
        else:
            raise ValueError("Client not initialized")
        
    def get_segfault(self, command):
        if self.client and hasattr(self.client, 'get_address_segfault'):
            if self.send_payload_template:
                if isinstance(command, bytes):
                    command_str = command.decode()
                else:
                    command_str = command
                command_str = self.send_payload_template.replace("__PAYLOAD__", command_str)
                command = command_str.encode()
            return self.client.get_address_segfault(command)
        else:
            raise ValueError("Client does not support segfault retrieval or is not initialized")

    def send_command(self, command : bytes, get_return=True):
        if self.client:

            # Apply the send payload template if defined
            if self.send_payload_template:
                if isinstance(command, bytes):
                    command_str = command.decode()
                else:
                    command_str = command
                command_str = self.send_payload_template.replace("__PAYLOAD__", command_str)
                command = command_str.encode()

            if self.process_interactive:
                if self.verbose:
                    print_info("Process is interactive")
                if not self.client.process_alive():
                    raise ValueError("Process is not alive. Cannot send command.")
            else:
                if self.verbose:
                    print_info("Process is non-interactive")



            if self.client.verbose:
                print_info(f"Sending command: {command}")
            return self.client.send_request(command, get_return=get_return)
        else:
            raise ValueError("Client not initialized")
        
    def receive_response(self, arg=4096, disable_template=False):
        """
        Receive a response from the target service.
        :param arg: Number of bytes to receive, default is 4096 or 'line' to receive until a newline or a specific string to receive until
        :type arg: int or str
        :return: The response received from the target service
        """
        if self.client:
            response = self.client.receive_response(arg)
            if self.receive_payload_template and response and not disable_template:
                tokens = extract_tokens(self.receive_payload_template, response)

                return tokens["__EXTRACT__"] if tokens and "__EXTRACT__" in tokens else None
            return response if response else None
        else:
            raise ValueError("Client not initialized")
        
    def find_shell(self, payload:bytes = b"") -> bool:
        """
        Check if the binary process is a shell by sending a payload and checking the response.
        :param payload: The payload to send to the binary process
        :return: True if the binary process is a shell, False otherwise
        """

        # If no payload is provided, use a default payload
        if self.client is None:
            raise ValueError("Client not initialized")
        if self.verbose:
            print("Checking if the binary process is a shell.")

        # Connect and send the payload
        self.connect()
        self.send_command(payload, get_return=False)
        self.receive_response(disable_template=True)

        # Send 'id' command to check for shell
        self.client.p.send(b"id\nexit\n")
        data = self.receive_response(disable_template=True)

        # Close the connection
        self.close()

        # Check if the response contains 'uid=' and 'gid='
        if data and b"uid=" in data and b"gid=" in data:
            print_success(f"[+] Find a shell ! With the payload : {payload}.")
            if self.cmd_to_send:
                print_success(f"[+] Sending command to get the flag: {self.cmd_to_send}")
                self.connect()
                self.send_command(payload, get_return=False)
                self.receive_response(disable_template=True)
                self.client.p.send(self.cmd_to_send.encode() + b"\nexit\n")
                flag_data = self.receive_response(disable_template=True)
                if flag_data:
                    print_success(f"[+] Flag data: {flag_data.decode(errors='ignore')}")
                self.close()
            return True
        return False

    def close(self):
        if self.client:
            self.client.close()
        else:
            raise ValueError("Client not initialized")
        
    def parse_instructions(self, instructions):
        """
        Send the initial instructions to the target service.
        :param instructions: List of instructions to execute, this list should contain tuples of (command, argument)
                             Commands can be "recv" or "send". Careful with the command "recv" for recv an int you should give an integer and not a string.
        :return: None
        """
        if instructions and self.is_connected():
            for command, arg in instructions:
                if self.client.verbose:
                    print_info(f"Executing command: {command} with arg: {arg}")
                if command == "recv":
                    response = self.receive_response(arg)
                    if self.client.verbose:
                        print_info(f"Received: {response}")
                elif command == "send":
                    if isinstance(arg, str):
                        arg = arg.encode()
                    elif not isinstance(arg, bytes):
                        raise ValueError("Argument must be a string or bytes")
                    if self.client.verbose:
                        print_info(f"Sending: {arg}")
                    self.send_command(arg)
                else:
                    raise ValueError(f"Unknown command: {command}")
        else:
            raise ValueError("Instructions not set up or client not connected. Call setup_init_instructions() or connect() first.")
        
    def interactive(self):
        """
        Start an interactive session with the target service.
        :return: None
        """
        if self.client:
            self.client.interactive()
        else:
            raise ValueError("Client not initialized")
