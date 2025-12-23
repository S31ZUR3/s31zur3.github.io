web

The challenge involves a simple TCP server that asks for a "secret passphrase received from the environment". The Python source code (reservation.py) reveals that the server compares the user input against an environment variable named PROMPT.

PROMPT = os.getenv("PROMPT", "bananananannaanan")
...
if response == PROMPT:
    client_socket.sendall(b"Thank you for your patience. Here is your flag: " + FLAG.encode())

The server's banner ([windows_10 | cmd.exe]) and a curious comment in the source code about the WINDIR environment variable (`# This is missing from the .env file, but it still printed something, interesting`) strongly hint that the server is running on a Windows environment, or an environment designed to emulate Windows environment variables.

On Windows systems, the default value for the PROMPT environment variable is $P$G (which stands for current Path + Greater-than symbol).

Therefore, sending "$P$G" as the passphrase satisfies the server's check and returns the flag.

Flag:
nullctf{why_1s_it_r3srv3d_ceed3c0e6c3d10c3}