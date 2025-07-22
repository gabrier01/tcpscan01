# tcpscan01

This is a TCP port scanner written in C that performs a complete three-way handshake to determine if specified ports are open on a given hostname.

> [!NOTE]
> This program was developed for educational purposes to reinforce knowledge in port scanning, TCP sockets, and multithreading in C. It may have some bugs.

**Features**

- Supports both IPv4 and IPv6 (with -6 flag)
- Verbose mode for detailed output (-v)
- Banner grabbing to identify services (-b)
- Adjustable connection timeout (-t <ms>)
- Adjustable concurrency for faster scans (-c <number>)
- Scans specified ports provided via -p <ports>

**Compilation**

```shell
gcc tcpscan01.c -pthread -o tcpscan01
```

**Usage**

To run the program, use the following command:
```shell
./tcpscan01 -H <hostname> -p <ports> [options]
```

**Required Arguments**

- `-H <hostname>`: Specifies the hostname to scan
- `-p <ports>`: Specifies the list of ports to scan, separated by commas

**Options**

- `-6`: Enables IPv6 support (default: IPv4 only)
- `-v`: Enables verbose mode, displaying detailed information
- `-b`: Enables banner grabbing (may significantly slow down the scan)
- `-h`: Prints the help message
- `-t <ms>`: Sets the connection timeout in milliseconds (default: 100, range: 50-10000)
- `-c <number>`: Sets the number of concurrent threads (default: 5, range: 1-50)
