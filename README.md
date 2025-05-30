# Enhanced Ping Utility

A feature-rich ping utility with support for multiple targets, statistics, and various display options.

## Features

- Multiple target support
- Configurable packet sizes
- Detailed statistics (packet loss, RTT, jitter)
- Verbose mode with header information
- DNS resolution display
- Quiet mode
- Custom timeout settings

## Building from Source

### Debian Linux

1. Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install gcc make libc6-dev
```

2. Compile the program:
```bash
gcc fping.c -o fping -lm
```

3. Install the man page:
```bash
sudo mkdir -p /usr/local/share/man/man1
sudo cp fping.1 /usr/local/share/man/man1/
sudo mandb
```

### Windows

1. Install MinGW or Cygwin:
   - MinGW: Download and install from [MinGW website](https://www.mingw-w64.org/)
   - Cygwin: Download and install from [Cygwin website](https://www.cygwin.com/)

2. Using MinGW:
```batch
gcc fping.c -o fping.exe -lws2_32 -lm
```

3. Using Cygwin:
```bash
gcc fping.c -o fping.exe -lm
```

Note: The man page is not typically used on Windows systems.

## Usage

### Linux
```bash
# Basic usage
sudo ./fping google.com

# Multiple targets with verbose output
sudo ./fping -v google.com facebook.com

# Quiet mode with custom packet size
sudo ./fping -q -s 100 google.com

# Show DNS resolution with custom timeout
sudo ./fping -d -t 2000 google.com
```

### Windows
```batch
# Run as Administrator
fping.exe google.com

# Multiple targets
fping.exe -v google.com facebook.com
```

## Command Line Options

- `-v`: Verbose output
- `-q`: Quiet output (statistics only)
- `-d`: Show DNS resolution
- `-s size`: Set packet size (8-65527 bytes)
- `-t ms`: Set timeout (100-60000 ms)

## Viewing the Manual

### Linux
```bash
# After installation
man fping

# Direct from file
man ./fping.1
```

### Windows
- The manual content can be viewed in the source file `fping.1`
- Or access this README for quick reference

## Requirements

### Linux
- GCC compiler
- Root privileges for raw sockets
- Math library (libm)

### Windows
- MinGW or Cygwin
- Administrator privileges
- WinSock2 library (ws2_32)

## Common Issues

1. "Operation not permitted":
   - Run with sudo/administrator privileges

2. Compilation errors:
   - Ensure all required libraries are installed
   - Check if math library is linked (-lm)

3. Man page not found:
   - Run `sudo mandb` after installation
   - Check if man page is in correct directory
