# Distributed Network File System

A distributed network file system implementation featuring a Naming Server, multiple Storage Servers with replication support, and Client interface. The system provides fault tolerance through data replication and supports a wide range of file operations.

## Architecture

### Components

1. **Naming Server**
   - Manages the global namespace and file system hierarchy
   - Coordinates storage server registration and health monitoring
   - Handles client request routing and load balancing
   - Manages file replication and backup strategies
   - Maintains file system consistency and access control

2. **Storage Servers**
   - Store and manage actual file data
   - Handle file operations (read, write, create, delete)
   - Support file replication and backup
   - Manage local file system operations
   - Stream audio files and handle large file transfers

3. **Client Interface**
   - Provides user interface for file operations
   - Supports multiple concurrent client connections
   - Handles file transfer and streaming

## Features

- **Basic File Operations**
  - Read/Write files
  - Create/Delete files and directories
  - Copy files between storage servers
  - List directory contents
  - Get file information (size, permissions, last modified)

- **Advanced Features**
  - File replication and backup
  - Audio file streaming
  - Large file handling
  - Priority write operations
  - Append mode support
  - Health monitoring and fault tolerance

- **System Features**
  - Distributed architecture
  - Load balancing
  - Fault tolerance through replication
  - Concurrent client support
  - JSON-based communication protocol

## Prerequisites

- Linux operating system
- GCC compiler
- libjson-c library
- pthread support

## Installation

1. Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install build-essential libjson-c-dev
```

2. Compile the components:

For Naming Server:
```bash
cd naming_server_code
gcc -o ns tcode5.c -lpthread -ljson-c
```

For Storage Server:
```bash
cd storage_server_code
gcc -o storage_server storage_server.c -lpthread -ljson-c
```

For Client:
```bash
cd client_code
gcc -o client client.c -lpthread -ljson-c
```

## Usage

1. Start the Naming Server:
```bash
./ns <port>
```

2. Start Storage Servers:
```bash
./storage_server <server_id> <naming_server_ip> <naming_server_port> <client_port>
```

3. Run the Client:
```bash
./client <naming_server_ip> <naming_server_port>
```

### Available Client Operations

- `read` - Read file contents
- `write` - Write to file (with append/overwrite options)
- `delete` - Delete files or directories
- `create` - Create files or directories
- `copy` - Copy files between locations
- `stream` - Stream audio files
- `getfileinfo` - Get file metadata
- `list` - List directory contents

## Important Notes

1. When creating or copying directories, always include a trailing slash (/).
2. Main server implementation is in `tcode5.c`.
3. File paths are relative to storage server root directories.
4. The system supports multiple storage server instances with replication.

## Configuration

- Storage servers read their configuration from `configuration.txt`
- Available paths are configured in `available_paths.txt`
- Each instance maintains its own `myserver/` directory for file storage

## Implementation Details

- Uses JSON for inter-process communication
- Implements thread-safe operations with mutex locks
- Supports both synchronous and asynchronous write operations
- Maintains file system hierarchy using tree data structure
- Implements LRU caching for performance optimization
- Supports file streaming with chunked transfer

## Error Handling

- Path validation
- Server health monitoring
- Concurrent access control
- File operation atomicity
- Network communication reliability
