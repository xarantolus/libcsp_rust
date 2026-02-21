# libCSP Port Architecture

## Port Number Ranges (6-bit field: 0-63)

```
┌─────────────────────────────────────────────────────────┐
│  CSP Port Space (0-63)                                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  0-6:    Reserved Service Ports                        │
│          - Port 0: CMP (Management Protocol)           │
│          - Port 1: PING                                │
│          - Port 2: PS (Process list)                   │
│          - Port 3: MEMFREE                             │
│          - Port 4: REBOOT                              │
│          - Port 5: BUF_FREE                            │
│          - Port 6: UPTIME                              │
│                                                         │
│  7 to port_max_bind:  User Bindable Ports             │
│          - Default port_max_bind = 24                  │
│          - Your tests use port_max_bind = 58           │
│          - Application servers bind here               │
│                                                         │
│  (port_max_bind+1) to 63:  Ephemeral Ports           │
│          - Automatically assigned by csp_connect()     │
│          - Used as source port for outgoing connections│
│          - Cycled through to find unused port          │
│                                                         │
│  255 (CSP_ANY):  Wildcard - Accept on all ports       │
│          - Used with csp_bind() to catch-all           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## How Automatic Port Assignment Works

### There is NO "port 0 means auto-assign" in CSP!

Instead, ephemeral ports are automatically assigned when you **connect** (client side):

```c
// From libcsp/src/csp_conn.c
sport = (rand() % (CSP_ID_PORT_MAX - csp_conf.port_max_bind)) + (csp_conf.port_max_bind + 1);

while (++sport != start) {
    if (sport > CSP_ID_PORT_MAX)
        sport = csp_conf.port_max_bind + 1;
    
    // Check if this ephemeral port is free
    if (csp_conn_find(incoming_id.ext, CSP_ID_DPORT_MASK) == NULL) {
        // Found unused ephemeral port!
        break;
    }
}
```

### Example with Default Configuration

**Default: `port_max_bind = 24`**

```
Ports 0-24:   Available for binding (servers)
Ports 25-63:  Ephemeral pool (39 ports for clients)
Port 255:     CSP_ANY (wildcard)
```

**Your Tests: `port_max_bind = 58`**

```
Ports 0-58:   Available for binding (59 ports for servers)
Ports 59-63:  Ephemeral pool (5 ports for clients)
Port 255:     CSP_ANY (wildcard)
```

## Usage Patterns

### Server (Bind a specific port)

```rust
let sock = Socket::new(socket_opts::NONE)?;
sock.bind(10)?;        // Bind to port 10
sock.listen(5)?;

// Or bind to service port
sock.bind(ports::PING)?;  // Port 1

// Or bind to ALL ports
sock.bind(ANY_PORT)?;     // Port 255 = CSP_ANY
```

### Client (Automatic ephemeral port)

```rust
// csp_connect() automatically assigns an ephemeral port as source
let conn = node.connect(
    Priority::Norm,
    dest_addr,      // Destination address
    dest_port,      // Destination port  
    timeout,
    conn_opts::NONE
)?;

// The connection's source port is automatically assigned from the ephemeral range
// You don't specify it - CSP picks one for you!
```

## Key Differences from Traditional Networking

| Traditional TCP/IP | libCSP |
|-------------------|---------|
| Port 0 = "OS assigns port" | No port 0 auto-assign |
| Ephemeral: 49152-65535 | Ephemeral: (port_max_bind+1) to 63 |
| Bind to port 0 for auto | No bind needed - connect() auto-assigns |
| 16-bit ports (65536) | 6-bit ports (64 total) |

## Why Port 0 is NOT Auto-Assign

Port 0 has a specific, important purpose:

```c
typedef enum {
    CSP_CMP = 0,  // Management Protocol - THE MOST IMPORTANT SERVICE!
} csp_service_port_t;
```

CMP (CSP Management Protocol) handles:
- Node identification (ident)
- Route updates  
- Memory statistics
- Configuration management

**You cannot use port 0 for anything else!**

## Common Mistake

❌ **WRONG** (trying to bind port 0 for auto-assign):
```rust
sock.bind(0)?;  // This binds to CMP service port, not auto-assign!
```

✅ **CORRECT** (server binds specific port):
```rust
sock.bind(10)?;  // Bind to port 10
```

✅ **CORRECT** (client gets automatic ephemeral port):
```rust
// No bind needed - connect() assigns ephemeral source port automatically
let conn = node.connect(Priority::Norm, dest_addr, 10, timeout, opts)?;
```

## Checking Ephemeral Port Range

```rust
// Your configuration
CspConfig::new()
    .port_max_bind(58)  // Bindable: 0-58, Ephemeral: 59-63
    .init()?;
```

To allow more ephemeral ports, **decrease** `port_max_bind`:

```rust
CspConfig::new()
    .port_max_bind(40)  // Bindable: 0-40, Ephemeral: 41-63 (23 ports!)
    .init()?;
```

## Why CSP_ID_PORT_MAX - port_max_bind Must Be > 0

```c
sport = (rand() % (CSP_ID_PORT_MAX - csp_conf.port_max_bind)) + ...
                 // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                 // If this is 0, you get division by zero!
```

This is why `port_max_bind = 63` causes SIGFPE - no ephemeral ports available!
