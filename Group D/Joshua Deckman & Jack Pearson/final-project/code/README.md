# ECE4301-Final

## Project Structure ##

- `src/`
    - `main.rs`: Main Rust code
- `benchmark.csv`: Raw data from a test sweep
- `benchmarking.py`: Python script for running test sweeps
- `run-client.sh`: A script used for regulating network connections, as explained in this readme
- `README.md`: This readme file

## Walk-through

This project serves to benchmark the post-quantum cryptographic public key
exchange system called Kyber by comparing the performance of Kyber to 
that of the Diffie-Hellman key exchange protocol. To accomplish this, 
this project creates a server and a client that participate 
in these key exchanges.

**This project is meant to be run on a single Linux system so that the network stack 
can be explicitly controlled.**

Begin by building the Rust code for the client and server: 

```bash
cargo build
```

To start the server, open a terminal and enter the following command:

```bash
./target/debug/ECE4301-Final server 0.0.0.0 9000
```

With the server running, open another terminal through which to run the rest of the 
project. In the new terminal, the application itself can be tested with a command 
like the following:

```bash
sudo ./run-client.sh target/debug/ECE4301-Final 4kbit 0ms client diffie-hellman 10.200.1.1 9000
```

The `run-client.sh` script is used to regulate the network stack while running a key exchange.
The arguments used here are explained later. After running this, you should see something like:

```
Diffie-Hellman exchange time: 1620.283 ms
```

This means that Diffie-Hellman key exchange took 1620.283 ms with a 4kbit/s
data rate on the connection and 0ms delay introduced.
Parameters only need to be specified on the client's side as they are passed to the
server over the network before running the benchmark.

The first three parameters, `target/debug/ECE4301-Final`, `4kbit`, and `0ms`
are used by the script to find the Rust binary and configure the simulated
network connection.

The next four, `client`, `diffie-hellman`, `10.200.1.1`, and `9000` are
forwarded to the Rust binary. `client` puts it in client mode,
`diffie-hellman` initiates a Diffie-Hellman key exchange, `10.200.1.1` and
`9000` indicate the server address and port. The server address is hard-coded
to be `10.200.1.1` with the simulated network connection, so that address must
be passed for benchmarking.

You can pass `kyber` instead of `diffie-hellman` and get the kyber key-exchange time.
With the same network parameters our results are:

```
Kyber exchange time: 4780.538 ms
```

Note that the server *does not need to be restarted* as you run these
different benchmarks.

### Network Buffer Testing ###

There is also a `buffer-exchange` mode which can be invoked like this:

```bash
$ sudo ./run-client.sh target/debug/ECE4301-Final 8kbit 0ms client buffer-exchange 10.200.1.1 9000 --buffer-size 1000
RTT for 1000 bytes: 2960.226 ms
```

RTT is Round Trip Time. The buffer-exchange mode simply writes a buffer to the
server, then reads back an identical size buffer from the server.

Here, we specified `--buffer-size 1000` and network rate `8kbit` and network
latency `0ms`.

You would expect the 1000 bytes to take exactly 1 second to go over a 8kbit/s
connection, then another 1 second as 1000 bytes are written back on the return
path. But rather than a clean `2000 ms` we get `2960.226 ms`. There is a bunch of
overhead from TCP which doesn't really go away. The error goes down somewhat
with bigger transactions (`80kbit`, `0ms`, `--buffer-size 10000` gives
`2683.627 ms` for us), but it doesn't go away.

You can also inspect raw effect of the latency with `buffer-exchange` mode.

```bash
$ sudo ./run-client.sh target/debug/ECE4301-Final 1mbit 10ms client buffer-exchange 10.200.1.1 9000 --buffer-size 1
RTT for 1 bytes: 43.765 ms
```

See how we set the bandwidth to something super high so we can forget about it
(`1mbit`), set delay to `10ms`, and `--buffer-size 1`. So we're literally just
timing RTT of a single byte.

You would expect it to be 2 * 10ms = 20ms. But in fact it's 43.765. This is
again due to TCP under the hood. Every transfer has to be ACK'd, so in reality
two round trips are made. 4 * 10ms = 40ms, and so we see that delay is
working too.

There is a `--debug` flag you can pass too to enable logging and validate that
the shared secrets computed in `kyber` and `diffie-hellman` mode match on
client and server, among other things.

## Benchmarking ##

A Python script (`benchmarking.py`) is included to run a series of automated 
benchmark tests to compare Kyber to Diffie-Hellman. The script iterates 
through multiple network rates and network delays between bounds specified 
by the user. It has the following positional arguments: 

* `filename`: The output CSV file to be made
* `min_rate`: The lower bound on the network rates to be tested 
* `max_rate`: The upper bound on the network rates to be tested 
* `rate_step`: The difference in the tested network rate between iterations
* `min_delay`: The lower bound on the network delay to be tested
* `max_delay`: The upper bound on the network delay to be tested
* `delay_step`: The difference in the tested network delay between iterations

For this project, we tested 20 different network rates across 4 different 
network delays. This was done with the following command:

    sudo python3 benchmarking.py benchmark.csv 50 550 50 0 100 25

To replicate this benchmark yourself, ensure that the server is running before executing this command.

## Reference Material

### Running the Server

```bash
./target/debug/ECE4301-Final server <host> <port>
```

**Parameters:**
- `server` - Subcommand to run in server mode
- `<host>` - Host address to bind to (e.g., `0.0.0.0` to listen on all interfaces)
- `<port>` - Port number to listen on

**Example:**
```bash
./target/debug/ECE4301-Final server 0.0.0.0 9000
```

The server accepts incoming TCP connections and handles different key exchange modes based on what the client requests.

### Running the Client

```bash
sudo ./run-client.sh <binary_path> <rate> <delay> client <mode> <host> <port>
```

This script creates a network namespace with traffic control to simulate network conditions, then runs the client inside it.

**Script Parameters:**
1. `<binary_path>` - Path to the compiled binary (e.g., `target/debug/ECE4301-Final`)
2. `<rate>` - Network bandwidth limit (e.g., `4kbit` = 4 kilobits per second)
3. `<delay>` - Network delay to simulate (e.g., `0ms` = no added delay, `25ms` for simulated latency)
4. `client` - Subcommand to run in client mode
5. `<mode>` - Client mode (see below)
6. `<host>` - Server IP address
7. `<port>` - Server port (matching port specified when launching the server)

**Client Modes:**
- `diffie-hellman` - Diffie-Hellman key exchange
- `kyber` - Kyber (post-quantum) key exchange
- `buffer-exchange -b <size>` - Buffer exchange with specified size in bytes

**Example:**
```bash
sudo ./run-client.sh target/debug/ECE4301-Final 4kbit 0ms client diffie-hellman 10.200.1.1 9000
```

The `run-client.sh` script sets up a virtual network with MTU=256 bytes, applies rate limiting and delay using Linux traffic control (tc), then executes the client binary in this constrained environment to measure algorithm performance under constrained network conditions.
