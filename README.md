# LogBucket

Syslog collector and fanout server.

TCP(+TLS) input, json and regex parser, zstandard file output, unix socket outputs for integration

### Features

* Highly concurrent tcp syslog(+tls) receiver
* Easy configuration of any number of regexes to parse inputs (tested in order of capture group count)
* Built in line based json parsing
* Arbitrary number of unix socket forwards for integration with other systems
* Plain TCP and TLS handling (use nftables to forward :514 to :6514) 
* Non-blocking TLS handshakes off main accept loop
* Zstandard inline compressed file outputs
* Arbitrary time buckets for batched output file management
* Automatic self-signed SSL generation for testing
* Easy active log debugging with `nc -l -k -U /tmp/debug.sock` (if configed as an output)


### Nftables forwarding

```bash
# Forward non-tls syslog to syslog-tls listener
nft add rule nat prerouting tcp dport 514 redirect to 6514
```
