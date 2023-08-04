# LogBucket

Syslog collector and fanout server.

TCP(+TLS) input with n\*unix socket outputs

### Features

* Highly concurrent tcp syslog(+tls) receiver
* Arbitrary number of unix socket forwards for integration with other systems
* Plain TCP and TLS handling (use nftables to forward :514 to :6514) 
* TLS handshake performed off primary listener goroutine as to not block other clients during slow negotiation
* Zstandard inline compressed file outputs
* Arbitrary time buckets for batched output file management
* Automatic self-signed SSL generation for testing
* Easy active log debugging with `nc -l -k -U /tmp/debug.sock` (if configed as an output)