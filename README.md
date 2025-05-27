# SimpDNS

A recursive DNS server using .NET

- Implements RFC1034, RFC1035 and a few later RFCs for modern DNS and for IPv6
- Supports UDP and TCP
- Supports A & AAAA queries and can handle CNAMEs
- SQLite for caching and negative caching, no replacement or size limit, only based on TTL
- Supports local resolution with wildcard domains
- Verbose logging (3 levels)


## Usage

1. Run the server
```
dotnet run
```

2. Query the server using python's dns library
```
py testdns.py <domain>
```

3. Query the server using dig
```
dig @localhost -p <port> <domain> <type>
```

## Config File

The server and DNS properties are in a TOML file => `config.toml`.

1. Port, TCP availability, verbosity & other DNS properties
    - `port` - The port to listen on
    - `tcp` - Whether to listen on TCP
    - `verbosity` - The verbosity of the logging
    - `db_file` - The path to the cache database file
    - `db_setup` - The path to the cache database setup file    

2. Local resolutions
Follow the instructions in the config file comments

```
# ============================================= #
#                 LOCAL RESOLUTION              #
# Add your local resolution rules under here    #
# with the format of:                           #
#                                               #
# [[simp_dns.local_resolution]]                 #
# domain = <domain>                             #
# 1 = <ipv4_address>                            #
# 28 = <ipv6_address>                           #
#                                               #
# Note: <domain> can also be a wildcard domain. #
#       Don't need both IPv4 and IPv6 addresses #
#       for local resolution to work.           #
# ============================================= #
```
