import sys
import dns.message
import dns.query

PORT = 8000

query = dns.message.make_query(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "A")
response = dns.query.udp(query, "127.0.0.1", port=PORT)

print(response)
