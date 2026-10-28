# Shodan Host Lookup Demo

This standard-library Python CLI makes one passive Shodan Host API lookup for a
public IP address you own or are authorized to assess. It does not scan targets
or search across the Internet.

Set your Shodan API key in the environment; do not put it in source code:

```powershell
$env:SHODAN_API_KEY = "your-shodan-api-key"
```

Run the lookup with an authorized public IP:

```powershell
python .\shodan_demo.py 8.8.8.8
```

The output summarizes the IP, organization, country, and open ports. The demo
uses only Python's standard library and requires no package installation.

## DNS Resolution Demo

Install the DNS query dependency from this directory:

```powershell
python -m pip install -r requirements.txt
```

Resolve a hostname and query its A records:

```powershell
python .\dns_demo.py example.com
```

Choose another supported record type:

```powershell
python .\dns_demo.py example.com --type MX
```

The demo prints IPv4/IPv6 addresses from the operating-system resolver and
answers for one selected DNS record type using the system-configured DNS
resolver. Supported types are A, AAAA, CNAME, MX, NS, and TXT.
