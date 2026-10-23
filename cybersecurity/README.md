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
