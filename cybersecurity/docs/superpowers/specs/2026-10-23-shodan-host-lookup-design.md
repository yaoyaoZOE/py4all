# Shodan Host Lookup Demo Design

## Goal

Provide a small Python demo that looks up one public IP address the user owns or is authorized to assess, using Shodan's Host API.

## Approach

Use Python's standard-library `urllib` and `json` rather than adding the Shodan SDK as a dependency. Read the API key from `SHODAN_API_KEY`; accept the target IP as a required command-line argument.

## Behavior

- Make one Host API request for the supplied IP; do not perform broad searches, batch lookups, or active scans.
- Print a concise summary containing the IP, organization, country, and open ports.
- Fail clearly when the API key is missing, the IP argument is invalid, the request fails, or Shodan returns an API error.
- Keep the API key out of source code and avoid printing it.

## Validation

Check argument and missing-key handling without network access. Keep the HTTP request isolated so its response and API error behavior can be tested with a mocked response.
