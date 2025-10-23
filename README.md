# proxy-fingerprint-worker

A Cloudflare Worker that fingerprints domains to detect reverse proxies, CDNs, and other infrastructure.

## Features

- **DNS Fingerprinting**: Queries A, AAAA, CNAME, NS, and TXT records
- **HTTP Header Analysis**: Examines response headers for proxy indicators
- **Reverse Proxy Detection**: Identifies Cloudflare, AWS CloudFront, Azure Front Door, Akamai, Fastly, and generic proxies
- **Edge Runtime**: Runs on Cloudflare's global edge network for fast responses

## API

### GET /scan

Fingerprints a domain and returns JSON with DNS records, HTTP headers, and reverse proxy detection.

**Parameters:**
- `domain` (required): The domain to fingerprint (e.g., `example.com`)

**Example Request:**
```bash
curl "https://your-worker.workers.dev/scan?domain=example.com"
```

**Example Response:**
```json
{
  "domain": "example.com",
  "timestamp": "2024-10-23T09:47:00.000Z",
  "dns": {
    "records": {
      "A": ["93.184.216.34"],
      "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
      "NS": ["a.iana-servers.net.", "b.iana-servers.net."]
    },
    "nameservers": ["a.iana-servers.net.", "b.iana-servers.net."]
  },
  "http": {
    "headers": {
      "server": "ECS",
      "x-cache": "HIT"
    },
    "statusCode": 200,
    "redirects": []
  },
  "reverseProxy": {
    "detected": true,
    "type": "Generic CDN/Cache",
    "confidence": "medium",
    "indicators": ["x-cache header: HIT"]
  }
}
```

## Deployment

### Prerequisites

- Node.js 16 or later
- A Cloudflare account (free tier works)
- Wrangler CLI installed globally

### Install Wrangler

```bash
npm install -g wrangler
```

### Authenticate with Cloudflare

```bash
wrangler login
```

### Deploy the Worker

```bash
wrangler deploy
```

The Worker will be deployed to `https://proxy-fingerprint-worker.<your-subdomain>.workers.dev`

### Local Development

Test the Worker locally using Wrangler's dev server:

```bash
wrangler dev
```

This starts a local server at `http://localhost:8787`. Test it with:

```bash
curl "http://localhost:8787/scan?domain=example.com"
```

## Configuration

The Worker configuration is in `wrangler.toml`. You can customize:

- `name`: The Worker name (used in the URL)
- `compatibility_date`: The Cloudflare Workers compatibility date

## How It Works

1. **DNS Lookup**: Uses Cloudflare's DNS over HTTPS (DoH) API to query DNS records
2. **HTTP Analysis**: Sends a HEAD request to the domain and analyzes response headers
3. **Pattern Matching**: Compares headers and DNS records against known CDN/proxy patterns
4. **Confidence Scoring**: Assigns confidence levels (high/medium/low) based on indicator strength

## Detected Proxies

The Worker can identify:

- **Cloudflare**: Via `cf-ray` header, IP ranges, or CNAME records
- **AWS CloudFront**: Via `x-amz-cf-id` header or CNAME records
- **Azure Front Door**: Via `x-azure-ref` header
- **Akamai**: Via `x-akamai-transformed` header or CNAME records
- **Fastly**: Via CNAME records
- **Generic Proxies**: Via `via`, `x-cache`, or `x-proxy` headers

## Limitations

- No external dependencies (runs on Cloudflare's edge runtime)
- No Node.js-specific APIs (pure Web APIs only)
- DNS queries limited to Cloudflare's DoH API capabilities
- HTTP analysis uses HEAD requests (some servers may behave differently for GET/POST)

## License

MIT