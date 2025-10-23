/**
 * Cloudflare Worker for domain fingerprinting
 * Exposes a /scan endpoint that performs DNS and HTTP header analysis
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Only handle /scan endpoint
    if (url.pathname !== '/scan') {
      return new Response(JSON.stringify({ error: 'Not found. Use /scan endpoint' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Only accept GET requests
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ error: 'Method not allowed. Use GET' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Get domain from query parameter
    const domain = url.searchParams.get('domain');
    if (!domain) {
      return new Response(JSON.stringify({ error: 'Missing domain parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate domain format
    if (!isValidDomain(domain)) {
      return new Response(JSON.stringify({ error: 'Invalid domain format' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    try {
      // Perform fingerprinting
      const fingerprint = await fingerprintDomain(domain);
      
      return new Response(JSON.stringify(fingerprint, null, 2), {
        status: 200,
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache'
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({ 
        error: 'Failed to fingerprint domain',
        message: error.message 
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};

/**
 * Validate domain format
 */
function isValidDomain(domain) {
  // Basic domain validation regex
  const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
  return domainRegex.test(domain);
}

/**
 * Fingerprint a domain by performing DNS and HTTP header analysis
 */
async function fingerprintDomain(domain) {
  const result = {
    domain,
    timestamp: new Date().toISOString(),
    dns: await performDNSFingerprint(domain),
    http: await performHTTPFingerprint(domain)
  };
  
  // Analyze results to detect reverse proxy
  result.reverseProxy = detectReverseProxy(result);
  
  return result;
}

/**
 * Perform DNS fingerprinting
 */
async function performDNSFingerprint(domain) {
  const dnsResult = {
    records: {},
    nameservers: []
  };
  
  try {
    // Check A records using DNS over HTTPS (Cloudflare)
    const aRecords = await queryDNS(domain, 'A');
    if (aRecords && aRecords.length > 0) {
      dnsResult.records.A = aRecords;
    }
    
    // Check AAAA records
    const aaaaRecords = await queryDNS(domain, 'AAAA');
    if (aaaaRecords && aaaaRecords.length > 0) {
      dnsResult.records.AAAA = aaaaRecords;
    }
    
    // Check CNAME records
    const cnameRecords = await queryDNS(domain, 'CNAME');
    if (cnameRecords && cnameRecords.length > 0) {
      dnsResult.records.CNAME = cnameRecords;
    }
    
    // Check NS records
    const nsRecords = await queryDNS(domain, 'NS');
    if (nsRecords && nsRecords.length > 0) {
      dnsResult.nameservers = nsRecords;
    }
    
    // Check TXT records
    const txtRecords = await queryDNS(domain, 'TXT');
    if (txtRecords && txtRecords.length > 0) {
      dnsResult.records.TXT = txtRecords;
    }
  } catch (error) {
    dnsResult.error = error.message;
  }
  
  return dnsResult;
}

/**
 * Query DNS using Cloudflare's DNS over HTTPS
 */
async function queryDNS(domain, type) {
  try {
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    const response = await fetch(dohUrl, {
      headers: { 'Accept': 'application/dns-json' }
    });
    
    if (!response.ok) {
      return null;
    }
    
    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      return data.Answer.map(answer => answer.data);
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Perform HTTP header fingerprinting
 */
async function performHTTPFingerprint(domain) {
  const httpResult = {
    headers: {},
    statusCode: null,
    redirects: []
  };
  
  try {
    // Try HTTPS first
    const httpsUrl = `https://${domain}`;
    const httpsResponse = await fetch(httpsUrl, {
      method: 'HEAD',
      redirect: 'manual'
    });
    
    httpResult.statusCode = httpsResponse.status;
    
    // Capture interesting headers
    const interestingHeaders = [
      'server',
      'x-powered-by',
      'x-frame-options',
      'x-content-type-options',
      'strict-transport-security',
      'content-security-policy',
      'x-xss-protection',
      'via',
      'x-cache',
      'x-proxy',
      'x-forwarded-for',
      'x-real-ip',
      'cf-ray',
      'x-amz-cf-id',
      'x-azure-ref',
      'x-cdn',
      'x-akamai-transformed'
    ];
    
    for (const header of interestingHeaders) {
      const value = httpsResponse.headers.get(header);
      if (value) {
        httpResult.headers[header] = value;
      }
    }
    
    // Check for redirects
    if (httpsResponse.status >= 300 && httpsResponse.status < 400) {
      const location = httpsResponse.headers.get('location');
      if (location) {
        httpResult.redirects.push({
          from: httpsUrl,
          to: location,
          statusCode: httpsResponse.status
        });
      }
    }
  } catch (error) {
    httpResult.error = error.message;
  }
  
  return httpResult;
}

/**
 * Detect reverse proxy based on fingerprint data
 */
function detectReverseProxy(fingerprint) {
  const indicators = {
    detected: false,
    type: null,
    confidence: 'none',
    indicators: []
  };
  
  // Check HTTP headers for reverse proxy indicators
  const headers = fingerprint.http.headers;
  
  // Cloudflare detection
  if (headers['cf-ray']) {
    indicators.detected = true;
    indicators.type = 'Cloudflare';
    indicators.confidence = 'high';
    indicators.indicators.push('cf-ray header present');
  }
  
  // AWS CloudFront detection
  if (headers['x-amz-cf-id']) {
    indicators.detected = true;
    indicators.type = 'AWS CloudFront';
    indicators.confidence = 'high';
    indicators.indicators.push('x-amz-cf-id header present');
  }
  
  // Azure Front Door detection
  if (headers['x-azure-ref']) {
    indicators.detected = true;
    indicators.type = 'Azure Front Door';
    indicators.confidence = 'high';
    indicators.indicators.push('x-azure-ref header present');
  }
  
  // Akamai detection
  if (headers['x-akamai-transformed']) {
    indicators.detected = true;
    indicators.type = 'Akamai';
    indicators.confidence = 'high';
    indicators.indicators.push('x-akamai-transformed header present');
  }
  
  // Generic reverse proxy detection
  if (headers['via']) {
    indicators.detected = true;
    if (!indicators.type) {
      indicators.type = 'Generic Reverse Proxy';
      indicators.confidence = 'medium';
    }
    indicators.indicators.push(`via header: ${headers['via']}`);
  }
  
  if (headers['x-cache']) {
    indicators.detected = true;
    if (!indicators.type) {
      indicators.type = 'Generic CDN/Cache';
      indicators.confidence = 'medium';
    }
    indicators.indicators.push(`x-cache header: ${headers['x-cache']}`);
  }
  
  if (headers['x-proxy']) {
    indicators.detected = true;
    if (!indicators.type) {
      indicators.type = 'Generic Proxy';
      indicators.confidence = 'medium';
    }
    indicators.indicators.push(`x-proxy header: ${headers['x-proxy']}`);
  }
  
  // Check DNS for CDN patterns
  const aRecords = fingerprint.dns.records.A || [];
  const cnameRecords = fingerprint.dns.records.CNAME || [];
  
  // Cloudflare IP ranges (simplified check)
  for (const ip of aRecords) {
    if (ip.startsWith('104.') || ip.startsWith('172.') || ip.startsWith('173.')) {
      if (!indicators.detected) {
        indicators.detected = true;
        indicators.type = 'Cloudflare (IP-based)';
        indicators.confidence = 'medium';
      }
      indicators.indicators.push(`Cloudflare IP range detected: ${ip}`);
    }
  }
  
  // Check CNAME for CDN patterns
  for (const cname of cnameRecords) {
    if (cname.includes('cloudflare')) {
      indicators.detected = true;
      indicators.type = 'Cloudflare';
      indicators.confidence = 'high';
      indicators.indicators.push(`CNAME points to Cloudflare: ${cname}`);
    } else if (cname.includes('cloudfront')) {
      indicators.detected = true;
      indicators.type = 'AWS CloudFront';
      indicators.confidence = 'high';
      indicators.indicators.push(`CNAME points to CloudFront: ${cname}`);
    } else if (cname.includes('akamai')) {
      indicators.detected = true;
      indicators.type = 'Akamai';
      indicators.confidence = 'high';
      indicators.indicators.push(`CNAME points to Akamai: ${cname}`);
    } else if (cname.includes('fastly')) {
      indicators.detected = true;
      indicators.type = 'Fastly';
      indicators.confidence = 'high';
      indicators.indicators.push(`CNAME points to Fastly: ${cname}`);
    }
  }
  
  return indicators;
}
