# Caddy ipv64 Configuration Guide

Quick reference for choosing the right configuration.

## 🎯 TL;DR - Which Config Do I Need?

### ✅ Simple (Try This First)

```caddyfile
*.sickcloud.ipv64.de {
  tls {
    dns ipv64 {
      api_token your_token_here
    }
  }
}
```

**Works on:**
- ✅ Cloud VMs (AWS, DigitalOcean, Hetzner, etc.)
- ✅ Bare metal servers with direct internet
- ✅ Most Linux servers with default DNS

**Doesn't work on:**
- ❌ Docker containers
- ❌ Systems with local DNS (192.168.x.x)
- ❌ Corporate networks with DNS filtering

---

### 🔧 Production (Use When Simple Fails)

```caddyfile
*.sickcloud.ipv64.de {
  tls {
    dns ipv64 {
      api_token your_token_here
    }
    resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1 8.8.8.8
    propagation_timeout 90s
    propagation_delay 3s
  }
}
```

**Use this if you get errors like:**
- `dial udp: lookup ... on 192.168.x.x:53: no such host`
- `No TXT record found`
- `During secondary validation: No TXT record found`

---

### 🚀 Maximum Reliability (For Stubborn Cases)

```caddyfile
*.sickcloud.ipv64.de {
  tls {
    dns ipv64 {
      api_token your_token_here
    }
    resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1 8.8.8.8
    propagation_timeout 120s  # 2 minutes for multi-datacenter
    propagation_delay 8s      # Very slow checks
  }
}
```

**Only needed for:**
- Wildcard certificates in complex environments
- Repeated secondary validation failures
- Very slow DNS propagation

---

## 📊 Decision Tree

```
Certificate fails?
│
├─ Error: "no such host on 192.168.x.x"
│  └─> Add: resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1
│
├─ Error: "No TXT record found"
│  └─> Add: propagation_timeout 90s + propagation_delay 3s
│
├─ Error: "During secondary validation"
│  └─> Increase to: propagation_timeout 120s + propagation_delay 8s
│
└─ Still failing?
   └─> Check: API token valid? Domain exists in ipv64.net panel?
```

---

## 🔍 What Each Setting Does

### `api_token`
**Required.** Your ipv64.net API key from the control panel.

### `resolvers` (optional)
**Bypasses local DNS.** Tells Caddy which DNS servers to use for checking if TXT records exist.

- **Default:** System DNS (whatever your server uses)
- **Recommended:** `ns1.ipv64.net ns2.ipv64.net 1.1.1.1`
- **Why it matters:** Local DNS (192.168.x.x) often can't resolve external domains

### `propagation_timeout` (optional)
**How long to wait for DNS.** Maximum time Caddy waits for TXT records to appear globally.

- **Default:** 60s (Caddy default)
- **Recommended:** `90s` (tested with Lego's ipv64 provider)
- **For stubborn cases:** `120s` (2 minutes)
- **Why it matters:** ipv64.net DNS takes 30-90 seconds to propagate worldwide

### `propagation_delay` (optional)
**How often to check DNS.** Interval between DNS propagation checks.

- **Default:** 2s (Caddy default, same as Lego)
- **Recommended:** `3s` for wildcards
- **For stubborn cases:** `8s`
- **Why it matters:** Slower checks = record stays alive longer = more time for Let's Encrypt validation

---

## 🎓 Understanding the Problem

### Why the minimal config sometimes fails:

1. **Your server uses local DNS** (192.168.1.1, 10.0.0.1, etc.)
2. **Local DNS can't resolve** `ns1.ipv64.net` or external domains
3. **Caddy can't verify** if TXT records exist
4. **Certificate issuance fails**

### The solution:

- **Option 1:** Use explicit `resolvers` (recommended)
- **Option 2:** Fix your server's DNS to use public DNS (8.8.8.8, 1.1.1.1)

---

## 📝 Complete Examples

### Home Lab (Bare Metal)

```caddyfile
{
  email admin@example.com
}

*.homelab.ipv64.de {
  tls {
    dns ipv64 {
      api_token abc123def456
    }
    # Most home internet has working DNS
  }
  
  respond "Hello from {host}!"
}
```

### Docker (Compose)

```caddyfile
{
  email admin@example.com
}

*.dockerapp.ipv64.de {
  tls {
    dns ipv64 {
      api_token abc123def456
    }
    # Docker DNS is often broken
    resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1
    propagation_timeout 90s
    propagation_delay 3s
  }
  
  reverse_proxy app:8080
}
```

### Production VPS (Cloud)

```caddyfile
{
  email admin@example.com
  # Use staging for testing
  # acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}

*.myapp.ipv64.de {
  tls {
    dns ipv64 {
      api_token abc123def456
    }
    # Cloud DNS usually works, but add resolvers for safety
    resolvers ns1.ipv64.net ns2.ipv64.net 1.1.1.1 8.8.8.8
    propagation_timeout 90s
    propagation_delay 3s
  }
  
  root * /var/www/html
  file_server
}
```

---

## 🐛 Debugging

### Enable Debug Logging

```caddyfile
{
  debug
}
```

Or via command line:
```bash
caddy run --config Caddyfile --debug
```

### Check DNS Resolution

Test if your server can resolve ipv64.net nameservers:

```bash
# Should return IP addresses
nslookup ns1.ipv64.net
nslookup ns2.ipv64.net

# If this fails, you MUST use explicit resolvers in Caddyfile
```

### Test with Let's Encrypt Staging

Add to global config to avoid rate limits during testing:

```caddyfile
{
  acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```

---

## ❓ FAQ

### Q: Do I always need to add resolvers?

**A:** No. Try the simple config first. Only add `resolvers` if you get DNS errors.

### Q: Can I use environment variables?

**A:** Yes! `api_token {env.IPV64_API_TOKEN}` or `api_token {$IPV64_API_TOKEN}`

### Q: Why is my wildcard certificate failing?

**A:** Wildcards need more time for multi-datacenter validation. Use `propagation_delay 3s` or higher (up to 8s for stubborn cases).

### Q: What if I get rate limited?

**A:** Use Let's Encrypt staging CA for testing: `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory`

### Q: How do I know if ipv64.net DNS is propagated?

**A:** Check with: `dig TXT _acme-challenge.yourdomain.ipv64.de @ns1.ipv64.net`

---

## 📚 See Also

- [README.md](README.md) - Full documentation
- [Troubleshooting Guide](README.md#troubleshooting) - Detailed error solutions
- [ipv64.net API Docs](https://ipv64.net/) - DNS provider documentation
