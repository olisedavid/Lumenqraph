# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Lumenqraph, please report it responsibly to the maintainers instead of disclosing it publicly. This allows us to investigate and release a fix before the vulnerability is exposed to potential attackers.

### Reporting Methods

We accept security reports through:

1. **GitHub Security Advisory (Recommended)**: Use the [private vulnerability reporting feature](https://github.com/Lumen-Scribe/Lumenqraph/security/advisories) to report directly to our repository.

2. **Email**: Send details to the project maintainers at security@lumenqraph.dev with the following information:
   - A clear description of the vulnerability
   - Steps to reproduce the issue (if applicable)
   - The affected version(s)
   - Potential impact and severity assessment
   - Any suggested fixes or mitigations

### What to Include

When reporting a vulnerability, please provide:

- **Type of vulnerability** (e.g., SQL injection, XSS, authentication bypass, cryptographic weakness, DoS)
- **Location** (file path, function, or component)
- **Affected versions** (commit SHA or release version)
- **Description** of the vulnerability and its potential impact
- **Proof of concept** (code snippet or test case that demonstrates the issue)
- **Your contact information** for follow-up questions
- **Optional**: A suggested fix or patch

## Response Timeline

We commit to the following response timeline:

| Severity | Initial Response | Fix Release |
|----------|------------------|-------------|
| Critical | < 24 hours | < 7 days |
| High | < 48 hours | < 14 days |
| Medium | < 72 hours | < 30 days |
| Low | < 1 week | < 60 days |

**Severity Definitions:**

- **Critical**: Remote code execution, authentication bypass, or data exfiltration affecting production deployments
- **High**: Privilege escalation, significant data corruption, or denial of service
- **Medium**: Significant functional limitation, information disclosure, or cryptographic weakness with limited impact
- **Low**: Minor issues with workarounds or limited practical impact

## Supported Versions

Security updates are provided for:

- **Current release**: Full support for all issues
- **Previous major version**: Critical and high severity issues only
- **Earlier versions**: No guaranteed support (updates may be provided at maintainers' discretion)

Check the [releases page](https://github.com/Lumen-Scribe/Lumenqraph/releases) for version information.

## Security Best Practices

### For Operators

When deploying Lumenqraph in production:

1. **Keep dependencies updated**: Regularly run `cargo update` and monitor security advisories
2. **Rotate API keys regularly**: Use unique keys per client and monitor usage patterns
3. **Use HTTPS**: Always deploy behind TLS/HTTPS in production
4. **Secure webhook endpoints**: Validate webhook signatures (`timingSafeEqual` or equivalent constant-time comparison)
5. **Rate limiting**: Configure appropriate rate limits for your use case
6. **Database security**: Use strong authentication, network isolation, and regular backups
7. **Monitor logs**: Track authentication failures, unusual query patterns, and rate limit hits
8. **RPC route protection**: Configure separate, tighter rate limits for expensive RPC-backed endpoints (`/contracts/:id/call`, `/contracts/:id/simulate`):

   ```bash
   # Stricter limit for expensive RPC operations (default: 10 req/min)
   RPC_ROUTE_RATE_LIMIT_PER_MIN=5
   
   # Optionally require authentication even when other routes don't
   RPC_REQUIRE_API_KEY=true
   ```

   These endpoints proxy requests to upstream Soroban RPC and share quota with the indexer — limiting them separately prevents a single caller from exhausting the entire RPC allocation.

9. **Webhook secret encryption**: Store webhook signing secrets encrypted at rest:

   ```bash
   # Set a strong encryption key (required for production)
   WEBHOOK_ENCRYPTION_KEY=$(openssl rand -hex 32)
   ```

   The encryption key is used with PostgreSQL's `pgp_sym_encrypt()` to protect webhook secrets. After deploying with this variable set, run migration `0020_webhook_secret_encryption_backfill.sql` to encrypt existing secrets.

   **Key rotation procedure:**
   
   If you need to rotate the encryption key:
   
   1. Keep the old key available temporarily
   2. Deploy the new key to all instances
   3. Run this migration with both keys available:
   
   ```sql
   -- Decrypt with old key, re-encrypt with new key
   UPDATE webhook_subscriptions
   SET encrypted_secret = pgp_sym_encrypt(
       pgp_sym_decrypt(encrypted_secret, 'OLD_KEY'),
       'NEW_KEY'
   )
   WHERE encrypted_secret IS NOT NULL;
   ```
   
   4. Remove the old key after verifying all webhooks work
   
   Note: The plaintext `secret` column is retained for backward compatibility during rolling deployments. A future migration will drop it once all instances are updated.

### Webhook Signing Secret Rotation

To rotate a subscription's signing secret without losing delivery history or resetting the watermark, use the dedicated rotation endpoint:

```bash
curl -X POST https://<host>/webhooks/<subscription-id>/rotate-secret \
  -H "x-api-key: <your-api-key>"
```

The response contains the new secret (shown **once only**) and the timestamp until which the previous secret remains valid:

```json
{
  "id": "...",
  "secret": "<new-hex-secret>",
  "previous_secret_valid_until": "2025-01-24T12:05:00Z",
  "message": "Store this secret immediately — it will not be shown again."
}
```

**Rotation procedure:**

1. Call `POST /webhooks/:id/rotate-secret` and capture the new secret immediately.
2. Update your consumer to accept both the old and new secrets during the grace period (`WEBHOOK_SECRET_GRACE_SECS`, default 300 seconds). The server validates deliveries signed with either secret during this window.
3. After the grace period expires, retire the old secret from your consumer — only the new one will be valid.

The grace period avoids a verification gap: in-flight deliveries signed with the old secret are still accepted while you roll out the updated secret to your infrastructure.

**Environment configuration:**

```bash
# Grace period during which the old secret stays valid alongside the new one (seconds).
# Default: 300 (5 minutes). Increase for slower rollouts.
WEBHOOK_SECRET_GRACE_SECS=300
```

### For Developers

When contributing to Lumenqraph:

1. **Never hardcode secrets**: Use environment variables for API keys, database URLs, and credentials
2. **Constant-time comparisons**: Use `subtle::ConstantTimeEq` or similar for all sensitive equality checks
3. **Input validation**: Validate all user inputs and external data
4. **Error handling**: Avoid leaking sensitive information in error messages
5. **Dependencies**: Audit transitive dependencies and maintain MSRV (minimum supported Rust version)
6. **Testing**: Include security-focused tests for authentication and authorization

## Cryptography

### Signature Verification

All webhook signatures use HMAC-SHA256. Verification must use constant-time comparison to prevent timing attacks.

**Rust implementation:**

Use the `lumenqraph_core::crypto::verify_hmac_signature()` function for safe webhook signature verification:

```rust
use lumenqraph_core::crypto::verify_hmac_signature;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

let secret = b"webhook-secret";
let body = b"webhook payload";

let mut mac = HmacSha256::new_from_slice(secret).unwrap();
mac.update(body);
let expected = hex::encode(mac.finalize().into_bytes());

let provided = "sha256=abc123..."; // From X-Lumenqraph-Signature header

if verify_hmac_signature(&expected, provided) {
    // Signature is valid
} else {
    // Signature is invalid — reject the webhook
}
```

The `verify_hmac_signature()` function uses the `subtle` crate's `ConstantTimeEq` trait to compare signatures in constant time, preventing timing attacks that could leak information about the secret.

**JavaScript/Node.js implementation:**

For consuming webhook signatures in Node.js, use the built-in `crypto.timingSafeEqual()`:

```javascript
const crypto = require("crypto");

function verify(rawBody, signatureHeader, secret) {
  const expected =
    "sha256=" + crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  return crypto.timingSafeEqual(
    Buffer.from(signatureHeader),
    Buffer.from(expected)
  );
}
```

### API Key Hashing

API keys are hashed using SHA-256 before database storage. Raw keys are never stored, reducing exposure if the database is compromised.

## Dependency Scanning

Lumenqraph uses automated tools to detect and prevent vulnerable or non-compliant dependencies from being merged:

### Cargo Audit

[Cargo Audit](https://github.com/rustsec/cargo-audit) checks all dependencies against the [RustSec Advisory Database](https://rustsec.org/) for known security vulnerabilities. This runs on every PR and weekly on schedule to catch newly-published advisories.

**Configuration:** CI fails when open advisories are detected. Exception mechanism:
```bash
# Only in Cargo.toml.lock or through GitHub Security Advisory ignore list
cargo audit --ignore RUSTSEC-XXXX
```

### Cargo Deny

[Cargo Deny](https://embarkstudios.github.io/cargo-deny/) provides comprehensive supply-chain scanning:

- **Advisories:** Duplicate of cargo-audit, catching known vulnerabilities
- **Licenses:** Enforces license compliance (see `deny.toml`)
- **Bans:** Detects and alerts on duplicate/unmaintained crates
- **Sources:** Restricts dependencies to approved registries and git repositories

**Configuration:** See [`deny.toml`](deny.toml) at the repository root.

### Running Locally

```bash
# Check for known vulnerabilities
cargo audit

# Run comprehensive supply-chain checks
cargo deny check
```

## Incident Response

If a vulnerability is confirmed:

1. A patch will be prepared and tested
2. A [GitHub Security Advisory](https://github.com/Lumen-Scribe/Lumenqraph/security/advisories) will be published with the fix
3. Users will be notified through release notes and advisories
4. The reporter will be credited (unless they request anonymity)
5. A post-mortem analysis may be conducted for critical issues

## Acknowledgments

We appreciate the security research community and thank all reporters who have responsibly disclosed vulnerabilities. Contributors to security improvements will be acknowledged in our [Security Credits](SECURITY_CREDITS.md) file (if applicable).

## Questions or Concerns?

If you have general security questions or concerns about Lumenqraph's security architecture, please open a [GitHub Discussion](https://github.com/Lumen-Scribe/Lumenqraph/discussions) or reach out to the maintainers.

---

**Last updated**: 2025-01-24

For more information on Stellar's security practices, see the [Stellar Security Resources](https://developers.stellar.org/docs/reference/security).
