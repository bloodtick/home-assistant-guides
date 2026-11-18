# Home Assistant Access with Cloudflare Tokens and Temporary Cookies

This guide covers adding a token-and-cookie access gate in front of Home Assistant using a Cloudflare Worker.

This setup uses an existing Cloudflare Tunnel. Home Assistant continues to enforce its own authentication.

## How it works

| Request | Result |
|---|---|
| Correct query token | Worker forwards the original request to HA |
| GET with the correct token | Worker also issues a signed browser cookie |
| Valid cookie without a token | Worker forwards the request to HA |
| Missing or invalid credentials | Request is blocked |

The browser cookie works for every path on the hostname where it was issued. Its default lifetime is 10 minutes.

The Worker preserves the original URL, query string, HTTP method, and body. It adds the cookie to HA's response instead of redirecting token-bearing requests.

## Connection sequence

| Step | Component | Action |
|---|---|---|
| 1 | Cloudflare WAF | Checks whether a token parameter or gateway cookie is present |
| 2 | Worker | Validates the token value or the signed cookie |
| 3 | Cloudflare Tunnel | Carries the authorized request to HA |
| 4 | Home Assistant | Processes the request and its own authentication |
| 5 | Worker | Adds a cookie to token-authorized GET responses |

The WAF performs an initial presence check. The Worker validates the actual credential.

## Requirements

- A domain using Cloudflare DNS.
- A working Cloudflare Tunnel to Home Assistant.
- One or more proxied hostnames routed to HA.
- Access to Cloudflare Workers and WAF custom rules.

The examples use:

```text
ha-integration-1.yourdomain.com
ha-integration-2.yourdomain.com
```

Replace those names with your own.

## 1. Create two secrets

Generate two different random secrets:

| Secret | Purpose |
|---|---|
| `WAF_TOKEN` | Shared credential included in browser and curl URLs |
| `COOKIE_SIGNING_KEY` | Signs and verifies temporary browser cookies |

For example, run this command twice in Terminal to generate two separate values:

```bash
openssl rand -hex 32
```

The token is a bearer credential. Anyone who obtains it can pass this gateway and request a new cookie.

Keep the signing key exclusively in the Worker.

## 2. Create the Worker

In Cloudflare, open:

**Compute > Workers & Pages > Create application**

Select **Start with Hello World!**, name the Worker:

```text
ha-access-gateway
```

Click **Deploy**.

Once the Worker exists, open **Edit code**, replace the entire starter script with the code below, and deploy it.

```javascript
const COOKIE_NAME = "__Host-ha_login";
const DEFAULT_COOKIE_TTL_SECONDS = 600;
const MAX_COOKIE_TTL_SECONDS = 604800;

const encoder = new TextEncoder();

function forbidden() {
  return new Response("Forbidden", {
    status: 403,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function importSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"],
  );
}

function cookieDuration(url) {
  const raw = url.searchParams.get("duration");
  const seconds = Number(raw);

  if (
    raw === null ||
    !/^\d+$/.test(raw) ||
    !Number.isSafeInteger(seconds) ||
    seconds < 1
  ) {
    return DEFAULT_COOKIE_TTL_SECONDS;
  }

  return Math.min(seconds, MAX_COOKIE_TTL_SECONDS);
}

async function issueCookie(hostname, secret, duration) {
  const expires = Math.floor(Date.now() / 1000) + duration;
  const key = await importSigningKey(secret);

  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(`${hostname}:${expires}`),
    ),
  );

  const hex = Array.from(
    signature,
    byte => byte.toString(16).padStart(2, "0"),
  ).join("");

  return [
    `${COOKIE_NAME}=${expires}.${hex}`,
    "Path=/",
    `Max-Age=${duration}`,
    "Secure",
    "HttpOnly",
    "SameSite=Lax",
  ].join("; ");
}

async function hasValidCookie(request, hostname, secret) {
  const prefix = `${COOKIE_NAME}=`;

  const value = (request.headers.get("Cookie") || "")
    .split(/;\s*/)
    .find(cookie => cookie.startsWith(prefix))
    ?.slice(prefix.length);

  const match = value?.match(/^(\d{10})\.([a-f0-9]{64})$/);

  if (!match) {
    return false;
  }

  const [, expires, hex] = match;

  if (Number(expires) <= Math.floor(Date.now() / 1000)) {
    return false;
  }

  const signature = Uint8Array.from(
    hex.match(/../g),
    byte => parseInt(byte, 16),
  );

  const key = await importSigningKey(secret);

  return crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    encoder.encode(`${hostname}:${expires}`),
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.protocol !== "https:") {
      return forbidden();
    }

    if (!env.WAF_TOKEN || !env.COOKIE_SIGNING_KEY) {
      return new Response("Gateway configuration incomplete", {
        status: 503,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    const validToken = url.searchParams
      .getAll("token")
      .includes(env.WAF_TOKEN);

    if (validToken) {
      // Preserve the original URL, method, query string, and body.
      const response = await fetch(request, {
        redirect: "manual",
      });

      // POST and other methods pass through without issuing a cookie.
      // Preserve WebSocket upgrade responses directly.
      if (request.method !== "GET" || response.status === 101) {
        return response;
      }

      const headers = new Headers(response.headers);

      headers.append(
        "Set-Cookie",
        await issueCookie(
          url.hostname,
          env.COOKIE_SIGNING_KEY,
          cookieDuration(url),
        ),
      );

      headers.set("Cache-Control", "no-store");
      headers.set("Referrer-Policy", "no-referrer");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    }

    if (
      await hasValidCookie(
        request,
        url.hostname,
        env.COOKIE_SIGNING_KEY,
      )
    ) {
      return fetch(request, {
        redirect: "manual",
      });
    }

    return forbidden();
  },
};
```

## 3. Add the Worker secrets

Open the Worker's **Settings > Variables and Secrets**.

Add these values using the **Secret** type:

| Name | Value |
|---|---|
| `WAF_TOKEN` | Your shared token |
| `COOKIE_SIGNING_KEY` | Your separate signing secret |

Enter raw values without surrounding quotes or `token=`.

Save and deploy the secrets.

A request without credentials returning **Forbidden** in the editor preview is expected.

[Cloudflare Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

## 4. Attach the Worker to every protected hostname

Open the Worker's **Domains** tab or **Settings > Domains & Routes**, depending on your dashboard version.

Add a **Route** for each hostname:

```text
ha-integration-1.yourdomain.com/*
ha-integration-2.yourdomain.com/*
```

Choose the appropriate Cloudflare zone.

The `/*` pattern covers every path, including login endpoints, frontend assets, API calls, and webhooks.

Select **Fail closed** where the route configuration offers a failure-mode setting. Requests must be rejected if the Worker cannot execute.

Confirm that every hostname included in the WAF rule below has an active Worker route. A cookie-presence exception depends on the Worker validating the cookie.

[Cloudflare Worker routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)

## 5. Disable the public workers.dev URL

On the Worker's **Domains** page:

1. Disable the Production `workers.dev` URL.
2. Keep Preview URLs disabled.

The HA hostname routes continue to invoke the Worker.

[Cloudflare workers.dev settings](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)

## 6. Create the WAF Block rule

After the Worker routes are active, create a custom WAF rule.

Open **Security > Security rules > Custom rules > Create rule**.

Select **Edit expression** and paste:

```text
(
  http.host in {
    "ha-integration-1.yourdomain.com"
    "ha-integration-2.yourdomain.com"
  }
  and not (
    any(http.request.uri.args.names[*] eq "token")
    or http.cookie contains "__Host-ha_login="
  )
)
```

Set the action to **Block**.

This rule contains no token value. It checks only whether a parameter named `token` or the gateway cookie is present.

An arbitrary token or fake cookie can pass this initial filter. The Worker must validate it before forwarding the request.

Other Cloudflare security rules can still block a request before the Worker executes.

[Cloudflare security feature ordering](https://developers.cloudflare.com/waf/feature-interoperability/)

## 7. Test the browser flow

Open a private browser window and visit:

```text
https://ha-integration-1.yourdomain.com/?token=YOUR_TOKEN
```

Home Assistant should load. The Worker adds the signed cookie to the response.

Now visit the same hostname without the token:

```text
https://ha-integration-1.yourdomain.com/
```

The cookie should allow the request through the gateway.

Home Assistant's own login still applies.

The token remains in the original URL because the Worker forwards the request unchanged. After receiving the cookie, you can use the clean URL.

## 8. Choose a cookie duration

The default duration is 600 seconds, or 10 minutes.

To request a 24-hour cookie:

```text
https://ha-integration-1.yourdomain.com/?token=YOUR_TOKEN&duration=86400
```

| Duration | Seconds |
|---|---|
| 10 minutes | `600` |
| 1 hour | `3600` |
| 24 hours | `86400` |
| 7 days | `604800` |

Only a GET with the correct token issues a cookie and applies the requested duration.

Missing or invalid durations use the default. This example caps the duration at seven days through:

```javascript
const MAX_COOKIE_TTL_SECONDS = 604800;
```

Change that constant if you want a different maximum.

Cookie-only requests do not renew the expiry. A new token-authorized GET issues a fresh cookie.

## 9. Keep certificate-only hostnames separate

If your other subdomains use the mTLS guide, exempt the token-enabled hostnames from that certificate rule.

For example, use this separate **Block** rule:

```text
(
  ends_with(http.host, ".yourdomain.com")
  and not http.host in {
    "ha-integration-1.yourdomain.com"
    "ha-integration-2.yourdomain.com"
  }
  and (
    not cf.tls_client_auth.cert_verified
    or cf.tls_client_auth.cert_revoked
    or cf.tls_client_auth.cert_fingerprint_sha256 ne "YOUR_64_CHARACTER_SHA256_FINGERPRINT"
  )
)
```

Also ensure the token-enabled hostnames are configured to accept clients without a client certificate. Review their mTLS Associated Hostnames settings.

Passing the token WAF rule does not skip another Block rule. The hostname exclusions keep certificate-only access and token-enabled access scoped correctly.

## 10. Verify rejection and cookie validation

Replace the example hostname and token in the following commands.

### No credentials

```bash
curl -i 'https://ha-integration-1.yourdomain.com/'
```

Expected result: **403**.

### Incorrect token

```bash
curl -i 'https://ha-integration-1.yourdomain.com/?token=wrong'
```

Expected result: **403**.

### Fake cookie

```bash
curl -i \
  -H 'Cookie: __Host-ha_login=fake' \
  'https://ha-integration-1.yourdomain.com/'
```

Expected result: **403**.

### Future expiry with a forged signature

```bash
curl -i \
  -H 'Cookie: __Host-ha_login=4102444800.0000000000000000000000000000000000000000000000000000000000000000' \
  'https://ha-integration-1.yourdomain.com/'
```

Expected result: **403**.

This checks that a plausible expiration time alone cannot satisfy the Worker.

### Correct token and cookie issuance

```bash
curl -i \
  -c /tmp/ha-cookie-test.txt \
  'https://ha-integration-1.yourdomain.com/?token=YOUR_TOKEN'
```

Expected result: HA's response and a `Set-Cookie` header for `__Host-ha_login`.

### Cookie without a token

```bash
curl -i \
  -b /tmp/ha-cookie-test.txt \
  'https://ha-integration-1.yourdomain.com/'
```

Expected result: HA's response.

These commands save the test cookie temporarily. Remove it afterward:

```bash
rm -f /tmp/ha-cookie-test.txt
```

A token entered directly into a shell command may remain in shell history.

Repeat the tests for each protected hostname.

## Cookie behavior and limits

- Each cookie is bound to its issuing hostname.
- `Path=/` makes it available on every path on that hostname.
- `Secure` restricts browser transmission to HTTPS.
- `HttpOnly` prevents webpage JavaScript from reading it.
- `SameSite=Lax` supports ordinary top-level browser navigation.
- The Worker checks the signature and signed expiry on each new cookie-authorized request.
- Changing the cookie's expiry or signature causes validation to fail.
- A copied cookie can be replayed on the same hostname until it expires.
- Browser restrictions can prevent cookies from working inside cross-site iframes.
- Expiry blocks new requests. It does not forcibly close an already established WebSocket or other long-lived connection.

## Rotate credentials

### Change the shared token

Update the Worker's `WAF_TOKEN` secret, then update saved browser URLs and curl commands that use it.

The WAF expression needs no token-value change.

Existing signed cookies remain valid until their expiry.

### Invalidate existing cookies

Replace `COOKIE_SIGNING_KEY` with a new random secret and deploy it.

Cookies signed with the previous key will fail validation once the new deployment is active.

A correct token can then obtain a new cookie.

## Troubleshooting

| Symptom | Check |
|---|---|
| Correct token receives Cloudflare block page | Security Events and other matching WAF rules |
| Worker returns `Forbidden` | Token value, cookie validity, and HTTPS |
| Worker returns configuration error | Both production secrets are configured |
| First page loads but later requests get 403 | Cookie storage, cookie name, hostname, and Worker route |
| Fake cookie reaches HA | Worker route coverage and failure mode |
| Works locally but fails remotely | Tunnel, public hostname, WAF, and Worker |
| Embedded dashboard fails | Browser third-party cookie restrictions |

Test through the actual HA hostname. The editor's workers.dev preview does not test your tunnel route to Home Assistant.

## Operating this setup

Keep the token private. URLs containing it can appear in browser history, bookmarks, logs, and copied links.

The Worker intentionally preserves the original query string, so the token also reaches the origin.

Use a short cookie lifetime appropriate for your use case. Longer-lived cookies also give a copied cookie a longer replay window.

Keep every protected hostname covered by an active Worker route configured to fail closed. The WAF checks for credential presence; the Worker enforces validity.
