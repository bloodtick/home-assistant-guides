# Home Assistant with Cloudflare Tunnel and Client Certificates

This guide documents my setup for accessing Home Assistant through Cloudflare Tunnel with mutual TLS (mTLS).

Cloudflare requires a valid, non-revoked client certificate with the exact SHA-256 fingerprint configured in a WAF rule. Cloudflared connects outbound from the home network, so no inbound router port forwarding is required.

This guide covers setting up Cloudflare Tunnel and mutual TLS (mTLS) for Home Assistant, including creating and installing a client certificate on **macOS** and configuring it in the **Home Assistant Companion app for iOS**.

The external address uses standard HTTPS:

```text
https://homeassistant-1.yourdomain.com
```

## How the connection works

| Step | Component | What happens |
|---|---|---|
| 1 | Browser or Companion app | Connects over HTTPS and presents its client certificate |
| 2 | Cloudflare | Verifies the certificate, checks revocation, and matches the SHA-256 fingerprint |
| 3 | Cloudflare Tunnel | Forwards the authorized request through the outbound tunnel |
| 4 | Home Assistant | Receives the request at `http://homeassistant:8123` and applies its own authentication |

Home Assistant still requires its own authentication after the request passes Cloudflare.

## Before you start

You need:

- A domain using Cloudflare DNS.
- Home Assistant with support for apps/add-ons.
- Access to the Cloudflare dashboard.
- A Mac with OpenSSL for the certificate commands below.
- Local access to Home Assistant while configuring remote access.

Replace `yourdomain.com` and `homeassistant-1.yourdomain.com` with your own domain and hostname.

## 1. Put your domain on Cloudflare

Add your domain to Cloudflare and update its authoritative nameservers at your domain registrar.

Wait for Cloudflare to show the zone as active before continuing.

## 2. Install Cloudflared

In Home Assistant, open:

**Settings → Add-ons → Add-on Store → ⋮ → Repositories**

Depending on your Home Assistant version, add-ons may be labeled **Apps**.

Add this repository:

```text
https://github.com/homeassistant-apps/repository
```

Install **Cloudflared**.

This guide uses a **remotely managed tunnel**, with routing configured in Cloudflare. Enter the tunnel token before starting the app.

[Cloudflared documentation](https://github.com/homeassistant-apps/app-cloudflared/blob/main/cloudflared/DOCS.md)

## 3. Configure Home Assistant's trusted proxy

Open:

**Settings → System → Network → HTTP server**

Enable **Trust X-Forwarded-For**.

Under **Trusted proxies**, add:

```text
172.30.33.0/24
```

This is the proxy subnet used by the Cloudflared Home Assistant app setup. If your connector runs elsewhere, use its actual address or subnet.

Save the settings and complete any restart and confirmation prompts shown by Home Assistant.

[Home Assistant HTTP configuration](https://www.home-assistant.io/integrations/http/)

## 4. Create a Cloudflare Tunnel

In Cloudflare Zero Trust, open **Networks** and find **Tunnels** or **Connectors**, depending on the dashboard version.

1. Create a tunnel.
2. Choose **Cloudflared**.
3. Give the tunnel a name, such as `homeassistant-1`.
4. Copy the tunnel token from the connector installation instructions.

Cloudflare may display a complete installation command. You need the token from that command.

In Home Assistant, open:

**Cloudflared → Configuration**

Enter the token:

```yaml
tunnel_token: YOUR_CLOUDFLARE_TUNNEL_TOKEN
```

Save and start Cloudflared.

Check the app logs, then confirm that Cloudflare shows the tunnel as healthy or connected.

Keep the tunnel token private.

[Remotely managed tunnel setup](https://github.com/homeassistant-apps/app-cloudflared/blob/main/cloudflared/DOCS.md#remote-tunnel-app-setup-advanced)

## 5. Add the published application route

Select your tunnel and add a **Published application route**.

| Setting | Value |
|---|---|
| Hostname | `homeassistant-1.yourdomain.com` |
| Service type | HTTP |
| Service URL | `homeassistant:8123` |

The complete internal service address is:

```text
http://homeassistant:8123
```

The Cloudflared Home Assistant app can resolve the internal hostname `homeassistant`. If your connector runs on another machine, use an internal address it can reach.

If Home Assistant listens on a different internal port, substitute that port.

Save the route and confirm that its DNS entry is created. Enable WebSockets for the Cloudflare zone, as required by the Cloudflared app documentation.

## 6. Test the tunnel

Open:

```text
https://homeassistant-1.yourdomain.com
```

Confirm that Home Assistant loads.

At this stage, Home Assistant's login protects the application. The client-certificate gate is added next.

## 7. Create a Cloudflare client certificate

In your Cloudflare zone, open:

**SSL/TLS → Client Certificates**

Create a **Cloudflare-managed client certificate**.

Save both:

- The client certificate.
- Its private key.

The commands below use these filenames:

```text
ha-client-cert.pem
ha-client-key.pem
```

Store the private key securely. A client needs that key to authenticate with the certificate.

## 8. Create a password-protected P12 file

Place the certificate and private key in a private working folder on your Mac.

Open Terminal in that folder and run:

```bash
openssl pkcs12 -export \
  -out ha-client.p12 \
  -inkey ha-client-key.pem \
  -in ha-client-cert.pem \
  -name "Home Assistant Cloudflare"
```

Enter an export password when prompted.

Verify the file:

```bash
openssl pkcs12 -info -in ha-client.p12 -noout
```

Look for both a certificate bag and a shrouded keybag.

### Install on macOS

1. Double-click `ha-client.p12`.
2. Import it into the **login** keychain.
3. Open **Keychain Access → login → My Certificates**.
4. Expand the certificate and confirm that its private key appears underneath it.

When the browser requests permission to use the private key, approve access for the browser you intend to use. In my setup, I selected **Always Allow** for that browser.

### Install in the iOS Companion app

Transfer the password-protected P12 to your iPhone, for example using AirDrop.

In my Home Assistant Companion app setup, I had to open the server settings and explicitly import/select the identity under **Client Certificate (Labs)**. Installing the identity into iOS alone did not configure the app to use it.

Menu labels can vary by app version.

If the standard P12 fails to import or work, try a legacy-format container using OpenSSL 3:

```bash
openssl pkcs12 -export -legacy \
  -out ha-client-legacy.p12 \
  -inkey ha-client-key.pem \
  -in ha-client-cert.pem \
  -name "Home Assistant Cloudflare"
```

Use an OpenSSL installation that supports `-legacy`.

The legacy P12 was the format that worked for my iOS setup.

[Companion app setup and client certificates](https://companion.home-assistant.io/docs/getting_started/)

## 9. Enable mTLS for the hostname

In Cloudflare, open:

**SSL/TLS → Client Certificates → Associated Hostnames**

Add:

```text
homeassistant-1.yourdomain.com
```

Repeat this for every hostname you want protected.

This enables client-certificate authentication for the hostname. The WAF rule in the next steps enforces the certificate requirements.

[Enable mTLS at Cloudflare](https://developers.cloudflare.com/ssl/client-certificates/enable-mtls/)

## 10. Get the SHA-256 fingerprint

In the folder containing your certificate, run:

```bash
openssl x509 \
  -in ha-client-cert.pem \
  -noout \
  -fingerprint \
  -sha256
```

The output resembles:

```text
sha256 Fingerprint=AA:BB:CC:DD:...
```

For the WAF rule, remove the colons and convert the letters to lowercase. The resulting fingerprint should contain **64 hexadecimal characters**.

This command produces the normalized value directly:

```bash
openssl x509 -in ha-client-cert.pem -noout -fingerprint -sha256 \
  | cut -d= -f2 \
  | tr -d ':' \
  | tr '[:upper:]' '[:lower:]'
```

## 11. Create the WAF Block rule

In your Cloudflare zone, open:

**Security → Security rules → Custom rules → Create rule**

Choose **Edit expression**.

Paste the following, replacing the domain and fingerprint:

```text
(
  ends_with(http.host, ".yourdomain.com")
  and (
    not cf.tls_client_auth.cert_verified
    or cf.tls_client_auth.cert_revoked
    or cf.tls_client_auth.cert_fingerprint_sha256 ne "YOUR_64_CHARACTER_SHA256_FINGERPRINT"
  )
)
```

Set the action to **Block**, then save and enable the rule.

The rule blocks a request if any of these conditions is true:

| Condition | Result |
|---|---|
| Client certificate is unverified | Block |
| Client certificate is flagged as revoked | Block |
| SHA-256 fingerprint differs from your configured value | Block |

A request passes this rule only when Cloudflare verifies the certificate, does not flag it as revoked, and finds the exact fingerprint match.

The explicit revocation check matters because Cloudflare can report `cert_verified` as true for a revoked certificate. Cloudflare's documented revocation check applies to certificates issued by its managed CA.

[Cloudflare certificate revocation checks](https://developers.cloudflare.com/api-shield/security/mtls/configure/#check-for-revoked-certificates)

### Which hostnames does this protect?

The rule covers all subdomains of `yourdomain.com`, including:

```text
homeassistant-1.yourdomain.com
homeassistant-2.yourdomain.com
another-service.yourdomain.com
```

The bare domain `yourdomain.com` falls outside that expression.

If you also want the bare domain covered, use this complete rule instead:

```text
(
  (
    http.host eq "yourdomain.com"
    or ends_with(http.host, ".yourdomain.com")
  )
  and (
    not cf.tls_client_auth.cert_verified
    or cf.tls_client_auth.cert_revoked
    or cf.tls_client_auth.cert_fingerprint_sha256 ne "YOUR_64_CHARACTER_SHA256_FINGERPRINT"
  )
)
```

Every service covered by the rule requires the pinned client certificate. This includes webhook endpoints on those hostnames.

## 12. Test the rule

From a device with your client identity installed, open:

```text
https://homeassistant-1.yourdomain.com
```

It should reach Home Assistant.

Then verify the following:

| Test | Expected result |
|---|---|
| Verified, non-revoked certificate with the pinned fingerprint | Reaches Home Assistant |
| No client certificate | Blocked |
| A valid certificate with a different fingerprint | Blocked |
| Revoked Cloudflare-issued certificate | Blocked |

To verify the fingerprint check with your existing identity:

1. Temporarily change one character of the fingerprint in the WAF rule.
2. Retry the connection and confirm that it is blocked.
3. Restore the correct fingerprint.
4. Confirm that access works again.

Use **Cloudflare Security Events** to inspect blocked requests and identify the matched rule.

Some certificate failures can stop the TLS handshake before an HTTP request reaches the WAF. Those may appear as a browser TLS error.

## 13. Chrome and HTTP/3 troubleshooting

In my setup, Chrome failed to present the expected client certificate while Cloudflare's **HTTP/3 (with QUIC)** setting was enabled. Safari and curl worked with the same certificate.

I resolved that behavior by:

1. Disabling **HTTP/3 (with QUIC)** in Cloudflare.
2. Completely quitting Chrome.
3. Reopening Chrome and testing again.

I left HTTP/3 disabled and used HTTP/2.

This was a compatibility workaround observed in my setup. If Chrome has certificate problems while other clients work, test this setting.

Cloudflare's visitor-facing HTTP/3 setting and Cloudflared's outbound tunnel transport are configured separately.

[Cloudflare HTTP/3 documentation](https://developers.cloudflare.com/speed/optimization/protocol/http3/)

## Final behavior

Clients access the standard HTTPS hostname. Cloudflare verifies the client certificate, checks revocation, and matches its SHA-256 fingerprint before the request can continue through the tunnel.

Keep inbound router port forwarding disabled and close any other public route to the origin.

The certificate fingerprint is public identification data. Access requires possession of the corresponding private key, followed by Home Assistant's own authentication.
