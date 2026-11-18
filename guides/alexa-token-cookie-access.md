# Alexa Smart Home Access Through the Cloudflare Token-and-Cookie Gateway

This guide extends the official [Home Assistant Amazon Alexa Smart Home Skill setup](https://www.home-assistant.io/integrations/alexa.smart_home/).

Follow that guide to create the Alexa skill, AWS Lambda function, permissions, service endpoint, and Home Assistant integration. Apply the changes below to route account linking and Alexa commands through the Cloudflare token-and-cookie gateway.

First complete the [Cloudflare token-and-cookie gateway guide](guides/cloudflare-token-cookie-gateway.md). That guide provides the Worker, secrets, hostname routes, WAF rule, and validation checks used here.

## What this adds

Alexa communicates with Home Assistant through three paths:

| Path | Caller | Gateway credential |
|---|---|---|
| `/auth/authorize` and follow-up login requests | Browser opened by the Alexa app | Initial query token, then temporary cookie |
| `/auth/token` | Alexa's servers | Query token on the configured URL |
| `/api/alexa/smart_home` | Your AWS Lambda function | Query token added by the Python code |

The temporary cookie supports the browser login flow. Alexa's server-side requests and Lambda calls supply the token directly.

Home Assistant's own OAuth authentication continues to apply.

## Before you start

Confirm that:

- The official Home Assistant Alexa setup is configured.
- Your public HTTPS hostname reaches Home Assistant through Cloudflare Tunnel.
- The gateway Worker runs on the hostname's `/*` route.
- The Worker has its `WAF_TOKEN` and `COOKIE_SIGNING_KEY` secrets configured.
- The gateway's WAF rule is active.
- The hostname accepts clients without an mTLS client certificate.

Use the same shared token in the Worker, the Alexa account-linking URLs, and the Lambda environment variable.

This guide uses:

```text
https://ha-integration-1.yourdomain.com
```

Replace that hostname and `YOUR_TOKEN` throughout.

## 1. Update the Alexa skill's account-linking URLs

Open the [Alexa Developer Console](https://developer.amazon.com/alexa/console/ask), select your skill's development version, and open:

**Build > Account Linking**

Under **Security Provider Information**, update the following two fields.

### Your Web Authorization URI

```text
https://ha-integration-1.yourdomain.com/auth/authorize?token=YOUR_TOKEN
```

This is the URL the Alexa app opens when the user links their Home Assistant account.

The initial GET passes the gateway using the token. The Worker adds its signed cookie to the response, allowing the browser to load HA's subsequent login requests on the same hostname.

### Access Token URI

```text
https://ha-integration-1.yourdomain.com/auth/token?token=YOUR_TOKEN
```

Alexa's servers call this endpoint to exchange an authorization code and to refresh the Home Assistant access token.

Those server-side requests use the query token directly. They do not use the browser's gateway cookie.

Save the account-linking settings.

The shared gateway token belongs in these URLs. Continue using the other account-linking settings from the official HA setup.

[Alexa account-linking configuration](https://developer.amazon.com/docs/alexaplus/account-linking/configure-authorization-code-grant)

## 2. Add the Lambda environment variable

In the AWS console, open:

**Lambda > Functions > your Alexa function > Configuration > Environment variables > Edit**

Add:

| Key | Value |
|---|---|
| `CLOUDFLARE_WAF_TOKEN` | The raw shared token from the Worker's `WAF_TOKEN` secret |

For example:

```text
Key:   CLOUDFLARE_WAF_TOKEN
Value: your-token-value
```

Enter the raw value without quotes, `?token=`, or `token=`.

Keep `BASE_URL` set to the public HTTPS origin:

```text
https://ha-integration-1.yourdomain.com
```

The code appends the API path and optional query token. `BASE_URL` should contain the hostname without an API path or query string.

| Setting | Example |
|---|---|
| Worker secret `WAF_TOKEN` | `your-token-value` |
| Lambda variable `CLOUDFLARE_WAF_TOKEN` | `your-token-value` |
| Lambda variable `BASE_URL` | `https://ha-integration-1.yourdomain.com` |

Save the environment variables.

[Working with Lambda environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

## 3. Update the Lambda code

The Cloudflare changes are:

1. Import `urlencode`.
2. Read the optional `CLOUDFLARE_WAF_TOKEN` environment variable.
3. Append it as the `token` query parameter when it is nonempty.
4. Disable automatic redirects when the gateway token is included.

The existing Home Assistant bearer token stays in the `Authorization` header.

The resulting request is:

```text
POST https://ha-integration-1.yourdomain.com/api/alexa/smart_home?token=YOUR_TOKEN
```

If `CLOUDFLARE_WAF_TOKEN` is absent or empty, the code sends:

```text
POST https://ha-integration-1.yourdomain.com/api/alexa/smart_home
```

Your gateway will reject that request unless another accepted credential is supplied.

Open the Lambda function's **Code** tab, replace `lambda_function.py` with the complete code below, and click **Deploy**.

```python
"""
Copyright 2019 Jason Hu <awaregit at gmail.com>
Modified 2020 Matthew Hilton <matthilton2005@gmail.com>
Refactor and Modernised 2025 Matthew Hilton <matthilton2005@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

2026-11-16 Added CLOUDFLARE_WAF_TOKEN
"""

import json
import logging
import logging.handlers
import os
from typing import Any
from urllib.parse import urlencode

import urllib3

# Configure debug mode
_debug = bool(os.environ.get('DEBUG'))

# Configure logging with enhanced formatting
_log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
_formatter = logging.Formatter(_log_format)

# Console handler
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_formatter)

# Logger setup
_logger = logging.getLogger('HomeAssistant-SmartHome')
_logger.setLevel(logging.DEBUG if _debug else logging.INFO)
_logger.addHandler(_console_handler)

# Suppress debug logs from urllib3
logging.getLogger('urllib3').setLevel(logging.INFO)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle incoming Alexa directive.

    Args:
        event: The Alexa directive event payload
        context: AWS Lambda context object

    Returns:
        Response payload for Alexa

    Raises:
        AssertionError: If request validation fails
    """

    _logger.info('Processing Alexa request')
    _logger.debug('Event payload: %s', json.dumps(event, indent=2))

    try:
        base_url = os.environ.get('BASE_URL')
        if base_url is None:
            _logger.error('BASE_URL environment variable not set')
            raise ValueError('BASE_URL environment variable must be set')
        base_url = base_url.rstrip('/')
        _logger.debug('Base URL: %s', base_url)

        directive = event.get('directive')
        if directive is None:
            _logger.error('Malformed request: missing directive')
            raise ValueError('Request missing required directive field')

        payload_version = directive.get('header', {}).get('payloadVersion')
        if payload_version != '3':
            _logger.error('Unsupported payloadVersion: %s', payload_version)
            raise ValueError(f'Only payloadVersion 3 is supported, got {payload_version}')

        scope = directive.get('endpoint', {}).get('scope')
        if scope is None:
            # token is in grantee for Linking directive
            scope = directive.get('payload', {}).get('grantee')
        if scope is None:
            # token is in payload for Discovery directive
            scope = directive.get('payload', {}).get('scope')

        if scope is None:
            _logger.error('Malformed request: missing scope/token')
            raise ValueError('Request missing scope in endpoint or payload')

        scope_type = scope.get('type')
        if scope_type != 'BearerToken':
            _logger.error('Unsupported scope type: %s', scope_type)
            raise ValueError(f'Only BearerToken scope is supported, got {scope_type}')

        token = scope.get('token')
        if token is None and _debug:
            _logger.debug('Token not found in request, using LONG_LIVED_ACCESS_TOKEN from environment')
            token = os.environ.get('LONG_LIVED_ACCESS_TOKEN')

        if token is None:
            _logger.error('No authentication token available')
            raise ValueError('Authentication token is required')

        verify_ssl = not bool(os.environ.get('NOT_VERIFY_SSL'))
        _logger.debug('SSL verification enabled: %s', verify_ssl)

        http = urllib3.PoolManager(
            cert_reqs='CERT_REQUIRED' if verify_ssl else 'CERT_NONE',
            timeout=urllib3.Timeout(connect=2.0, read=10.0)
        )

        request_url = f'{base_url}/api/alexa/smart_home'
        waf_token = os.environ.get('CLOUDFLARE_WAF_TOKEN')
        if waf_token:
            request_url += '?' + urlencode({'token': waf_token})

        _logger.info('Sending request to Home Assistant')
        response = http.request(
            'POST',
            request_url,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
            body=json.dumps(event).encode('utf-8'),
            redirect=not bool(waf_token),
        )

        _logger.debug('Response status: %s', response.status)

        if response.status >= 400:
            response_text = response.data.decode('utf-8')
            _logger.error('Home Assistant returned error %s: %s', response.status, response_text)

            error_type = 'INVALID_AUTHORIZATION_CREDENTIAL' if response.status in (401, 403) else 'INTERNAL_ERROR'
            return {
                'event': {
                    'payload': {
                        'type': error_type,
                        'message': response_text,
                    }
                }
            }

        response_data = json.loads(response.data.decode('utf-8'))
        _logger.info('Successfully processed Alexa request')
        _logger.debug('Response: %s', json.dumps(response_data, indent=2))
        return response_data

    except (ValueError, KeyError, json.JSONDecodeError) as e:
        _logger.exception('Error processing request: %s', str(e))
        return {
            'event': {
                'payload': {
                    'type': 'INVALID_REQUEST',
                    'message': str(e),
                }
            }
        }
    except Exception as e:
        _logger.exception('Unexpected error: %s', str(e))
        return {
            'event': {
                'payload': {
                    'type': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred',
                }
            }
        }
```

Use the runtime and dependency setup from the official HA guide. The handler for a file named `lambda_function.py` is:

```text
lambda_function.lambda_handler
```

Leave `DEBUG` unset during normal operation. This code logs the complete Alexa event when debugging is enabled, and that event can contain the Home Assistant access token.

## 4. Relink the Alexa skill

After saving the account-linking URLs, Lambda environment variable, and deployed code:

1. Open the Alexa app.
2. Find your Home Assistant skill under **Skills & Games > Your Skills**.
3. Use its account-linking option to sign in again. If needed, disable and re-enable the skill to restart linking.
4. Complete the Home Assistant sign-in.
5. Confirm that Alexa reports successful linking.

Relinking is important when changing the Access Token URI. Existing linked accounts can continue using the previously saved endpoint.

## 5. Verify the complete flow

### Browser account linking

Start linking from the Alexa app.

Expected behavior:

- The browser reaches `/auth/authorize` with the query token.
- The Worker issues `__Host-ha_login`.
- Follow-up HA login requests use the cookie.
- Home Assistant authenticates the user.
- Alexa completes the account link.

Test from a connection outside your local network to exercise the public Cloudflare path.

### Discovery and commands

Run device discovery and issue a command to a device exposed through the official HA Alexa integration.

Expected behavior:

- Alexa invokes the configured Lambda function.
- Lambda adds `CLOUDFLARE_WAF_TOKEN` to its POST URL.
- The Worker validates the query token.
- HA processes the Alexa directive using its bearer authorization.
- The response returns through Lambda to Alexa.

A POST does not need the browser's cookie.

### Token refresh

After the HA access token expires, issue another Alexa command.

Confirm that Alexa can refresh through the tokenized `/auth/token` endpoint and continue operating.

Successful initial linking alone does not verify the later refresh path.

## Troubleshooting

| Symptom | Check |
|---|---|
| HA login page is blocked | Web Authorization URI, token value, Worker route, and WAF events |
| Login page loads but subsequent requests fail | Gateway cookie issuance, browser cookie storage, and hostname consistency |
| Sign-in succeeds but account linking fails | Access Token URI and its query token |
| Linking works but commands fail | Lambda deployment, `BASE_URL`, `CLOUDFLARE_WAF_TOKEN`, and the official skill endpoint configuration |
| Commands stop working later | Refresh requests to `/auth/token` and whether the skill was relinked after changing its URI |
| Lambda receives a Cloudflare 403 | Gateway token, other matching rules, and any certificate requirement on the hostname |
| Lambda receives an HA authorization error | HA bearer token and account-linking configuration |
| Lambda receives a redirect instead of HA JSON | `BASE_URL` and routing to the final HTTPS endpoint |

Use **Cloudflare Security Events** to identify WAF blocks and the Worker's **Observability** logs to determine whether requests reached it.

Use Lambda's **Monitor** tab and its CloudWatch logs to inspect function failures.

Avoid publishing logs or screenshots containing query tokens, cookies, or HA access tokens.

## Change the shared token later

Update these locations together:

| Location | Setting |
|---|---|
| Cloudflare Worker | `WAF_TOKEN` secret |
| Alexa account linking | Web Authorization URI |
| Alexa account linking | Access Token URI |
| AWS Lambda | `CLOUDFLARE_WAF_TOKEN` environment variable |

Relink the skill after changing the account-linking endpoints.

Existing gateway cookies remain valid until expiry unless you also rotate the Worker's `COOKIE_SIGNING_KEY`.

## References

- [Home Assistant Amazon Alexa Smart Home Skill setup](https://www.home-assistant.io/integrations/alexa.smart_home/)
- [Cloudflare token-and-cookie gateway guide](cloudflare-token-cookie-gateway.md)
- [Alexa account-linking configuration](https://developer.amazon.com/docs/alexaplus/account-linking/configure-authorization-code-grant)
- [AWS Lambda environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)
