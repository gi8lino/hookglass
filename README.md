# Hookglass

**A small webhook echo server with optional HMAC, header, and Bearer verification.**

Hookglass accepts HTTP requests, logs accepted webhook bodies using Go's default `slog` logger, and responds with `204 No Content`. It is designed for local development and integration testing, not as a production webhook ingestion service.

## Endpoints

| Method | Path       | Behavior                                                                                |
| ------ | ---------- | --------------------------------------------------------------------------------------- |
| `POST` | `/echo`    | Logs requests without authentication; always enabled.                                   |
| `POST` | `/hmac`    | Verifies a configurable HMAC signature and optional timestamp before logging; optional. |
| `POST` | `/header`  | Requires a specific header with an exact configured value; optional.                    |
| `POST` | `/bearer`  | Requires `Authorization: Bearer <token>`; optional.                                     |
| `GET`  | `/healthz` | Returns `204` without logging.                                                          |

Protected endpoints return `401` on failed verification. Oversized bodies return `413`. By default, request bodies are limited to **64 KiB**. Authentication credentials, signature values, and arbitrary request headers are **not logged**. A verified request body is logged verbatim, so it may still contain sensitive data.

**Security:** `/echo` is _always unauthenticated_, even when other verification routes are enabled. Bind Hookglass to loopback or a trusted development network; **do not expose it to the public Internet**.

## Quick start

```sh
make run HOOKGLASS_ASSIGNED_PORT=8080
# In another terminal:
curl -i -X POST http://127.0.0.1:8080/echo \
  -H 'Content-Type: application/json' \
  -d '{"hello":"world"}'
```

Use the included example files for specific verification schemes:

```sh
# Verify a Keycloak Snitch (or Warden) webhook signature.
export WEBHOOK_SECRET='replace-me'
make run HOOKGLASS_ASSIGNED_PORT=8080 CONFIG=examples/snitch.yaml
# POST http://127.0.0.1:8080/hmac

# Require a shared API key in X-API-Key.
export WEBHOOK_API_KEY='replace-me'
make run HOOKGLASS_ASSIGNED_PORT=8080 CONFIG=examples/header.yaml
curl -i http://127.0.0.1:8080/header -X POST \
  -H "X-API-Key: $WEBHOOK_API_KEY" -d 'test'

# Require a Bearer token.
export WEBHOOK_TOKEN='replace-me'
make run HOOKGLASS_ASSIGNED_PORT=8080 CONFIG=examples/bearer.yaml
curl -i http://127.0.0.1:8080/bearer -X POST \
  -H "Authorization: Bearer $WEBHOOK_TOKEN" -d 'test'
```

`make run` assigns a reusable local port and prints the endpoint URLs. The examples above pin port 8080 to keep the commands copyable; without that override, use the printed port. Run the `curl` commands in another terminal and use Ctrl+C to stop the server.

## Configuration

Use `--config=path/to/config.yaml` for verification settings and `--listen-address=:8080` to override the listening address. The listen address is a CLI/environment setting, not a YAML field. Without a configuration file, only `/echo` and `/healthz` are registered; running the binary directly defaults to `127.0.0.1:8080`.

Hookglass uses [tinyflags](https://github.com/containeroo/tinyflags). Flags can also be set through `HOOKGLASS__CONFIG` and `HOOKGLASS__LISTEN_ADDRESS` environment variables (command-line flags take precedence). The former `LISTEN_ADDR` environment override has been replaced by `HOOKGLASS__LISTEN_ADDRESS`.

All three verification routes can be enabled at once:

```yaml
max-body-bytes: 65536

hmac:
  enabled: true
  secret-env: WEBHOOK_SECRET
  algorithm: sha256
  signature-header: X-Snitch-Signature
  signature-prefix: "v1="
  signature-encoding: hex
  message-format: "{timestamp}.{body}"
  timestamp-header: X-Snitch-Timestamp
  timestamp-format: unix
  max-age: 5m

header:
  enabled: true
  name: X-API-Key
  value-env: WEBHOOK_API_KEY

bearer:
  enabled: true
  token-env: WEBHOOK_TOKEN
```

Each verification route is optional and **only registered when `enabled: true`**. Secrets and expected values are read from the named environment variables at startup, not from the YAML file. Missing or invalid enabled-route configuration prevents startup.

### Verification settings

| Section  | Key                  | Meaning                                                                                        |
| -------- | -------------------- | ---------------------------------------------------------------------------------------------- |
| `header` | `name`               | Any valid HTTP header field name, e.g. `X-API-Key`.                                            |
| `header` | `value-env`          | Environment variable containing the exact expected header value.                               |
| `bearer` | `token-env`          | Environment variable containing the expected Bearer credential (without the `Bearer ` prefix). |
| `hmac`   | `secret-env`         | Environment variable containing the signing secret.                                            |
| `hmac`   | `algorithm`          | `sha256` or `sha512`.                                                                          |
| `hmac`   | `signature-header`   | Header containing the provided signature.                                                      |
| `hmac`   | `signature-prefix`   | Optional literal prefix, e.g. `v1=` or `sha256=`.                                              |
| `hmac`   | `signature-encoding` | `hex` or standard padded `base64`.                                                             |
| `hmac`   | `message-format`     | Literals plus `{body}` exactly once and optional `{timestamp}`.                                |
| `hmac`   | `timestamp-header`   | Header holding the signed timestamp.                                                           |
| `hmac`   | `timestamp-format`   | `unix`, `unix-ms`, or `rfc3339`.                                                               |
| `hmac`   | `max-age`            | Duration such as `5m` required with `{timestamp}`.                                             |

`/header` and `/bearer` accept exactly one matching credential header and reject duplicates. Bearer scheme matching is case-insensitive. Header and token comparisons use constant-time digest comparison. The request body is logged **only after** authentication succeeds.

For `/hmac`, the original raw body bytes are used in signature calculation before any parsing or formatting. Timestamp validation enforces a freshness window but **does not prevent replays within the window**. Signature formats with compound headers (such as Stripe) still require provider-specific parsing.

Examples are available under [`examples/`](examples/): `snitch.yaml`, `warden.yaml`, `github.yaml`, `slack.yaml`, `header.yaml`, and `bearer.yaml`.

## Project layout

```text
cmd/hookglass/          CLI entry point (delegates to app.Run)
internal/app/           Startup, configuration, logging, graceful shutdown
internal/flags/         tinyflags CLI and environment overrides
internal/config/        Strict YAML configuration
internal/verification/  Enabled-route verification setup, header and Bearer checks
internal/hmacverify/    Configurable raw-body HMAC implementation
internal/server/        HTTP routing and request logging
examples/               Example verifier configurations
```

## Docker

```sh
docker build -t hookglass .
docker run --rm -p 127.0.0.1:8080:8080 hookglass
```

To enable HMAC verification:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  -e WEBHOOK_SECRET='replace-me' \
  -v "$(pwd)/examples/snitch.yaml:/etc/hookglass.yaml:ro" \
  hookglass --config=/etc/hookglass.yaml --listen-address=:8080
```

The image runs as a non-root user on a distroless base. Use `make check`, `make test`, or `make build` for local development.

## License

Apache-2.0. See [LICENSE](LICENSE).
