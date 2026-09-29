# Security

## Reporting

Please report vulnerabilities privately through GitHub's
**Security → Report a vulnerability** on this repository, not in a public issue.

## Model

- The app talks only to the scope on its own WiFi and to itself on `127.0.0.1`.
- State-changing HTTP requests require the `X-EarScope: 1` header.
- Camera frames are treated as untrusted data: they are only reassembled and
  passed to the browser's JPEG decoder.
- The scope's WiFi is open (no password) and its protocol is unauthenticated.
  Anyone in range can view or disturb the stream. That is a property of the
  hardware, not of this program.

## Supported versions

Only the latest release.
