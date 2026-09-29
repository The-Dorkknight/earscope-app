# How it works

## Overview

The scope makes its own WiFi network and sends JPEG frames as UDP packets. The
program joins that network, reassembles the frames, and serves them to a web
page on your own device. Only the Python standard library is used.

```
scope ──UDP──▶ Camera thread ──▶ latest JPEG ──▶ HTTP server (127.0.0.1:8080) ──▶ browser / Android WebView
```

- `src/earscope/ne3web.py`: everything above, including the web UI as one embedded page.
- `src/earscope/app.py`: Android/desktop wrapper (BeeWare Toga) that starts the
  server and shows it in a WebView. Adds WiFi pinning, gallery saving and fullscreen.

## Protocols

The program tries NE3 first and NE7 next, and keeps the one that answers.
Both were reverse-engineered by the [haxko hackerspace](https://github.com/haxko/NE3-Scope).

### NE3

- Scope at `192.168.169.1`, UDP port 8800. Start with `ef 00 04 00`.
- Messages start `ef 02`. Each frame has a 56-byte little-endian header,
  followed by 1024-byte chunks.
- The JPEG header is stripped by the scope, so the program rebuilds it from
  fixed quantisation and Huffman tables.
- The tilt angle is text after the first chunk. Each frame is acknowledged;
  a keepalive goes to port 1234.

### NE7

- Scope at `192.168.1.1`, found by a broadcast `66 39 01 01` to ports 58090 and
  46526, which answers with JSON.
- Send `20 36` and video arrives on UDP 44506; send `86 06 01` and tilt data
  arrives on 52219.
- Video chunks have a 4-byte header (frame number, flags, chunk number from 1,
  unused). Flag bit 0 marks the last chunk. Frames are whole JPEGs, trimmed at
  the real `FF D9` end marker because the scope pads them.

## Web server

Plain `ThreadingHTTPServer`. Endpoints:

| Path | Purpose |
|---|---|
| `/` | viewer UI |
| `/frame` | long-poll for the next frame |
| `/snapshot.jpg`, `/stream.mjpg` | latest frame, MJPEG stream |
| `/status`, `/log` | JSON status, log text |
| `POST /save`, `/reconnect`, `/diagnose`, `/restart`, `/shutdown`, `/immersive` | actions |

`POST` requests must carry the header `X-EarScope: 1`, which stops other web
pages from triggering them. The server listens on `127.0.0.1` unless you pass
`--host`. Starting a second copy replaces the first (checked through `/status`).

## Android specifics

- WiFi sockets are pinned to the scope's network with `Network.bindSocket`, so
  the camera works even with mobile data on.
- Gallery saving uses MediaStore, so no storage permission is needed.
- Cleartext HTTP is allowed because the page is served from `127.0.0.1` inside the app.
- Built with Briefcase; see `pyproject.toml` and `.github/workflows/build-android.yml`.

## UI

One canvas at the frame's native resolution, scaled with CSS `object-fit`.
Overlays are HTML, not canvas. The brushed-aluminium panel uses an embedded
WebP grain texture. Fullscreen uses the native API where available and a CSS
fallback elsewhere.
