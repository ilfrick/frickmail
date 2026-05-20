# Frickmail Desktop (Tauri)

Native desktop wrapper for Frickmail using [Tauri 2](https://tauri.app).

## Features

- Native window wrapping the Frickmail web UI
- System tray icon — close button hides to tray, does not quit
- Left-click tray icon or "Open Frickmail" menu item to restore the window
- Native OS notifications via `tauri-plugin-notification`

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable)
- [Node.js](https://nodejs.org) + npm/yarn
- Platform build tools:
  - **Linux**: `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Microsoft C++ Build Tools + WebView2

## Setup

```bash
cd tauri
npm install          # installs @tauri-apps/cli
```

## Development

Point the app at your running Frickmail instance:

```bash
# Edit tauri.conf.json: set "devUrl" to your Frickmail URL
# e.g. "devUrl": "https://webmail.housefz.com"

npm run tauri dev
```

## Build

```bash
# Edit tauri.conf.json: set "url" in windows[] to your Frickmail URL
npm run tauri build
```

Outputs are in `src-tauri/target/release/bundle/`.

## Configuration

| Setting | File | Description |
|---|---|---|
| Frickmail URL | `tauri.conf.json` → `app.windows[0].url` | The URL the webview loads |
| Window size | `tauri.conf.json` → `app.windows[0]` | width/height/minWidth/minHeight |
| App icons | `src-tauri/icons/` | Replace with Frickmail branded icons |

## Generating icons from Frickmail icon

```bash
# Requires ImageMagick
npm run tauri icon ../docs/frickmail-icon.png
```

This auto-generates all required icon sizes in `src-tauri/icons/`.
