# EmergentFlow Runner

Desktop app that runs your AI workflows in the background, even when your browser is closed.

## For Users

1. Download the installer for your OS from [emergentflow.io/downloads](https://emergentflow.io/downloads)
2. Install and run
3. Click "Login with EmergentFlow" 
4. Your flows sync automatically
5. Enable the flows you want to run in the background
6. Minimize to system tray - your flows keep running!

## For Developers

### Prerequisites

- Node.js 18+
- npm

### Development

```bash
# Install dependencies
npm install

# Run in development mode
npm start

# Build for current platform
npm run build

# Build for specific platforms
npm run build:win
npm run build:mac
npm run build:linux
```

### Project Structure

```
runner/
├── src/
│   ├── main.js      # Electron main process
│   ├── preload.js   # IPC bridge
│   ├── index.html   # UI
│   └── icons/       # App icons
├── package.json
└── .github/
    └── workflows/
        └── build.yml  # GitHub Actions for releases
```

### Building Releases

Push a version tag to trigger automatic builds:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions will build for Windows, macOS, and Linux, then create a release.

### How It Works

1. **Authentication**: Opens browser to EmergentFlow, receives token via local HTTP callback
2. **Sync**: Fetches user's flows from API
3. **Execution**: Runs flows using same logic as web app (LLM calls, HTTP, code nodes)
4. **Scheduling**: Enabled flows run on their configured schedule
5. **Local Server**: Port 3742 accepts flow deployments from the web app

### Server-Side Requirements

Your EmergentFlow backend needs these API endpoints:

- `GET /api/runner/flows` - Returns user's flows (requires auth token)
- `GET /auth/runner-login` - OAuth page that posts token to `localhost:3742/auth-callback`

## License

MIT
