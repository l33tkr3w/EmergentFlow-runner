# EmergentFlow Runner

Desktop app that runs your AI workflows in the background, even when your browser is closed.

## Features

- **Background Execution**: Flows keep running when browser is closed
- **Scheduled Flows**: Run on a schedule with cron-like precision
- **Direct Database Access**: Connect to PostgreSQL, MySQL, SQLite, MongoDB, Redis
- **Auto-Save Outputs**: Results saved to timestamped files
- **System Tray**: Runs silently in the background

## For Users

1. Download the installer for your OS from [emergentflow.io/downloads](https://emergentflow.io/downloads)
2. Install and run
3. Click "Login with EmergentFlow" 
4. Your flows sync automatically
5. Enable the flows you want to run in the background
6. Minimize to system tray - your flows keep running!

## Database Support

The Runner enables direct database connections that browsers cannot make:

| Database | Status | Notes |
|----------|--------|-------|
| PostgreSQL | ✅ | Full SQL, parameterized queries, SSL |
| MySQL | ✅ | Full SQL, prepared statements |
| SQLite | ✅ | Local .db files, WAL mode |
| MongoDB | ✅ | All CRUD operations, aggregation |
| Redis | ✅ | GET/SET, hashes, lists, Lua scripts |

### How It Works

1. Add a database node (PostgreSQL, MySQL, etc.) to your flow in the web app
2. Configure connection details in the node
3. When the flow runs in the Runner, it uses direct database connections
4. In browser, these nodes show "Runner required" message

## For Developers

### Prerequisites

- Node.js 18+
- npm

### Development

```bash
# Install dependencies
npm install

# Rebuild native modules for Electron
npm run postinstall

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
│   ├── preload.js   # IPC bridge (runner + electronAPI)
│   ├── database.js  # Database connection module
│   ├── index.html   # UI
│   └── icons/       # App icons
├── package.json
└── .github/
    └── workflows/
        └── build.yml  # GitHub Actions for releases
```

### Database Module

The `database.js` module provides:

- **Connection Pooling**: Connections are cached and reused
- **Lazy Loading**: Database drivers only load when needed
- **Error Handling**: All errors returned consistently
- **Cleanup**: Connections closed on app quit

```javascript
// IPC handlers registered automatically:
// db:postgres, db:mysql, db:sqlite, db:mongodb, db:redis
// db:test (connection test), db:closeAll (cleanup)
```

### Building Releases

Push a version tag to trigger automatic builds:

```bash
git tag v1.1.0
git push origin v1.1.0
```

GitHub Actions will build for Windows, macOS, and Linux, then create a release.

### Native Module Notes

The `better-sqlite3` package requires compilation. The `postinstall` script handles this:

```bash
npm run postinstall
# or manually:
npx electron-rebuild -f -w better-sqlite3
```

### How It Works

1. **Authentication**: Opens browser to EmergentFlow, receives token via local HTTP callback
2. **Sync**: Fetches user's flows from API
3. **Execution**: Runs flows using same logic as web app (LLM calls, HTTP, code nodes)
4. **Database**: Direct connections via node.js drivers (pg, mysql2, etc.)
5. **Scheduling**: Enabled flows run on their configured schedule
6. **Local Server**: Port 3742 accepts flow deployments from the web app

### Server-Side Requirements

Your EmergentFlow backend needs these API endpoints:

- `GET /api/runner/flows` - Returns user's flows (requires auth token)
- `GET /auth/runner-login` - OAuth page that posts token to `localhost:3742/auth-callback`

## License

MIT
