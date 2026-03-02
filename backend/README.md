# Black Codex Backend

Backend API server for the Black Codex IoT Security Platform. This server provides RESTful APIs and WebSocket connections for real-time IoT device monitoring, vulnerability scanning, and security analysis.

## Features

- 🔐 **Authentication & Authorization** - JWT-based auth with role-based access control
- 📱 **Device Management** - CRUD operations for IoT devices with status tracking
- 🔍 **Vulnerability Scanning** - Network scanning and vulnerability detection
- 📊 **Security Dashboard** - Real-time security metrics and trends
- ⚠️ **Alert System** - Configurable alerts with severity levels
- 🔒 **Quarantine Management** - Isolate compromised devices
- 🤖 **AI Analysis** - AI-powered security recommendations
- 📡 **WebSocket Support** - Real-time updates for live monitoring
- 📋 **CVE Database** - Local CVE cache for vulnerability correlation
- 🕵️ **Threat Intelligence** - External threat feed integration
- 📦 **Packet Capture** - Network traffic monitoring
- 🔑 **Default Credentials** - Detection of factory credentials
- 📝 **Audit Logging** - Comprehensive activity logging
- 📈 **Reporting** - Security reports in JSON, CSV, and HTML

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: SQLite (better-sqlite3)
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcryptjs
- **Real-time**: WebSocket (ws)
- **Scheduling**: node-cron
- **Logging**: Winston
- **Security**: helmet, cors, express-rate-limit
- **Validation**: express-validator

## Installation

```bash
# Navigate to backend directory
cd codex\ backend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your settings
# At minimum, change JWT_SECRET

# Start development server
npm run dev

# Or start production server
npm start
```

## Environment Variables

```env
PORT=3001
NODE_ENV=development
DATABASE_PATH=./data/codex.db
JWT_SECRET=your-super-secret-jwt-key-change-this
JWT_EXPIRES_IN=24h
CORS_ORIGIN=http://localhost:5173
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
ADMIN_EMAIL=admin@blackcodex.local
ADMIN_PASSWORD=ChangeMe123!
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login user |
| POST | `/api/auth/logout` | Logout user |
| POST | `/api/auth/refresh-token` | Refresh JWT token |
| GET | `/api/auth/me` | Get current user profile |

### Devices
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices |
| GET | `/api/devices/:id` | Get device by ID |
| POST | `/api/devices` | Create new device |
| PUT | `/api/devices/:id` | Update device |
| DELETE | `/api/devices/:id` | Delete device |
| POST | `/api/devices/:id/quarantine` | Quarantine device |
| POST | `/api/devices/:id/unquarantine` | Release device |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List all alerts |
| GET | `/api/alerts/stats` | Get alert statistics |
| GET | `/api/alerts/:id` | Get alert by ID |
| POST | `/api/alerts/:id/acknowledge` | Acknowledge alert |
| POST | `/api/alerts/acknowledge-all` | Acknowledge all alerts |
| DELETE | `/api/alerts/:id` | Delete alert |

### Vulnerabilities
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vulnerabilities` | List vulnerabilities |
| GET | `/api/vulnerabilities/stats/summary` | Get vulnerability stats |
| GET | `/api/vulnerabilities/:id` | Get vulnerability by ID |
| PUT | `/api/vulnerabilities/:id` | Update vulnerability |

### Network Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/start` | Start network scan |
| GET | `/api/scan/status/:id` | Get scan status |
| GET | `/api/scan/history` | Get scan history |
| POST | `/api/scan/:id/cancel` | Cancel running scan |

### CVE Database
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cve` | Search CVE database |
| GET | `/api/cve/stats/summary` | Get CVE statistics |
| GET | `/api/cve/:id` | Get CVE by ID |
| POST | `/api/cve/search` | Advanced CVE search |
| POST | `/api/cve/check-device` | Check device against CVEs |

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats` | List threat intelligence |
| GET | `/api/threats/stats/summary` | Get threat statistics |
| GET | `/api/threats/:id` | Get threat by ID |
| POST | `/api/threats/search-ioc` | Search by IOC |
| POST | `/api/threats/check-device` | Check device for threats |
| POST | `/api/threats` | Add new threat |

### AI Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ai/analyze` | Analyze device with AI |
| GET | `/api/ai/report/:deviceId` | Get AI report |
| POST | `/api/ai/chat` | AI chat endpoint |
| GET | `/api/ai/recommendations` | Get recommendations |
| POST | `/api/ai/analyze-network` | Network-wide analysis |

### Network Topology
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network/topology` | Get network topology |
| GET | `/api/network/traffic` | Get traffic data |
| GET | `/api/network/ports` | Get port statistics |
| GET | `/api/network/connections` | Get device connections |
| GET | `/api/network/segments` | Get network segments |
| GET | `/api/network/bandwidth` | Get bandwidth data |

### Packet Capture
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/packets` | List packet captures |
| GET | `/api/packets/stats/summary` | Get packet statistics |
| POST | `/api/packets/capture/start` | Start capture |
| POST | `/api/packets/capture/stop/:id` | Stop capture |
| POST | `/api/packets/search` | Search packets |

### Credentials Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/credentials` | List default credentials |
| POST | `/api/credentials/check-device` | Check device credentials |
| POST | `/api/credentials/scan-network` | Scan network for defaults |
| GET | `/api/credentials/vulnerable-devices` | Get vulnerable devices |
| GET | `/api/credentials/stats` | Get credential stats |

### Quarantine
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/quarantine` | List quarantined devices |
| GET | `/api/quarantine/:deviceId` | Get quarantine details |
| POST | `/api/quarantine/:deviceId` | Quarantine device |
| DELETE | `/api/quarantine/:deviceId` | Release device |
| POST | `/api/quarantine/bulk` | Bulk quarantine |
| DELETE | `/api/quarantine/bulk` | Bulk release |
| GET | `/api/quarantine/stats/summary` | Get quarantine stats |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/reports/generate` | Generate security report |
| GET | `/api/reports/templates` | Get report templates |
| GET | `/api/reports/dashboard` | Get dashboard data |
| GET | `/api/reports/trends` | Get security trends |

### Settings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/settings` | Get all settings |
| GET | `/api/settings/:key` | Get setting by key |
| PUT | `/api/settings/:key` | Update setting |
| PUT | `/api/settings` | Bulk update settings |
| GET | `/api/settings/user/preferences` | Get user preferences |
| PUT | `/api/settings/user/preferences` | Update preferences |
| GET | `/api/settings/scan/config` | Get scan configuration |
| PUT | `/api/settings/scan/config` | Update scan config |
| GET | `/api/settings/notifications` | Get notification settings |
| PUT | `/api/settings/notifications` | Update notifications |

### Audit Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit` | List audit logs |
| GET | `/api/audit/stats/summary` | Get audit statistics |
| GET | `/api/audit/:id` | Get audit log by ID |
| GET | `/api/audit/export/csv` | Export logs as CSV |
| GET | `/api/audit/user/:userId` | Get user activity |
| POST | `/api/audit/search` | Search audit logs |
| GET | `/api/audit/actions/list` | Get available actions |

## WebSocket

Connect to WebSocket at `ws://localhost:3001/ws`

### Message Types

**Client -> Server:**
```json
{ "type": "authenticate", "token": "jwt-token" }
{ "type": "subscribe", "channel": "alerts" }
{ "type": "unsubscribe", "channel": "alerts" }
{ "type": "ping" }
```

**Server -> Client:**
```json
{ "type": "connected", "clientId": "uuid" }
{ "type": "authenticated", "userId": "uuid" }
{ "type": "subscribed", "channel": "alerts" }
{ "type": "broadcast", "channel": "alerts", "data": {...} }
{ "type": "pong", "timestamp": 1234567890 }
```

### Available Channels
- `alerts` - Real-time alert notifications
- `devices` - Device status updates
- `scans` - Scan progress and results
- `packets` - Live packet capture
- `system` - System status updates

## Default Login

```
Email: admin@blackcodex.local
Password: ChangeMe123!
```

⚠️ **Important**: Change the default password immediately after first login!

## Development

```bash
# Run in development mode with auto-reload
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

## Project Structure

```
codex backend/
├── src/
│   ├── database/
│   │   ├── init.js          # Database initialization
│   │   └── seed.js          # Demo data seeding
│   ├── middleware/
│   │   ├── auth.js          # JWT authentication
│   │   └── audit.js         # Audit logging
│   ├── routes/
│   │   ├── ai.js            # AI analysis endpoints
│   │   ├── alerts.js        # Alert management
│   │   ├── audit.js         # Audit logs
│   │   ├── auth.js          # Authentication
│   │   ├── credentials.js   # Default credentials
│   │   ├── cve.js           # CVE database
│   │   ├── devices.js       # Device management
│   │   ├── network.js       # Network topology
│   │   ├── packets.js       # Packet capture
│   │   ├── quarantine.js    # Quarantine management
│   │   ├── reports.js       # Security reports
│   │   ├── scan.js          # Network scanning
│   │   ├── settings.js      # Settings management
│   │   ├── threats.js       # Threat intelligence
│   │   └── vulnerabilities.js
│   ├── services/
│   │   └── scheduler.js     # Scheduled tasks
│   ├── utils/
│   │   └── logger.js        # Winston logger
│   ├── websocket/
│   │   └── server.js        # WebSocket server
│   └── server.js            # Main entry point
├── data/                    # SQLite database
├── logs/                    # Application logs
├── .env.example
├── package.json
└── README.md
```

## License

MIT License - Black Codex IoT Security Platform
