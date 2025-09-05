# Personal Synapse Chat Server

A complete Matrix/Synapse server deployment with Redis caching, custom Python modules, and a web-based chat client. This project demonstrates backend service integration, containerization, and real-time messaging systems.

## Features

- **Matrix Synapse Server**: Full-featured Matrix homeserver running in Docker
- **Redis Caching**: High-performance caching for events, rate limiting, and worker coordination
- **Custom Python Modules**: Auto-moderation and keyword alert systems
- **Web Chat Client**: Real-time HTML/JavaScript client for testing
- **Docker Compose**: Easy deployment and management
- **Authentication**: Local user authentication with admin controls

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Git (for cloning the repository)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Personal-Synapse-Chat-Server
   ```

2. **Run the setup script**
   
   **On Windows:**
   ```cmd
   setup.bat
   ```
   
   **On Linux/Mac:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Create an admin user**
   ```bash
   docker-compose exec synapse register_new_matrix_user -c /data/homeserver.yaml -a -u admin -p admin123 http://localhost:8008
   ```

4. **Access the services**
   - Matrix Server: http://localhost:8008
   - Chat Client: Open `frontend/index.html` in your browser

## Project Structure

```
Personal-Synapse-Chat-Server/
├── docker-compose.yml          # Docker services configuration
├── homeserver.yaml            # Synapse server configuration
├── data/                      # Server data and logs
│   └── localhost.log.config   # Logging configuration
├── modules/                   # Custom Python modules
│   ├── __init__.py
│   ├── auto_moderation.py     # Auto-moderation module
│   └── keyword_alerts.py      # Keyword alert module
├── frontend/                  # Web chat client
│   ├── index.html
│   ├── style.css
│   └── script.js
├── setup.sh                   # Linux/Mac setup script
├── setup.bat                  # Windows setup script
└── README.md
```

## Services

### Matrix Synapse Server
- **Port**: 8008 (HTTP), 8448 (Federation)
- **Database**: PostgreSQL
- **Configuration**: `homeserver.yaml`
- **Features**: Registration, federation, media storage

### Redis Cache
- **Port**: 6379
- **Password**: redis_password
- **Purpose**: Event caching, rate limiting, worker coordination

### PostgreSQL Database
- **Port**: 5432
- **Database**: synapse
- **User**: synapse
- **Password**: synapse_password

## Custom Modules

### Auto-Moderation Module
Automatically deletes messages containing banned words.

**Configuration in `homeserver.yaml`:**
```yaml
modules:
  - module: modules.auto_moderation
    config:
      banned_words: ["spam", "scam", "hate"]
      action: "delete"
```

### Keyword Alerts Module
Sends notifications to admin when specific keywords are mentioned.

**Configuration in `homeserver.yaml`:**
```yaml
modules:
  - module: modules.keyword_alerts
    config:
      keywords: ["urgent", "help", "emergency"]
      admin_user: "@admin:localhost"
```

## Usage

### Starting the Server
```bash
docker-compose up -d
```

### Stopping the Server
```bash
docker-compose down
```

### Viewing Logs
```bash
docker-compose logs -f synapse
```

### Creating Users
```bash
# Create admin user
docker-compose exec synapse register_new_matrix_user -c /data/homeserver.yaml -a -u admin -p password http://localhost:8008

# Create regular user
docker-compose exec synapse register_new_matrix_user -c /data/homeserver.yaml -u username -p password http://localhost:8008
```

### Testing the Chat Client
1. Open `frontend/index.html` in your browser
2. Login with your Matrix credentials
3. Select a room from the dropdown
4. Send and receive messages in real-time

## Configuration

### Server Configuration (`homeserver.yaml`)
- **Server Name**: localhost
- **Registration**: Enabled without verification
- **Federation**: Disabled for local testing
- **Redis**: Configured for caching
- **Modules**: Auto-moderation and keyword alerts

### Redis Configuration
- **Host**: redis
- **Port**: 6379
- **Password**: redis_password
- **Database**: 0

## Development

### Adding New Modules
1. Create a new Python file in the `modules/` directory
2. Implement the `create_module` function
3. Add module configuration to `homeserver.yaml`
4. Restart the Synapse container

### Module Template
```python
from typing import Dict, Any
from synapse.module_api import ModuleApi

class MyModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        # Initialize your module
        
    async def check_event_allowed(self, event, state):
        # Your event handling logic
        return True

def create_module(config: Dict[str, Any], api: ModuleApi):
    return MyModule(config, api)
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   - Check if ports 8008, 8448, 5432, or 6379 are already in use
   - Stop conflicting services or change ports in `docker-compose.yml`

2. **Database connection failed**
   - Ensure PostgreSQL container is running
   - Check database credentials in `homeserver.yaml`

3. **Module not loading**
   - Check module syntax and imports
   - Verify module configuration in `homeserver.yaml`
   - Check Synapse logs for errors

4. **Frontend connection failed**
   - Ensure Synapse server is running
   - Check browser console for errors
   - Verify CORS settings if needed

### Logs and Debugging
```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs synapse
docker-compose logs redis
docker-compose logs postgres

# Follow logs in real-time
docker-compose logs -f synapse
```

## Security Considerations

- Change default passwords in production
- Enable TLS/SSL for external access
- Configure proper firewall rules
- Regular security updates
- Monitor logs for suspicious activity

## Performance Tuning

- Adjust Redis memory settings
- Configure database connection pooling
- Tune Synapse worker processes
- Monitor resource usage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational purposes. Please review Matrix and Synapse licensing for production use.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Synapse documentation
3. Check Matrix community resources
4. Create an issue in this repository