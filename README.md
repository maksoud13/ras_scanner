# File Scanner - Security Analyzer

A Spring Boot-based security analysis and file monitoring application designed to detect ransomware threats, analyze file systems, and provide real-time security monitoring for critical system paths and removable drives.

## Features

- **Real-time File Monitoring**: Continuously monitors critical system paths and removable drives
- **Ransomware Detection**: Identifies suspicious file patterns and potential ransomware activity
- **Scheduled Scanning**: Automated scans at configurable intervals
  - System scan every 5 minutes
  - Removable drive check every 30 seconds
  - System health check every minute
  - Deep security scan daily at 2 AM
- **Alert System**: Real-time alerts for suspicious activities and threats
- **REST API**: Comprehensive API endpoints for monitoring and status checks
- **Memory & Performance Monitoring**: Tracks system resource usage and alerts on anomalies

## Technology Stack

- **Framework**: Spring Boot 3.5.6
- **Language**: Java 21
- **Build Tool**: Maven
- **Key Dependencies**:
  - Spring Web (REST API)
  - Spring Actuator (Health checks)
  - Spring Validation
  - Jackson (JSON processing)
  - Apache Commons Lang3

## Project Structure

```
src/
├── main/
│   ├── java/com/maksoud/filescanner/
│   │   ├── analyzer/
│   │   │   ├── controller/       # REST API endpoints
│   │   │   ├── service/          # Business logic
│   │   │   └── model/            # Data models
│   │   └── core/                 # Core security scanning logic
│   └── resources/                # Configuration files
└── test/
    └── java/                     # Unit tests
```

## Getting Started

### Prerequisites

- Java 21 or higher
- Maven 3.6+

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd file-scanner
```

2. Build the project:
```bash
mvn clean install
```

3. Run the application:
```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080` by default.

## API Endpoints

### Monitoring Endpoints

- **GET** `/api/monitoring/status` - Get current monitoring status
- **GET** `/api/monitoring/alerts` - Retrieve recent alerts (last 50)
- **POST** `/api/monitoring/start-system` - Start system monitoring
- **GET** `/api/monitoring/health` - Health check endpoint

### Example Requests

Get monitoring status:
```bash
curl http://localhost:8080/api/monitoring/status
```

Get recent alerts:
```bash
curl http://localhost:8080/api/monitoring/alerts
```

## Configuration

The application monitors the following critical paths by default:

- `C:\Windows\System32`
- `C:\Program Files`
- `C:\ProgramData`
- `C:\Users`
- User home directory (`Documents`)

Removable drives (D:, E:, F:, G:, H:) are automatically detected and monitored.

## Monitoring Services

### ScheduledMonitorService

Handles all scheduled scanning tasks:

- **scheduledSystemScan()**: Scans critical system paths every 5 minutes
- **checkRemovableDrives()**: Detects and monitors USB drives every 30 seconds
- **systemHealthCheck()**: Monitors memory usage every minute
- **dailyDeepScan()**: Performs comprehensive scan daily at 2 AM

### RansomwareDetectionService

Analyzes files for ransomware indicators:
- File extension anomalies
- Suspicious file patterns
- Critical file modifications

## Alert System

The application maintains a synchronized alert log with:
- Real-time threat notifications
- System health warnings
- Monitoring status updates
- Emergency protocol triggers

Alerts are logged with timestamps and severity levels.

## Security Features

- **Emergency Protocol**: Triggered when ransomware is detected
  - Logs emergency actions
  - Tracks suspicious file counts
  - Monitors critical file modifications
  
- **System Access Monitoring**: Verifies access to critical system directories
- **Memory Threshold Alerts**: Warns when memory usage exceeds 80%
- **Process Monitoring**: Detects suspicious process activity

## Building & Deployment

### Build JAR

```bash
mvn clean package
```

The JAR file will be created in the `target/` directory.

### Run JAR

```bash
java -jar target/filescanner-0.0.1-SNAPSHOT.jar
```

## Development

### Running Tests

```bash
mvn test
```

### Code Style

The project follows standard Java conventions with:
- Spring Boot best practices
- RESTful API design patterns
- Dependency injection for loose coupling

## Logging

The application uses standard Java logging with:
- Console output for real-time monitoring
- Alert log storage (last 1000 entries)
- Timestamped entries for audit trails

## Performance Considerations

- **Concurrent Collections**: Uses `ConcurrentHashMap` and synchronized lists for thread safety
- **Scheduled Tasks**: Non-blocking scheduled execution
- **Memory Management**: Maintains alert log size limit (1000 entries)
- **Efficient Scanning**: Optimized file system traversal

## Troubleshooting

### High Memory Usage
- Check the `/api/monitoring/status` endpoint for memory metrics
- Review alert logs for scanning patterns
- Consider adjusting scan intervals in `ScheduledMonitorService`

### Missing Alerts
- Verify the application is running
- Check system permissions for monitored paths
- Review application logs for errors

<!-- ## Future Enhancements

- Database integration for persistent alert storage
- Web UI dashboard for real-time monitoring
- Email/SMS notifications for critical alerts
- Configurable scanning intervals via API
- Machine learning-based threat detection
- Integration with external security services -->

## License

[Add your license information here]

## Support

For issues, questions, or contributions, please contact the development team.

---

**Version**: 0.0.1-SNAPSHOT  
**Last Updated**: 2025
