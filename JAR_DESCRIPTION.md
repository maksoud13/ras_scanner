# File Scanner JAR - Deployment Guide

## JAR Information

**Artifact ID**: filescanner  
**Version**: 0.0.1-SNAPSHOT  
**Group ID**: com.maksoud  
**Packaging**: JAR (Spring Boot Executable)  
**Java Version**: 21  
**Spring Boot Version**: 3.5.6  

## JAR File Details

**Filename**: `filescanner-0.0.1-SNAPSHOT.jar`  
**Location**: `target/filescanner-0.0.1-SNAPSHOT.jar` (after build)  
**Type**: Executable Spring Boot JAR (includes embedded Tomcat)

## What's Inside

The JAR contains:

- **Spring Boot Application**: Complete security analyzer application
- **Embedded Tomcat Server**: No external application server needed
- **All Dependencies**: Maven dependencies packaged inside
- **Configuration Files**: Application properties and resources
- **REST API**: Monitoring and security analysis endpoints
- **Scheduled Tasks**: Automated scanning and monitoring services

## System Requirements

- **Java Runtime**: Java 21 or higher
- **Memory**: Minimum 512MB RAM (recommended 1GB+)
- **Disk Space**: ~100MB for JAR + space for logs
- **OS**: Windows, Linux, macOS (cross-platform)
- **Network**: Optional (for REST API access)

## Installation & Execution

### Quick Start

```bash
java -jar filescanner-0.0.1-SNAPSHOT.jar
```

### With Custom Port

```bash
java -jar filescanner-0.0.1-SNAPSHOT.jar --server.port=9090
```

### With JVM Options

```bash
java -Xmx1024m -Xms512m -jar filescanner-0.0.1-SNAPSHOT.jar
```

### Background Execution (Windows)

```bash
start javaw -jar filescanner-0.0.1-SNAPSHOT.jar
```

### Background Execution (Linux/macOS)

```bash
nohup java -jar filescanner-0.0.1-SNAPSHOT.jar > app.log 2>&1 &
```

## Default Configuration

- **Server Port**: 8080
- **Context Path**: /
- **API Base URL**: `http://localhost:8080/api`

## Available Endpoints After Startup

Once running, access these endpoints:

- **Status**: `http://localhost:8080/api/monitoring/status`
- **Alerts**: `http://localhost:8080/api/monitoring/alerts`
- **Health**: `http://localhost:8080/api/monitoring/health`
- **Start Monitoring**: `POST http://localhost:8080/api/monitoring/start-system`

## Included Services

### 1. ScheduledMonitorService
- Automated system scanning every 5 minutes
- USB/Removable drive detection every 30 seconds
- System health monitoring every minute
- Daily deep security scan at 2 AM

### 2. RansomwareDetectionService
- Real-time ransomware threat detection
- Suspicious file pattern analysis
- Critical file modification tracking

### 3. SecurityScanner
- File system analysis
- Threat assessment
- Vulnerability scanning

### 4. MonitoringController
- REST API for monitoring status
- Alert retrieval endpoints
- Health check endpoints
- System monitoring control

## Monitored Paths (Default)

- `C:\Windows\System32`
- `C:\Program Files`
- `C:\ProgramData`
- `C:\Users`
- User home directory

## Logs & Output

The application outputs to:
- **Console**: Real-time monitoring logs
- **System.err**: Alert messages
- **Internal Alert Log**: Last 1000 entries (in-memory)

## Performance Characteristics

- **Startup Time**: ~5-10 seconds
- **Memory Usage**: 200-400MB (varies with scanning)
- **CPU Usage**: Low during idle, moderate during scans
- **Disk I/O**: Depends on monitored directory size

## Configuration Options

You can customize behavior via environment variables or application.properties:

```properties
server.port=8080
server.servlet.context-path=/
logging.level.root=INFO
```

## Stopping the Application

### Windows
```bash
Ctrl+C (in console)
```

### Linux/macOS
```bash
kill <process-id>
# or
pkill -f "filescanner"
```

## Troubleshooting

### Port Already in Use
```bash
java -jar filescanner-0.0.1-SNAPSHOT.jar --server.port=9090
```

### Insufficient Memory
```bash
java -Xmx2048m -jar filescanner-0.0.1-SNAPSHOT.jar
```

### Permission Denied (Linux/macOS)
```bash
chmod +x filescanner-0.0.1-SNAPSHOT.jar
java -jar filescanner-0.0.1-SNAPSHOT.jar
```

### Access Denied (Windows System Paths)
Run command prompt as Administrator for full system monitoring capabilities.

## Security Considerations

- The application requires elevated privileges to monitor system paths
- Alerts are logged in-memory (not persisted by default)
- API endpoints are CORS-enabled for cross-origin requests
- No authentication is configured by default (add if needed)

## Deployment Scenarios

### Development
```bash
java -jar filescanner-0.0.1-SNAPSHOT.jar
```

### Testing
```bash
java -Xmx512m -jar filescanner-0.0.1-SNAPSHOT.jar --server.port=8081
```

### Production
```bash
java -Xmx2048m -Xms1024m -XX:+UseG1GC -jar filescanner-0.0.1-SNAPSHOT.jar
```

## Building the JAR

From project root:

```bash
mvn clean package
```

The JAR will be created in the `target/` directory.

## Verification

After building, verify the JAR:

```bash
jar tf filescanner-0.0.1-SNAPSHOT.jar | head -20
```

## Support & Maintenance

- **Java Version**: Update to latest Java 21 LTS for security patches
- **Spring Boot**: Version 3.5.6 (check for updates)
- **Dependencies**: Review pom.xml for dependency updates

## Version History

- **0.0.1-SNAPSHOT**: Initial release with core monitoring features

---

**Created**: 2025  
**Last Updated**: 2025
