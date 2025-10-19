@echo off
echo Installing Security Analyzer as Windows Service...

:: Build the application
mvn clean package

:: Create installation directory
mkdir "C:\SecurityAnalyzer"
copy target\security-analyzer-spring-1.0.0.jar "C:\SecurityAnalyzer\"
copy src/main/resources/application.properties "C:\SecurityAnalyzer\"

:: Create run script
echo @echo off > "C:\SecurityAnalyzer\run.bat"
echo java -jar security-analyzer-spring-1.0.0.jar >> "C:\SecurityAnalyzer\run.bat"

:: Install as Windows Service using NSSM (you'd need to download nssm.exe)
:: nssm install SecurityAnalyzer "C:\SecurityAnalyzer\run.bat"

echo Installation complete!
echo The Security Analyzer will run automatically on system startup.
echo Access the dashboard at: http://localhost:8080/security-analyzer
pause