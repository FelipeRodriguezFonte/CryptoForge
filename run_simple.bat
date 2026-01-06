@echo off
REM Simple runner for CryptoForge

cd /d "%~dp0"

REM Check if JAR exists in current directory (portable mode)
if exist "cryptoforge-1.0.0.jar" (
    set JAR_FILE=cryptoforge-1.0.0.jar
) else (
    REM Check if JAR exists in target directory (maven project mode)
    if exist "target\cryptoforge-1.0.0.jar" (
        set JAR_FILE=target\cryptoforge-1.0.0.jar
    ) else (
        set JAR_FILE=target\cryptoforge-1.0.0.jar
    )
)

if not exist "%JAR_FILE%" (
    echo Error: %JAR_FILE% not found.
    echo Please run 'mvn clean package -DskipTests' first to build the project.
    echo OR copy 'cryptoforge-1.0.0.jar' to this directory.
    pause
    exit /b 1
)

echo Starting CryptoForge...
java -jar "%JAR_FILE%"
pause
