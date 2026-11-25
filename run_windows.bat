@echo off
chcp 65001 >nul
title BTC ECDSA // Кибер-сканер уязвимостей
cd /d "%~dp0"
python main.py %*
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Не удалось запустить приложение. Убедитесь, что установлен Python 3.10+.
    pause
)
