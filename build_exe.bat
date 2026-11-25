@echo off
chcp 65001 >nul
title Сборка BTC-ECDSA-Scanner-Cyber.exe
cd /d "%~dp0"

echo [1/3] Проверка Python и установка PyInstaller...
python -m pip install --upgrade pip pyinstaller
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить PyInstaller.
    pause
    exit /b 1
)

echo [2/3] Запуск автоматических тестов...
python -m unittest discover -s tests -v
if errorlevel 1 (
    echo [ОШИБКА] Тесты не пройдены! Сборка остановлена.
    pause
    exit /b 1
)

echo [3/3] Сборка автономного Windows EXE...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "BTC-ECDSA-Scanner-Cyber" ^
    --add-data "core;core" ^
    --add-data "ui;ui" ^
    main.py

if errorlevel 1 (
    echo [ОШИБКА] Ошибка сборки PyInstaller.
    pause
    exit /b 1
)

echo.
echo [ГОТОВО] Файл создан: dist\BTC-ECDSA-Scanner-Cyber.exe
pause
