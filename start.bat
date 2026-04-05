@echo off
echo ============================================
echo   BugHunter Pro - Starting Full Stack
echo ============================================
echo.

:: Start backend in a new terminal window
echo [1/2] Starting Python FastAPI backend on http://localhost:8000
start "BugHunter Backend" cmd /k "cd /d "%~dp0backend" && python main.py"

:: Give backend a moment to start
timeout /t 3 /nobreak >nul

:: Start frontend in a new terminal window
echo [2/2] Starting Next.js frontend on http://localhost:3000
start "BugHunter Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ============================================
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:3000
echo   API Docs: http://localhost:8000/docs
echo ============================================
echo.
echo Opening browser in 5 seconds...
timeout /t 5 /nobreak >nul
start http://localhost:3000
