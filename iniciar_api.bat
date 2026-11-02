
@echo off
cd /d "C:\Users\USUARIO\GymFit1\backend"
call .venv\Scripts\activate
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause

