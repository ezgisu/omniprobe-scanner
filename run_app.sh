#!/bin/bash

# Kill ports if running
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:5173 | xargs kill -9 2>/dev/null

echo "🚀 Starting Vulnerability Scanner..."

# Start Backend
echo "Starting Backend (Port 8000)..."
cd backend
# Check if venv exists, if not create it
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

uvicorn main:app --reload --host 0.0.0.0 --port 8000 > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Start Frontend
echo "Starting Frontend (Port 5173)..."
cd frontend
npm run dev -- --host 0.0.0.0 > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

echo "✅ App is ready!"
echo "🌍 Dashboard: http://localhost:5173"
echo "🔧 API: http://localhost:8000"
echo ""
echo "📝 Logs located in backend.log and frontend.log"
echo "Press Ctrl+C to stop both servers."

# Trap Ctrl+C to kill bg processes
trap "kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT

wait
