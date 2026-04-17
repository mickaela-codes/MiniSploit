"""
server/__main__.py
MiniSploit Server start.

Description: Uses uvicorn to start FastAPI defined in app.py

Usage: python3 -m server
"""
import uvicorn
import logging

def main():
    #Configure logging and launch ASGI server
    logging.basicConfig(
        level=logging.INFO, #prints time, info, and message
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    #Run the server
    uvicorn.run(
        "server.app:app", #import module server/app.py
        host="0.0.0.0", #Connect to all interfaces, listen on port 8000
        port=8000,
        reload=False, #Don't auto reload
        log_level="info",
    )

if __name__ == "__main__":
    main()
