from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from detector import ThreatDetector
import uvicorn

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

detector = ThreatDetector()

@app.get("/")
async def root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/analyze")
async def analyze(packets: int = 100, ips: int = 5, ssh: int = 2, ports: int = 1):
    return detector.analyze(packets, ips, ssh, ports)

if __name__ == "__main__":
    print("Launched!")
    print("http://localhost:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
