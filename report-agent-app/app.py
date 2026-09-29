from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from agent import run_report_agent
import uvicorn

app = FastAPI()

class ReportRequest(BaseModel):
    run_id: str
    benchmark_name: str

class ReportResponse(BaseModel):
    run_id: str
    status: str
    latex_content: str      

@app.post("/generate-report", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    try:
        latex_content = await run_report_agent(
            run_id=request.run_id,
            benchmark_name=request.benchmark_name
        )

        if not latex_content.strip():
            raise HTTPException(status_code=500, detail="Agent returned empty content")

        return ReportResponse(
            run_id=request.run_id,
            status="success",
            latex_content=latex_content
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)