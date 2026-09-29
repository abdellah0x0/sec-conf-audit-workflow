from .minio_client import minio_client
from claude_agent_sdk import tool
from typing import Any
import io
import pdfplumber
import os
from dotenv import load_dotenv

load_dotenv()

MINIO_BENCHMARKS_BUCKET = os.getenv("MINIO_BENCHMARKS_BUCKET", "audit-benchmarks")

@tool(
    "read_audit_benchmark",
    "Read and extract text content from an audit benchmark PDF file stored in MinIO",
    {"benchmark_name": str}
)
async def read_audit_benchmark(args: dict[str, Any]) -> dict[str, Any]:
    benchmark_file = f"{args['benchmark_name']}.pdf"

    try:
        client = minio_client()
        response = client.get_object(MINIO_BENCHMARKS_BUCKET, benchmark_file)
        pdf_bytes = response.read()
        response.close()
        response.release_conn()

        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            text = "\n".join(
                page.extract_text()
                for page in pdf.pages
                if page.extract_text()   # skip empty pages
            )

        if not text.strip():
            return {"content": [{"type": "text", "text": f"No text could be extracted from {benchmark_file}"}]}

        return {"content": [{"type": "text", "text": f"Benchmark [{args['benchmark_name']}]:\n\n{text}"}]}

    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error reading benchmark '{benchmark_file}': {str(e)}"}]}