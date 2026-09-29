from .minio_client import minio_client
from claude_agent_sdk import tool
from typing import Any
import os
from dotenv import load_dotenv

load_dotenv()

MINIO_RESULTS_BUCKET = os.getenv("MINIO_RESULTS_BUCKET", "audit-results")

@tool(
    "read_audit_results",
    "Read audit scan results from a text file stored in MinIO given a run_id",
    {"run_id": str}
)
async def read_audit_results(args: dict[str, Any]) -> dict[str, Any]:
    results_file = f"audit_{args['run_id']}.txt"

    try:
        client = minio_client()
        response = client.get_object(MINIO_RESULTS_BUCKET, results_file)
        text = response.read().decode("utf-8")
        response.close()
        response.release_conn()

        if not text.strip():
            return {"content": [{"type": "text", "text": f"No content found in {results_file}"}]}

        return {"content": [{"type": "text", "text": f"Audit Results [run_id: {args['run_id']}]:\n\n{text}"}]}

    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error reading audit results '{results_file}': {str(e)}"}]}