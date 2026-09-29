from claude_agent_sdk import tool
from typing import Any
from pathlib import Path

# Get the project root (parent of tools/)
PROJECT_ROOT = Path(__file__).parent.parent

@tool(
    "read_template",
    "Read the LaTeX template file",
    {}  
)
async def read_template(args: dict[str, Any]) -> dict[str, Any]:
    template_path = PROJECT_ROOT / "template" / "template.tex"

    if not template_path.exists():
        return {"content": [{"type": "text", "text": f"Error: template not found at {template_path}"}]}

    try:
        content = template_path.read_text(encoding="utf-8")
        return {"content": [{"type": "text", "text": f"Template content:\n\n{content}"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error reading template: {str(e)}"}]}