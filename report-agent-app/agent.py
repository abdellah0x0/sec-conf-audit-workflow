import anyio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AssistantMessage,
    TextBlock,
    ResultMessage,
    create_sdk_mcp_server
)
from tools import all_tools

def create_options() -> ClaudeAgentOptions:
    server = create_sdk_mcp_server(
        name="report-tools",
        version="1.0.0",
        tools=all_tools
    )

    return ClaudeAgentOptions(
        system_prompt="""You are an expert audit report generator. Your job is to produce professional LaTeX audit reports.

When given a run_id and benchmark_name, you must follow these steps in exact order:

STEP 1 — READ INPUTS
- Read the LaTeX report template using the read_template tool
- Read the audit results file using the read_audit_results tool with the given run_id
- Read the audit benchmark file using the read_audit_benchmark tool with the given benchmark_name

STEP 2 — GENERATE THE REPORT
- Analyze the audit results against the benchmark criteria
- Generate a complete, professional audit report
- You MUST strictly respect the template structure — use the exact same sections, formatting, and LaTeX commands defined in the template
- Fill in all placeholders with real data from the audit results and benchmark
- Do not add or remove sections from the template

STEP 3 — RETURN THE LATEX
- Return ONLY the final complete LaTeX content, nothing else
- No explanation, no comments, no markdown — pure LaTeX content only
- Keep Encrypted data from results as it is

RULES:
- Never skip a step
- Never guess data — only use what is in the audit results and benchmark files
- Keep Encrypted data as it is , don't try to decrypt
- If a file is missing or a step fails, report the error clearly and stop""",
        mcp_servers={"report-tools": server},
        allowed_tools=[
            "mcp__report-tools__read_template",
            "mcp__report-tools__read_audit_results",
            "mcp__report-tools__read_audit_benchmark",
        ],
        max_turns=10,
    )


async def run_report_agent(run_id: str, benchmark_name: str) -> str:
    options = create_options()
    prompt = f"Generate the audit report for run_id: {run_id} using benchmark: {benchmark_name}"
    latex_content = ""

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    latex_content += block.text
        elif isinstance(message, ResultMessage):
            print(f"[+] Done — cost: ${message.total_cost_usd:.4f}")

    return latex_content


def report_agent(run_id: str, benchmark_name: str) -> str:
    return anyio.run(run_report_agent, run_id, benchmark_name)