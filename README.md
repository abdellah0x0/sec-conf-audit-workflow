# Agentic Security Audit Workflow

Automated Linux configuration security audit system using AI agents.

---

## Prerequisites

- Python 3.10+
- Docker
- pdfLaTeX (`miktex` on Windows, `texlive` on Linux)
- An Anthropic API key

---

## Project Structure

```
project_root/
├── audit-run-app/          ← Audit management web app (Flask, port 5001)
├── generate-script-app/    ← Audit script generator app (Flask, port 5000)
├── report-agent-app/       ← Report generation agent (FastAPI, port 8000)
├── .env                    ← Shared environment variables
└── requirements.txt
```

---

## Step 1 — Create Virtual Environment

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
```

---

## Step 2 — Start MinIO

```bash
docker run -d \
  --name minio \
  -p 9000:9000 \
  -p 9001:9001 \
  -e "MINIO_ROOT_USER=root" \
  -e "MINIO_ROOT_PASSWORD=MinIOH4sAv3ryStr0ngP4zz" \
  -v /home/minio/data:/data \
  minio/minio server /data --console-address ":9001"
```

MinIO console available at: `http://localhost:9001`

---

## Step 3 — Environment Variables

Create the following `.env` files:

### `./.env` and `./audit-run-app/.env`

```env
SECRET_KEY=ea60a36b4c8a0b870e4efa7f9c0f90a506097ff7b0714db813fc5b62186d5660
FLASK_DEBUG=1

# MinIO
MINIO_ENDPOINT=192.168.18.130:9000
MINIO_ACCESS_KEY=root
MINIO_SECRET_KEY=MinIOH4sAv3ryStr0ngP4zz
MINIO_BUCKET=audit-scripts
MINIO_RESULTS_BUCKET=audit-results
MINIO_BENCHMARKS_BUCKET=audit-benchmarks
MINIO_REPORTS_BUCKET=audit-reports
MINIO_SECURE=false

# Agent
AGENT_URL=http://127.0.0.1:8000

# API Keys
ANTHROPIC_API_KEY=<your-anthropic-key>
GROQ_API_KEY=<your-groq-key>

# Misc
HF_HUB_DISABLE_PROGRESS_BARS=1
```

> Replace `192.168.18.130` with your actual MinIO server IP.

---

## Step 4 — Create Admin Account

```bash
cd audit-run-app
python create_user.py
```

```
Username: Administrator
Password:
Confirm password:
Created auditor account 'Administrator'.
```

---

## Step 5 — Run the Applications

Open **3 separate terminals** and run each app:

### Terminal 1 — Audit Run App (port 5001)

```bash
cd audit-run-app
python app.py
```

### Terminal 2 — Generate Script App (port 5000)

```bash
python generate-script-app/app.py
```

### Terminal 3 — Report Agent App (port 8000)

```bash
python report-agent-app/app.py
```

---

## Step 6 — Usage

|Step|Action|URL|
|---|---|---|
|1|Upload benchmark PDF and generate audit script|`http://localhost:5000`|
|2|Create and run an audit on a Linux target|`http://localhost:5001`|
|3|Generate PDF report from audit results|`http://localhost:5001/audit/<id>/report`|

---

## MinIO Buckets

The following buckets are created automatically on first use:

|Bucket|Contents|
|---|---|
|`audit-scripts`|Generated bash audit scripts|
|`audit-results`|Anonymized audit result files|
|`audit-benchmarks`|Uploaded benchmark PDF files|
|`audit-reports`|Generated PDF audit reports|

---

## Troubleshooting

**pdfLaTeX not found**

```bash
# Windows — install MiKTeX
# https://miktex.org/download

# Linux
sudo apt install texlive-full
```

**MinIO connection refused**

```bash
# Check MinIO is running
docker ps | grep minio

# Check the endpoint in .env matches your server IP
MINIO_ENDPOINT=<your-ip>:9000
```

**Anthropic API key invalid**

```bash
# Verify the key is set correctly
echo $ANTHROPIC_API_KEY
# Should print: sk-ant-api03-...
```

**Report agent unavailable**

```bash
# Make sure Terminal 3 is running
python report-agent-app/app.py

# Check health endpoint
curl http://127.0.0.1:8000/health
# Expected: {"status": "ok"}
```