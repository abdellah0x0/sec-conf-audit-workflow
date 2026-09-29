import os
import threading
import time
from collections import defaultdict

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   abort,send_file, Response)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

from models import db, User, AuditRun, AuditResult, utcnow, RUN_SUCCESS, RUN_FAILED
from ssh_runner import run_audit_script, AuditConnectionError
import warnings
warnings.filterwarnings("ignore")

load_dotenv()

app = Flask(__name__)

_DEFAULT_SECRET = "change-this-in-production"
SECRET_KEY = os.getenv("SECRET_KEY", _DEFAULT_SECRET)
DEBUG = os.getenv("FLASK_DEBUG", "").lower() in ("1", "true", "yes")


if SECRET_KEY == _DEFAULT_SECRET and not DEBUG:
    raise RuntimeError(
        "SECRET_KEY is still the default. Set a strong SECRET_KEY in the "
        "environment before running outside debug mode."
    )
    
MAX_KEY_BYTES = 64 * 1024  # 64 KB

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI="sqlite:///audit_app.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not DEBUG,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB
)

db.init_app(app)
csrf = CSRFProtect(app)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

login_manager = LoginManager(app)
login_manager.login_view = "login"


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


_CSS_PATH = os.path.join(os.path.dirname(__file__), "static", "style.css")
_css_cache = None


def _load_inline_css():
    global _css_cache
    if _css_cache is not None and not DEBUG:
        return _css_cache
    try:
        with open(_CSS_PATH, "r", encoding="utf-8") as f:
            _css_cache = f.read()
    except OSError:
        _css_cache = ""
    return _css_cache


@app.context_processor
def inject_inline_css():
    return dict(inline_css=_load_inline_css())

#---- LOAD MINIO ENV VARIABLES --------------------------------------------
 
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "audit-scripts")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_RESULTS_BUCKET = os.getenv("MINIO_RESULTS_BUCKET", "audit-results")
MINIO_REPORTS_BUCKET = os.getenv("MINIO_REPORTS_BUCKET", "audit-reports")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false")

def _minio_client():
    from minio import Minio
    return Minio(
        MINIO_ENDPOINT,
        access_key=os.getenv("MINIO_ACCESS_KEY", ""),
        secret_key=os.getenv("MINIO_SECRET_KEY", ""),
        secure=os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes"),
    )


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

#--- LOAD AGENT ENV ---------------------------------------------

AGENT_URL= os.getenv("AGENT_URL", "") 

# --- RATE LIMIT PROTECTION -------------------------------------


_LOGIN_ATTEMPTS = defaultdict(list)   
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300


def _throttle_key():
    return request.remote_addr or "unknown"


def _too_many_attempts(key):
    now = time.time()
    recent = [t for t in _LOGIN_ATTEMPTS[key] if now - t < _WINDOW_SECONDS]
    _LOGIN_ATTEMPTS[key] = recent
    return len(recent) >= _MAX_ATTEMPTS


def _record_attempt(key):
    _LOGIN_ATTEMPTS[key].append(time.time())


def _clear_attempts(key):
    _LOGIN_ATTEMPTS.pop(key, None)

# ----- GET BENCHMARK NAMES FROM MINIO BUCKET ------------

def get_benchmarks():
    """Benchmark names = the '<name>.sh' scripts present in the MinIO bucket.

    This is the source of truth for what can be audited: a benchmark is
    auditable exactly when its generated script has been uploaded."""
    try:
        client = _minio_client()
        if not client.bucket_exists(MINIO_BUCKET):
            return []
        names = []
        for obj in client.list_objects(MINIO_BUCKET, recursive=True):
            key = obj.object_name
            
            if key.endswith(".sh"):
                names.append(key[:-3])  # strip the .sh suffix
        return sorted(names)
    except Exception:
        return []

#--- SAVE AUDIT RESULTS --------------------------------- 
from anonymization.anonymizer import anonymizer

def _render_results_text(run):
    """Render an AuditRun and its results as a plain-text report."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"Audit #{run.id} - {run.benchmark}")
    lines.append("=" * 70)
    lines.append(f"Host       : {anonymizer(run.host)}:{run.port}")
    lines.append(f"SSH user   : {anonymizer(run.ssh_user)}")
    lines.append(f"Status     : {run.status}")
    lines.append(f"Started    : {run.started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    if run.finished_at:
        lines.append(f"Finished   : {run.finished_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    if run.duration_seconds is not None:
        lines.append(f"Duration   : {run.duration_seconds}s")
    lines.append(f"Started by : {run.started_by}")
    if run.status == RUN_FAILED and run.error:
        lines.append("")
        lines.append(f"ERROR: {run.error}")
    lines.append("")
    lines.append(f"Results ({run.result_count}):")
    lines.append("-" * 70)
    for r in run.results:
        lines.append(f"[{r.rule}] {r.command}")
        lines.append(f"    -> {anonymizer(r.command_result)}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _results_txt_path(run_id):
    return os.path.join(RESULTS_DIR, f"audit_{run_id}.txt")


def _write_results_txt(run):
    """Write a run's text report to the results directory. Returns the path."""
    if run is None:
        return None
    path = _results_txt_path(run.id)
    with open(path, "w", encoding="utf-8") as f:
        f.write(_render_results_text(run))
    return path

# -------------------------------------------------------------------------------------
from minio import Minio

# ---------------- RUN AUDIT AND SAVE RESULTS -----------------------------------------

def _run_in_background(run_id, host, port, ssh_user, password, key_content,
                       key_passphrase, benchmark):
    """Executed in a worker thread. Uses its own scoped DB session so it never
    shares the request thread's session (which is not thread-safe).

    The private key content and any passphrase live only for the duration of
    this function and are dropped when it returns - they are never persisted."""
    client = Minio(MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes"),
    )
    
    with app.app_context():
        session = db.session()
        try:
            run = session.get(AuditRun, run_id)
            if run is None:
                return
            try:
                rows = run_audit_script(
                    host, port, ssh_user, password, key_content, benchmark,
                    key_passphrase=key_passphrase,
                )
                for rule, command, result in rows:
                    session.add(AuditResult(
                        run_id=run_id, rule=rule, command=command, command_result=result
                    ))
                run.status = RUN_SUCCESS
            except AuditConnectionError as e:
                run.status = RUN_FAILED
                run.error = str(e)
            except Exception as e:
                run.status = RUN_FAILED
                run.error = f"Unexpected error: {e}"
            finally:
                run.finished_at = utcnow()
                session.commit()
                # Auto-save a .txt of this run's results.
                try:
                    source = _write_results_txt(session.get(AuditRun, run_id))
                    dest = f"audit_{run_id}.txt"
                    bucket_name = "audit-results"
                    found = client.bucket_exists(bucket_name)
                    if not found:
                        client.make_bucket(bucket_name)
                    client.fput_object(bucket_name, dest, source,)
                    os.remove(source)
                except Exception as e:
                    print(f"Could not write results txt for run {run_id}: {e}")
        finally:
            db.session.remove()
            del key_content, key_passphrase, password

# ------------------- APP ROUTES -------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        key = _throttle_key()
        if _too_many_attempts(key):
            flash("Too many failed attempts. Wait a few minutes and try again.", "error")
            return render_template("login.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            _clear_attempts(key)
            login_user(user)
            return redirect(url_for("dashboard"))

        _record_attempt(key)
        flash("Invalid username or password", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    runs = AuditRun.query.order_by(AuditRun.started_at.desc()).all()
    return render_template("dashboard.html", runs=runs)

# ---------------------------------- AUDIT RUN ------------------------------------------

@app.route("/audit/new", methods=["GET", "POST"])
@login_required
def new_audit():
    benchmarks = get_benchmarks()
    
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        try:
            port = int(request.form.get("port") or 22)
        except ValueError:
            flash("Port must be a number", "error")
            return redirect(url_for("new_audit"))
        if not (1 <= port <= 65535):
            flash("Port must be between 1 and 65535", "error")
            return redirect(url_for("new_audit"))

        ssh_user = request.form.get("user", "").strip() or "root"
        password = request.form.get("password", "").strip() or None
        key_passphrase = request.form.get("key_passphrase", "").strip() or None
        benchmark = request.form.get("benchmark", "").strip()

     
        key_content = None
        key_file = request.files.get("key_file")
        if key_file and key_file.filename:
            raw = key_file.read(MAX_KEY_BYTES + 1)
            if len(raw) > MAX_KEY_BYTES:
                flash("Key file is too large to be a private key", "error")
                return redirect(url_for("new_audit"))
            try:
                key_content = raw.decode("utf-8")
            except UnicodeDecodeError:
                flash("Key file is not valid text - upload a PEM/OpenSSH private key", "error")
                return redirect(url_for("new_audit"))

        if not host or not benchmark:
            flash("Host and benchmark are required", "error")
            return redirect(url_for("new_audit"))
        if benchmark not in benchmarks:
            flash("Unknown benchmark - pick one from the list", "error")
            return redirect(url_for("new_audit"))
        if not password and not key_content:
            flash("Provide either a password or a private key file", "error")
            return redirect(url_for("new_audit"))

        run = AuditRun(
            host=host, port=port, ssh_user=ssh_user, benchmark=benchmark,
            status="running", started_by=current_user.username,
        )
        db.session.add(run)
        db.session.commit()
        run_id = run.id
        thread = threading.Thread(
            target=_run_in_background,
            args=(run_id, host, port, ssh_user, password, key_content,
                  key_passphrase, benchmark),
            daemon=True,
        )
        thread.start()

        return redirect(url_for("view_audit", run_id=run_id))

    return render_template("new_audit.html", benchmarks=benchmarks)


@app.route("/audit/<int:run_id>")
@login_required
def view_audit(run_id):
    run = db.session.get(AuditRun, run_id) or abort(404)
    return render_template("result.html", run=run)


@app.route("/audit/<int:run_id>/download")
@login_required
def download_audit(run_id):
    """Download this run's results as a .txt file. Generated fresh from the DB
    so it works for any run and always reflects current data."""
    run = db.session.get(AuditRun, run_id) or abort(404)
    text = _render_results_text(run)
    filename = f"audit_{run_id}_{run.benchmark}.txt"
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/audit/<int:run_id>/delete", methods=["POST"])
@login_required
def delete_audit(run_id):
    run = db.session.get(AuditRun, run_id) or abort(404)
    db.session.delete(run)
    db.session.commit()
    flash(f"Audit #{run_id} deleted", "info")
    return redirect(url_for("dashboard"))


# ------------------------ REPORT GENERATION --------------------------------
import requests
import subprocess
import tempfile
import os
import io
from anonymization.deanonymizer import deanonymize
from datetime import datetime, timezone

def _check_anonymization_step(run_id):
    try:
        results_file = f"audit_{run_id}.txt"
        client = _minio_client()
        for obj in client.list_objects(MINIO_RESULTS_BUCKET, recursive=True):
            if obj.object_name == results_file:
                return True
        return False                        
    except Exception as e:
        print(f"[-] MinIO check failed: {e}")
        return False


def _check_report_agent_status():
    try:
        response = requests.get(
            f"{AGENT_URL}/health",                
            timeout=5
        )
        return response.json().get("status") == "ok"
    except Exception as e:
        print(f"[-] Agent health check failed: {e}")
        return False


def _compile_latex(latex_content: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
        tex_path = os.path.join(tmpdir, "report.tex")

        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(latex_content)

        for _ in range(2):
            result = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", tex_path],
                cwd=tmpdir,
                capture_output=True,
                text=True
            )

        pdf_path = os.path.join(tmpdir, "report.pdf")

        if not os.path.exists(pdf_path):
            raise Exception(f"LaTeX compilation failed:\n{result.stdout[-2000:]}")

        with open(pdf_path, "rb") as f:
            return f.read()


def _upload_to_minio(run_id, pdf_bytes: bytes):
    client = _minio_client()
    report_name = f"audit_{run_id}_report.pdf"

    if not client.bucket_exists(MINIO_REPORTS_BUCKET):
        client.make_bucket(MINIO_REPORTS_BUCKET)

    client.put_object(
        MINIO_REPORTS_BUCKET,
        report_name,
        io.BytesIO(pdf_bytes),
        len(pdf_bytes),
        content_type="application/pdf"
    )
    print(f"[+] Uploaded: {MINIO_REPORTS_BUCKET}/{report_name}")


def _set_report_failed(run_id, reason):     
    try:
        with app.app_context():
            run = db.session.get(AuditRun, run_id)
            run.report_status = "failed"
            run.error = reason
            run.finished_at = datetime.now(timezone.utc)
            db.session.commit()
    except Exception as e:
        print(f"[-] Could not update DB: {e}")


def _run_agent(run_id, benchmark_name):
    try:
        print("[*] STARTING...")
        response = requests.post(
            f"{AGENT_URL}/generate-report",    
            json={
                "run_id": str(run_id),
                "benchmark_name": str(benchmark_name)
            },
            timeout=300
        )
        response.raise_for_status()
        data = response.json()

        latex_content = data.get("latex_content", "")
        if not latex_content.strip():
            raise Exception("Agent returned empty LaTeX content")

        print("[*] Deanonymizing LaTeX content...")
        deanonymized_latex = deanonymize(latex_content)

        print("[*] Compiling LaTeX...")
        pdf_bytes = _compile_latex(deanonymized_latex)

        print("[*] Uploading to MinIO...")
        _upload_to_minio(run_id, pdf_bytes)

        print(f"[+] Report generated successfully for run_id: {run_id}")

        with app.app_context():
            run = db.session.get(AuditRun, run_id)
            run.report_status = "done"
            run.report_url = f"audit-reports/audit_{run_id}_report.pdf"
            run.finished_at = datetime.now(timezone.utc)
            db.session.commit()

    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to agent at {AGENT_URL}")
        _set_report_failed(run_id, "Agent unreachable")  

    except requests.exceptions.HTTPError as e:
        print(f"[-] Agent error: {e.response.status_code} {e.response.text}")
        _set_report_failed(run_id, f"Agent error {e.response.status_code}")

    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        _set_report_failed(run_id, str(e))


@app.route('/audit/<int:run_id>/report')
def generate_report(run_id):
    run = db.session.get(AuditRun, run_id) or abort(404)

    
    if run.report_status == "done":
        flash("Report already generated.")
        return render_template("result.html", run=run)

    if run.report_status == "running":
        flash("Report is already being generated, please wait.")
        return render_template("result.html", run=run)

    if not _check_anonymization_step(run_id):
        flash("WAIT FOR ANONYMIZATION AND TRY AGAIN !")
        return render_template("result.html", run=run)

    if not _check_report_agent_status():
        flash("REPORT AGENT IS NOT AVAILABLE")
        return render_template("result.html", run=run)

    
    run.report_status = "running"
    db.session.commit()

    thread = threading.Thread(
        target=_run_agent,
        args=(run_id, run.benchmark),
        daemon=True,
    )
    thread.start()

    flash("REPORT GENERATION IS STARTING ...")
    return render_template("result.html", run=run)


@app.route('/audit/<int:run_id>/report-status')
def report_status(run_id):
    run = db.session.get(AuditRun, run_id) or abort(404)
    return {
        "status": run.report_status,
        "report_url": run.report_url,
        "error": run.error
    }


@app.route('/audit/<int:run_id>/download-report')
def download_report(run_id):
    run = db.session.get(AuditRun, run_id) or abort(404)

    if run.report_status != "done":
        abort(404)

    client = _minio_client()
    report_name = f"audit_{run_id}_report.pdf"

    response = client.get_object(MINIO_REPORTS_BUCKET, report_name)
    pdf_bytes = response.read()
    response.close()
    response.release_conn()

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=report_name
    )
    
if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0", port=5001)
