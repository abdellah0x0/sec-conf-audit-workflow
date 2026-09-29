from flask import Flask, render_template, request, jsonify, send_from_directory
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import os
import shutil
import tempfile
import threading
import warnings
warnings.filterwarnings("ignore")

import generate_audit_script_smart       

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './generate-script-app/temp-uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

ALLOWED_EXTENSIONS = {'pdf'}

GENERATION_MODES = {
    "smart": "Smart (Claude agent reads the document directly)",
}
DEFAULT_MODE = "smart"




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html', modes=GENERATION_MODES, default_mode=DEFAULT_MODE)


def _persist_pdf_for_smart(src_path, benchmark_name):
    """The Smart agent reads the PDF AFTER the request returns, so we can't let
    the request's finally-block delete it first. Copy it to a private temp path
    the background thread owns and is responsible for deleting."""
    fd, dst = tempfile.mkstemp(suffix=".pdf", prefix=f"{benchmark_name}_")
    os.close(fd)
    shutil.copyfile(src_path, dst)
    return dst


def _smart_worker(benchmark_name, pdf_copy_path):
    """Background worker for the Smart path. Owns pdf_copy_path and deletes it."""
    try:
        generate_audit_script_smart.generate_script_smart(benchmark_name, pdf_copy_path)
    except Exception as e:
        print(f"\u2717 Smart generation failed for {benchmark_name}: {e}")
    finally:
        if os.path.exists(pdf_copy_path):
            try:
                os.remove(pdf_copy_path)
            except OSError:
                pass

#---- LOAD MINIO ENV VARIABLES --------------------------------------------
 
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_BENCHMARKS_BUCKET = os.getenv("MINIO_BENCHMARKS_BUCKET", "audit-benchmarks")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false")

def _minio_client():
    from minio import Minio
    return Minio(
        MINIO_ENDPOINT,
        access_key=os.getenv("MINIO_ACCESS_KEY", ""),
        secret_key=os.getenv("MINIO_SECRET_KEY", ""),
        secure=os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes"),
    )


@app.route('/upload', methods=['POST'])
def upload_file():
    filepath = None
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        benchmark_name = request.form.get('benchmark_name', '').strip()
        mode = request.form.get('mode', DEFAULT_MODE).strip().lower()

        if not benchmark_name:
            return jsonify({"error": "Benchmark name required"}), 400
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Only PDF files allowed"}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # --- UPLOAD BENCHMARK FILE TO MINIO BUCKET : -----------------------
        
        client = _minio_client()
        dest = f"{benchmark_name}.pdf"
        bucket_name = MINIO_BENCHMARKS_BUCKET
        
        found = client.bucket_exists(bucket_name)
        if not found:
            client.make_bucket(bucket_name)
        client.fput_object(bucket_name, dest, filepath,)
        
        if mode == "smart":
            
            pdf_copy = _persist_pdf_for_smart(filepath, benchmark_name)
            threading.Thread(
                target=_smart_worker,
                args=(benchmark_name, pdf_copy),
                daemon=True,
            ).start()
            message = (f"Uploaded. Smart generation is starting "
                       f"for '{benchmark_name}'...")
            chunks_count = None



        resp = {
            "success": True,
            "message": message,
            "benchmark": benchmark_name,
            "mode": mode,
        }
        if chunks_count is not None:
            resp["chunks"] = chunks_count
        return jsonify(resp), 200

    except Exception as e:
        print(f"\u2717 Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass


@app.route('/download/<path:filename>')
def download(filename):
    return send_from_directory(app.config['SCRIPTS_DIR'], filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
