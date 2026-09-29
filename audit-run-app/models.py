from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Timezone-aware UTC. datetime.utcnow() is deprecated in 3.12+ and returns
    a naive datetime, which is a footgun for comparisons and display."""
    return datetime.now(timezone.utc)


class User(db.Model, UserMixin):
    """Auditor account. No self-registration - accounts are created via create_user.py."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


# Run status: SUCCESS means the script ran and returned results;
# FAILED means the run could not complete (connection / auth / script error).
RUN_RUNNING = "running"
RUN_SUCCESS = "success"
RUN_FAILED = "failed"


class AuditRun(db.Model):
    """One audit execution against one host, using one benchmark's generated script."""
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=22)
    ssh_user = db.Column(db.String(80), nullable=False, default="root")
    benchmark = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default=RUN_RUNNING, index=True)  # running|success|failed
    error = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    started_by = db.Column(db.String(80), nullable=False)
    report_status = db.Column(db.String(20), nullable=True)   # None|running|done|failed
    report_url = db.Column(db.String(500), nullable=True)

    results = db.relationship(
        "AuditResult", backref="run", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def result_count(self):
        return len(self.results)

    @property
    def duration_seconds(self):
        if not self.finished_at:
            return None
        return int((self.finished_at - self.started_at).total_seconds())


class AuditResult(db.Model):
    """One (rule, command, command_result) row produced by a run."""
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("audit_run.id"), nullable=False, index=True)
    rule = db.Column(db.String(255), nullable=False)
    command = db.Column(db.Text, nullable=False)
    command_result = db.Column(db.Text, nullable=False)