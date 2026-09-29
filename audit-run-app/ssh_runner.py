"""Deterministic SSH execution of a pre-generated audit script.
"""
import io
import os
import re
import time

import paramiko


_SAFE_BENCHMARK = re.compile(r"^[A-Za-z0-9._-]+$")


class AuditConnectionError(Exception):
    pass


def _minio_client():
    """Build a MinIO client from environment settings. The SDK is imported
    lazily so this module still imports where the SDK isn't installed."""
    from minio import Minio

    endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "")
    secret_key = os.getenv("MINIO_SECRET_KEY", "")
    if not access_key or not secret_key:
        raise AuditConnectionError("MINIO_ACCESS_KEY / MINIO_SECRET_KEY not set")
    secure = os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes")
    return Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)


def _load_script_from_minio(benchmark):
    """Fetch the generated script for a benchmark from the MinIO bucket.

    The benchmark name maps directly to the object name '<benchmark>.sh', so it
    is validated against a strict allowlist first - it must not be able to
    reference arbitrary objects or contain path separators."""
    if not benchmark or not _SAFE_BENCHMARK.match(benchmark):
        raise AuditConnectionError(f"Invalid benchmark name: {benchmark!r}")

    bucket = os.getenv("MINIO_BUCKET", "audit-scripts")
    object_name = f"{benchmark}.sh"

    from minio.error import S3Error
    client = _minio_client()
    response = None
    try:
        response = client.get_object(bucket, object_name)
        data = response.read()
    except S3Error as e:
        # NoSuchKey / NoSuchBucket surface here as a missing-script error.
        raise AuditConnectionError(
            f"No generated script found in MinIO for benchmark '{benchmark}' "
            f"(bucket '{bucket}', object '{object_name}'): {e.code}"
        )
    except Exception as e:
        raise AuditConnectionError(f"Failed to fetch script from MinIO: {e}")
    finally:
        if response is not None:
            response.close()
            response.release_conn()

    return data.decode("utf-8", errors="replace")


def _parse_output(raw_stdout, benchmark):
    """Each line is: benchmark_name|rule|command|command_result

    """
    rows = []
    unparsed = []
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            unparsed.append(line)
            continue
        _bench, rule, command, result = parts
        rows.append((rule, command, result))

    if unparsed:
        preview = "\n".join(unparsed[:50])
        rows.append((
            "(unparsed script output)",
            "-",
            f"{len(unparsed)} line(s) did not match 'benchmark|rule|command|result':\n{preview}",
        ))
    return rows


def _load_key_from_string(key_str, passphrase=None):
    """Parse a private key from its raw text, entirely in memory.

    """
    key_classes = [
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
        paramiko.DSSKey,
    ]
    last_error = None
    for key_cls in key_classes:
        try:
            return key_cls.from_private_key(io.StringIO(key_str), password=passphrase)
        except paramiko.PasswordRequiredException:
            raise AuditConnectionError("This private key is encrypted - a passphrase is required.")
        except paramiko.SSHException as e:
            last_error = e
            continue
    raise AuditConnectionError(
        f"Could not parse the private key (tried Ed25519, ECDSA, RSA, DSA). "
        f"Last error: {last_error}"
    )


def run_audit_script(host, port, ssh_user, password, key_content, benchmark,
                     key_passphrase=None, timeout=30):
    """Connects over SSH, runs the benchmark's generated script, returns parsed rows.

    """
    script_content = _load_script_from_minio(benchmark)

    pkey = None
    if key_content:
        pkey = _load_key_from_string(key_content, key_passphrase)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    remote_path = None
    try:
        connect_kwargs = dict(
            hostname=host,
            port=port,
            username=ssh_user,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,      # only use the creds we were handed
            look_for_keys=False,    # don't silently fall back to ~/.ssh keys
        )
        if pkey is not None:
            connect_kwargs["pkey"] = pkey
        elif password:
            connect_kwargs["password"] = password
        else:
            raise AuditConnectionError("Either a password or a private key is required")

        client.connect(**connect_kwargs)

        remote_path = f"/tmp/audit_{benchmark}_{int(time.time())}.sh"
        sftp = client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as remote_file:
                remote_file.write(script_content)
            sftp.chmod(remote_path, 0o700)
        finally:
            sftp.close()

        stdin, stdout, stderr = client.exec_command(f"bash {remote_path}", timeout=timeout * 10)
        raw_stdout = stdout.read().decode(errors="replace")
        raw_stderr = stderr.read().decode(errors="replace")

        rows = _parse_output(raw_stdout, benchmark)
        if not rows and raw_stderr.strip():
            raise AuditConnectionError(f"Script produced no results. stderr: {raw_stderr.strip()[:500]}")
        if not rows:
            raise AuditConnectionError("Script produced no results and no error output.")

        return rows

    except paramiko.AuthenticationException:
        raise AuditConnectionError("Authentication failed - check user/password/key")
    except paramiko.SSHException as e:
        raise AuditConnectionError(f"SSH error: {e}")
    except OSError as e:
        raise AuditConnectionError(f"Connection failed: {e}")
    finally:
        # Best-effort cleanup of the uploaded script, then always close.
        if remote_path:
            try:
                client.exec_command(f"rm -f {remote_path}")
            except Exception:
                pass
        client.close()
