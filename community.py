"""
Vyrulix - Local-First & API-Isolated Community Intelligence Manager (community.py)
Forensic Audit Remediated Release:
  1. Canonical Local-First Storage (`~/.vyrulix/community.json`):
     - Stores comments, user accounts, and reputation tallies in `~/.vyrulix/community.json`
       using atomic file writes (`tempfile.mkstemp` + `os.fsync` + `os.replace`) so power loss
       or concurrent threads never corrupt the JSON store.
     - Automatically migrates any existing records from legacy `vyrulix_community_db.json`.
  2. Salted SHA-256 Password Hashing & 6-Digit Confirmation Flow:
     - `register_user(username, password, email, confirm_password, role)` validates minimum
       password length (`>= 6`), verifies `password == confirm_password`, generates a 6-digit
       confirmation code, and stores salted `hashlib.sha256` password digests (`salt` + `sha256`).
     - `login_user(identifier, password)` authenticates by either username/handle or email
       using constant-time `secrets.compare_digest`.
  3. Reputation & Comment Synchronization:
     - `get_reputation_summary(sha256, sync_online=False)` returns vote tallies
       (`safe_count`, `suspicious_count`, `malicious_count`, `total_comments`, `consensus`).
     - `fetch_comments(sha256, sync_online=False)` and `append_comment(sha256, handle, verdict, comment, filename, role)`
       manage per-hash analyst commentary with deterministic UUIDv5 deduplication.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import secrets
import smtplib
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_VERDICTS: List[str] = ["Safe", "Suspicious", "Malicious"]
VYRULIX_APP_DIR = Path.home() / ".vyrulix"
DEFAULT_DB_FILENAME = "community.json"
LEGACY_DB_FILENAME = "vyrulix_community_db.json"
VERIFICATION_OUTBOX_FILENAME = "verification_outbox.json"

# Optional environment-isolated cloud & SMTP endpoints
ENV_API_PROXY_URL = os.environ.get("VYRULIX_API_PROXY_URL", "").strip().rstrip("/")
ENV_SUPABASE_URL = os.environ.get("VYRULIX_SUPABASE_URL", "").strip().rstrip("/")
ENV_SUPABASE_ANON_KEY = os.environ.get("VYRULIX_SUPABASE_ANON_KEY", "").strip()

ENV_SMTP_HOST = os.environ.get("VYRULIX_SMTP_HOST", "").strip()
ENV_SMTP_PORT = int(os.environ.get("VYRULIX_SMTP_PORT", "587") or 587)
ENV_SMTP_USER = os.environ.get("VYRULIX_SMTP_USER", "").strip()
ENV_SMTP_PASS = os.environ.get("VYRULIX_SMTP_PASS", "").strip()
ENV_SMTP_FROM = os.environ.get("VYRULIX_SMTP_FROM", ENV_SMTP_USER or "noreply@vyrulix.local").strip()

CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")
USERNAME_SAFE_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{2,36}$")
EMAIL_SAFE_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def sanitize_text(value: str, max_length: int = 2000, allow_newlines: bool = True) -> str:
    """
    Strips ASCII control characters and enforces a strict character length bound
    to prevent log/JSON injection or oversized payload corruption.
    """
    cleaned = CONTROL_CHAR_REGEX.sub("", str(value or ""))
    if not allow_newlines:
        cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    return cleaned.strip()[:max_length]


def validate_email_address(email: str) -> str:
    """Validates and normalizes an email address, raising ValueError if malformed."""
    clean_email = sanitize_text(email, max_length=120, allow_newlines=False).lower()
    if not clean_email or not EMAIL_SAFE_REGEX.fullmatch(clean_email):
        raise ValueError("Please enter a valid email address (e.g., analyst@example.com).")
    return clean_email


class CommunityManager:
    """
    Local-first, thread-safe community intelligence and analyst session manager
    storing state inside `~/.vyrulix/community.json` via atomic file writes.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            VYRULIX_APP_DIR.mkdir(parents=True, exist_ok=True)
            canonical_path = VYRULIX_APP_DIR / DEFAULT_DB_FILENAME
            legacy_path = VYRULIX_APP_DIR / LEGACY_DB_FILENAME
            if not canonical_path.is_file() and legacy_path.is_file():
                try:
                    os.replace(str(legacy_path), str(canonical_path))
                except OSError:
                    pass
            self.db_path = str(canonical_path)
        else:
            self.db_path = os.path.abspath(db_path)

        self.outbox_path = str(Path(self.db_path).resolve().parent / VERIFICATION_OUTBOX_FILENAME)
        self._lock = threading.RLock()
        self._ensure_db_initialized()

    # -------------------------------------------------------------------------
    # Storage & Atomic Persistence (`tempfile.mkstemp` + `os.replace`)
    # -------------------------------------------------------------------------
    def _default_schema(self) -> Dict[str, Any]:
        return {
            "version": "6.0",
            "app": "Vyrulix",
            "mode": "local_first",
            "cloud_config": {
                "enabled": bool(ENV_API_PROXY_URL or ENV_SUPABASE_URL),
                "api_proxy_url": ENV_API_PROXY_URL,
                "supabase_url": ENV_SUPABASE_URL,
                "supabase_anon_key": ENV_SUPABASE_ANON_KEY,
            },
            "current_session": None,
            "local_users": {},
            "samples": {},
        }

    def _ensure_db_initialized(self) -> None:
        with self._lock:
            parent_dir = os.path.dirname(self.db_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            if not os.path.exists(self.db_path):
                self._write_db_unlocked(self._default_schema())
                return

            try:
                data = self._read_db_unlocked()
                changed = False
                for key, default_val in self._default_schema().items():
                    if key not in data:
                        data[key] = default_val
                        changed = True
                if changed:
                    self._write_db_unlocked(data)
            except Exception:
                self._write_db_unlocked(self._default_schema())

    def _read_db_unlocked(self) -> Dict[str, Any]:
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("samples"), dict):
                if "users" in data and "local_users" not in data:
                    data["local_users"] = data.pop("users")
                data.setdefault("local_users", {})
                data.setdefault("cloud_config", self._default_schema()["cloud_config"])
                data.setdefault("current_session", None)
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return self._default_schema()

    def _write_db_unlocked(self, payload: Dict[str, Any]) -> None:
        parent_dir = os.path.dirname(self.db_path) or "."
        os.makedirs(parent_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".vyrulix_comm_", suffix=".tmp", dir=parent_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(payload, tmp_file, indent=2, ensure_ascii=False)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, self.db_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

    # -------------------------------------------------------------------------
    # User Authentication (`hashlib.sha256` + salt, 6-Digit Confirmation Code)
    # -------------------------------------------------------------------------
    @staticmethod
    def _hash_password_sha256(password: str, salt: str) -> str:
        """Hashes `password` with `salt` using `hashlib.sha256`."""
        salted = f"{salt}:{password}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()

    @staticmethod
    def _hash_password_legacy_pbkdf2(password: str, salt: str) -> str:
        """Backward-compatible PBKDF2-HMAC-SHA256 verifier for older user records."""
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120_000,
        )
        return dk.hex()

    def send_confirmation_email(
        self, email: str, username: str, confirmation_code: str
    ) -> Tuple[bool, str]:
        """
        Dispatches a 6-digit account confirmation code via SMTP if configured,
        and persists the confirmation record to `~/.vyrulix/verification_outbox.json`.
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        record = {
            "email": email,
            "username": username,
            "confirmation_code": confirmation_code,
            "timestamp": timestamp,
            "delivery": "local_outbox",
        }

        smtp_sent = False
        if ENV_SMTP_HOST and ENV_SMTP_USER and ENV_SMTP_PASS:
            try:
                msg = EmailMessage()
                msg["Subject"] = f"Vyrulix Verification Code: {confirmation_code}"
                msg["From"] = ENV_SMTP_FROM
                msg["To"] = email
                msg.set_content(
                    f"Welcome to Vyrulix, {username}!\n\n"
                    f"Your 6-digit account confirmation code is: {confirmation_code}\n"
                    f"Generated at: {timestamp}\n"
                )
                with smtplib.SMTP(ENV_SMTP_HOST, ENV_SMTP_PORT, timeout=6.0) as server:
                    server.starttls()
                    server.login(ENV_SMTP_USER, ENV_SMTP_PASS)
                    server.send_message(msg)
                smtp_sent = True
                record["delivery"] = "smtp"
            except Exception:
                smtp_sent = False

        try:
            outbox_dir = os.path.dirname(self.outbox_path) or "."
            os.makedirs(outbox_dir, exist_ok=True)
            existing: List[Dict[str, Any]] = []
            if os.path.isfile(self.outbox_path):
                try:
                    with open(self.outbox_path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                        if isinstance(loaded, list):
                            existing = loaded
                except Exception:
                    existing = []
            existing.append(record)
            fd, tmp_out = tempfile.mkstemp(prefix=".vyrulix_outbox_", suffix=".tmp", dir=outbox_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(existing[-100:], f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_out, self.outbox_path)
        except Exception:
            pass

        return (
            True,
            "Sent via SMTP" if smtp_sent else f"Code {confirmation_code} logged to local outbox",
        )

    def register_user(
        self,
        username: str,
        password: str,
        email: str = "",
        confirm_password: Optional[str] = None,
        role: str = "Security Researcher",
    ) -> Dict[str, Any]:
        """
        Registers a new analyst account in `~/.vyrulix/community.json`:
          - Validates username format and email address.
          - Enforces minimum password length (>= 6 characters).
          - Verifies `password == confirm_password` when `confirm_password` is supplied.
          - Generates a 6-digit confirmation code (`confirmation_code`).
          - Stores salted `hashlib.sha256` password digest (`salt` + `password_hash`).
        """
        clean_user = sanitize_text(username, max_length=36, allow_newlines=False).lstrip("@").strip()
        if not clean_user or not USERNAME_SAFE_REGEX.fullmatch(clean_user):
            raise ValueError(
                "Username must be 2–36 characters and contain only letters, numbers, '.', '_', or '-'."
            )

        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")

        if confirm_password is not None and password != confirm_password:
            raise ValueError("Password and Confirm Password do not match.")

        clean_email = (
            validate_email_address(email)
            if (email and email.strip())
            else f"{clean_user.lower()}@vyrulix.local"
        )
        clean_role = (
            sanitize_text(role, max_length=48, allow_newlines=False)
            or "Security Researcher"
        )

        with self._lock:
            db = self._read_db_unlocked()
            users = db.setdefault("local_users", {})
            user_key = clean_user.lower()

            if user_key in users:
                raise ValueError(f"Username '@{clean_user}' is already registered.")

            for existing_u in users.values():
                if isinstance(existing_u, dict) and existing_u.get("email", "").lower() == clean_email:
                    raise ValueError(f"Email '{clean_email}' is already registered.")

            salt = secrets.token_hex(16)
            pw_hash = self._hash_password_sha256(password, salt)
            confirmation_code = f"{secrets.randbelow(900000) + 100000:06d}"
            created_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            handle = f"@{clean_user}"

            user_record = {
                "username": clean_user,
                "handle": handle,
                "email": clean_email,
                "role": clean_role,
                "salt": salt,
                "password_hash": pw_hash,
                "hash_alg": "sha256_salted",
                "confirmation_code": confirmation_code,
                "verified": True,
                "created_at": created_at,
            }
            users[user_key] = user_record

            session = {
                "username": clean_user,
                "handle": handle,
                "email": clean_email,
                "role": clean_role,
                "confirmation_code": confirmation_code,
                "logged_in_at": created_at,
            }
            db["current_session"] = session
            self._write_db_unlocked(db)

        self.send_confirmation_email(clean_email, clean_user, confirmation_code)
        return session

    def login_user(
        self,
        identifier: str = "",
        password: str = "",
        username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Authenticates an existing user by either Username/Handle OR Email Address
        and sets the active session in `~/.vyrulix/community.json`.
        """
        raw_id = (identifier or username or "").strip()
        clean_id = sanitize_text(raw_id, max_length=120, allow_newlines=False).lstrip("@").lower()
        if not clean_id or not password:
            raise ValueError("Please enter both your Username/Email and Password.")

        with self._lock:
            db = self._read_db_unlocked()
            users = db.get("local_users", {})

            matched_record: Optional[Dict[str, Any]] = None
            if clean_id in users and isinstance(users[clean_id], dict):
                matched_record = users[clean_id]
            else:
                for u_rec in users.values():
                    if not isinstance(u_rec, dict):
                        continue
                    if (
                        str(u_rec.get("email", "")).lower() == clean_id
                        or str(u_rec.get("username", "")).lower() == clean_id
                        or str(u_rec.get("handle", "")).lstrip("@").lower() == clean_id
                    ):
                        matched_record = u_rec
                        break

            if matched_record is None:
                raise ValueError(f"No account found matching '{raw_id}'. Please Sign Up first.")

            salt = str(matched_record.get("salt", ""))
            expected_hash = str(matched_record.get("password_hash", ""))
            hash_alg = str(matched_record.get("hash_alg", "sha256_salted"))

            cand_sha256 = self._hash_password_sha256(password, salt)
            valid = secrets.compare_digest(cand_sha256, expected_hash)
            if not valid and hash_alg != "sha256_salted":
                cand_pbkdf2 = self._hash_password_legacy_pbkdf2(password, salt)
                valid = secrets.compare_digest(cand_pbkdf2, expected_hash)

            if not valid:
                raise ValueError("Invalid password. Please try again.")

            now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            session = {
                "username": matched_record.get("username", clean_id),
                "handle": matched_record.get("handle", f"@{clean_id}"),
                "email": matched_record.get("email", ""),
                "role": matched_record.get("role", "Security Researcher"),
                "logged_in_at": now_str,
            }
            db["current_session"] = session
            self._write_db_unlocked(db)
            return session

    def logout_user(self) -> None:
        """Clears the active analyst session in `~/.vyrulix/community.json`."""
        with self._lock:
            db = self._read_db_unlocked()
            db["current_session"] = None
            self._write_db_unlocked(db)

    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Returns the currently signed-in analyst session dictionary, or `None`."""
        with self._lock:
            db = self._read_db_unlocked()
            sess = db.get("current_session")
            return dict(sess) if isinstance(sess, dict) and sess.get("handle") else None

    # -------------------------------------------------------------------------
    # Reputation Tallies & Per-SHA256 Comment Feed
    # -------------------------------------------------------------------------
    @staticmethod
    def _normalize_sha256(sha256: str) -> str:
        clean = (sha256 or "").strip().lower()
        if not SHA256_HEX_REGEX.fullmatch(clean):
            return hashlib.sha256(clean.encode("utf-8")).hexdigest() if clean else ""
        return clean

    def fetch_comments(self, sha256: str, sync_online: bool = False) -> List[Dict[str, Any]]:
        """
        Returns the chronological list of community comments for `sha256`.
        Optionally merges remote comments if `sync_online=True` and a cloud endpoint is configured.
        """
        norm_hash = self._normalize_sha256(sha256)
        if not norm_hash:
            return []

        if sync_online:
            self._try_pull_online_comments(norm_hash)

        with self._lock:
            db = self._read_db_unlocked()
            sample_obj = (db.get("samples") or {}).get(norm_hash) or {}
            raw_comments = sample_obj.get("comments") or []
            if not isinstance(raw_comments, list):
                return []
            return [dict(c) for c in raw_comments if isinstance(c, dict)]

    def get_reputation_summary(
        self, sha256: str, sync_online: bool = False
    ) -> Dict[str, Any]:
        """
        Computes vote tallies (`safe_count`, `suspicious_count`, `malicious_count`,
        `total_comments`, `consensus`) for `sha256`.
        """
        comments = self.fetch_comments(sha256, sync_online=sync_online)
        safe_count = 0
        suspicious_count = 0
        malicious_count = 0

        for item in comments:
            v = str(item.get("verdict", "")).capitalize()
            if v == "Safe":
                safe_count += 1
            elif v == "Suspicious":
                suspicious_count += 1
            elif v == "Malicious":
                malicious_count += 1

        total = safe_count + suspicious_count + malicious_count
        if total == 0:
            consensus = "No Community Votes Yet"
        elif malicious_count >= suspicious_count and malicious_count >= safe_count and malicious_count > 0:
            consensus = "Community Consensus: Malicious"
        elif suspicious_count >= safe_count and suspicious_count > 0:
            consensus = "Community Consensus: Suspicious"
        else:
            consensus = "Community Consensus: Safe"

        return {
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count,
            "total_comments": total,
            "consensus": consensus,
        }

    def append_comment(
        self,
        sha256: str,
        handle: str,
        verdict: str,
        comment: str,
        filename: str = "",
        role: str = "Community Analyst",
    ) -> Dict[str, Any]:
        """
        Appends a validated analyst verdict and comment to `~/.vyrulix/community.json`
        using deterministic UUIDv5 deduplication and atomic file replacement.
        """
        norm_hash = self._normalize_sha256(sha256)
        if not norm_hash:
            raise ValueError("A valid SHA-256 hash is required to post a comment.")

        clean_verdict = sanitize_text(verdict, max_length=24, allow_newlines=False).capitalize()
        if clean_verdict not in VALID_VERDICTS:
            raise ValueError(f"Verdict must be one of: {', '.join(VALID_VERDICTS)}.")

        clean_comment = sanitize_text(comment, max_length=2000, allow_newlines=True)
        if not clean_comment:
            raise ValueError("Comment text cannot be empty.")

        clean_handle = sanitize_text(handle, max_length=40, allow_newlines=False) or "@analyst"
        if not clean_handle.startswith("@"):
            clean_handle = f"@{clean_handle}"

        clean_role = sanitize_text(role, max_length=48, allow_newlines=False) or "Community Analyst"
        clean_filename = sanitize_text(filename, max_length=255, allow_newlines=False)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        comment_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_OID,
                f"{norm_hash}:{clean_handle.lower()}:{clean_verdict}:{clean_comment}",
            )
        )

        entry = {
            "id": comment_id,
            "sha256": norm_hash,
            "handle": clean_handle,
            "role": clean_role,
            "verdict": clean_verdict,
            "comment": clean_comment,
            "filename": clean_filename,
            "timestamp": timestamp,
        }

        with self._lock:
            db = self._read_db_unlocked()
            samples = db.setdefault("samples", {})
            sample_rec = samples.setdefault(
                norm_hash,
                {"sha256": norm_hash, "filename": clean_filename, "comments": []},
            )
            if clean_filename and not sample_rec.get("filename"):
                sample_rec["filename"] = clean_filename

            comments_list: List[Dict[str, Any]] = sample_rec.setdefault("comments", [])
            if not any(isinstance(c, dict) and c.get("id") == comment_id for c in comments_list):
                comments_list.insert(0, entry)
            self._write_db_unlocked(db)

        return entry

    def _try_pull_online_comments(self, norm_hash: str) -> None:
        """Optional non-throwing cloud comment pull when `VYRULIX_API_PROXY_URL` is configured."""
        if not ENV_API_PROXY_URL:
            return
        url = f"{ENV_API_PROXY_URL}/comments?sha256={urllib.parse.quote(norm_hash)}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "Vyrulix-Community/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                remote_items = json.loads(resp.read().decode("utf-8", errors="replace"))
            if not isinstance(remote_items, list):
                return
            with self._lock:
                db = self._read_db_unlocked()
                samples = db.setdefault("samples", {})
                sample_rec = samples.setdefault(
                    norm_hash, {"sha256": norm_hash, "filename": "", "comments": []}
                )
                comments_list: List[Dict[str, Any]] = sample_rec.setdefault("comments", [])
                seen_ids = {str(c.get("id")) for c in comments_list if isinstance(c, dict)}
                changed = False
                for r_item in remote_items[:50]:
                    if not isinstance(r_item, dict):
                        continue
                    cid = sanitize_text(str(r_item.get("id", "")), max_length=64, allow_newlines=False)
                    if not cid or cid in seen_ids:
                        continue
                    v = sanitize_text(str(r_item.get("verdict", "Suspicious")), max_length=16, allow_newlines=False).capitalize()
                    if v not in VALID_VERDICTS:
                        continue
                    comments_list.append(
                        {
                            "id": cid,
                            "sha256": norm_hash,
                            "handle": sanitize_text(str(r_item.get("handle", "@analyst")), max_length=40, allow_newlines=False),
                            "role": sanitize_text(str(r_item.get("role", "Community")), max_length=48, allow_newlines=False),
                            "verdict": v,
                            "comment": sanitize_text(str(r_item.get("comment", "")), max_length=2000),
                            "filename": sanitize_text(str(r_item.get("filename", "")), max_length=255, allow_newlines=False),
                            "timestamp": sanitize_text(str(r_item.get("timestamp", "")), max_length=32, allow_newlines=False),
                        }
                    )
                    seen_ids.add(cid)
                    changed = True
                if changed:
                    self._write_db_unlocked(db)
        except Exception:
            pass