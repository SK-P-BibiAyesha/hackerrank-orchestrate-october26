import csv
import json
import re
import shutil
import sqlite3
import subprocess
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
_rapid_ocr = None

STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)

ACTION_STEPS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": (
        "REPORT_EXPOSED_PII",
        "ANONYMIZE_RECORD",
        "VERIFY_RECORD_ANONYMIZED",
    ),
}

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


@dataclass(frozen=True)
class Observation:
    evidence_id: str
    captured_at: datetime
    system_id: str
    resource_id: str
    category: str
    record: dict
    state: str = "PRESENT"
    source_id: str = ""


def read_csv(path):
    if not path.is_file():
        raise FileNotFoundError(f"Required input file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def parse_time(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize(value):
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def normalize_phone(value):
    return re.sub(r"\D", "", str(value or ""))


def build_identity_index(identities, audit_log):
    by_email = {}
    fields_by_user = {}

    def add(user_id, field, value):
        value = str(value or "").strip()
        if not user_id or not value:
            return
        fields_by_user.setdefault(user_id, {}).setdefault(field.casefold(), set()).add(value)
        if field.casefold() == "email" and "@" in value:
            by_email.setdefault(normalize(value), set()).add(user_id)

    for row in identities:
        user_id = row.get("user_id", "").strip()
        for field in ("name", "email", "phone", "email_hash"):
            add(user_id, field, row.get(field))
        add(user_id, "user_id", user_id)

    for row in audit_log:
        user_id = row.get("user_id", "").strip()
        field = row.get("field_name", "").strip()
        if field:
            add(user_id, field, row.get("old_value"))
            add(user_id, field, row.get("new_value"))

    return by_email, fields_by_user


def request_authorizes_deletion(text):
    text = normalize(text)
    if not text:
        return False

    explicit_negation = re.compile(
        r"\b(?:do\s+not|don't|not|without|no)\s+"
        r"(?:(?:ask(?:ing)?|request(?:ing)?|want(?:ing)?)\s+(?:us\s+)?to\s+)?"
        r"(?:want\s+)?(?:delete|deleting|deletion|erase|erasure|remove|"
        r"borrar|eliminar|suprimir|supprimer|effacer|löschen)\b",
        re.IGNORECASE,
    )
    if explicit_negation.search(text):
        return False

    deletion_intent = re.compile(
        r"\b(?:delet(?:e|ing|ed|ion)|eras(?:e|ing|ure)|remov(?:e|ing|al)|wipe|"
        r"close\s+(?:(?:my|the|this|that)\s+)?account|"
        r"elimin(?:ar|ación|acion)|borr(?:ar|ado)|suprim(?:ir|e)|"
        r"solicito\s+(?:la\s+)?(?:eliminaci[oó]n|supresi[oó]n)|"
        r"supprimer|suppression|effacer|effacement|"
        r"r[eé]silier\s+(?:mon\s+)?compte|"
        r"l[oö]schen|entfern(?:en|ung)|konto\s+schlie(?:ß|ss)en|"
        r"cancellare|eliminare|cancellazione|"
        r"excluir|apagar|elimina(?:ção|cao)|"
        r"verwijder(?:en|ing)|wissen"
        r")\b",
        re.IGNORECASE,
    )
    if deletion_intent.search(text) or re.search(r"消去|削除|抹消", text):
        return True

    deletion_follow_up = re.compile(
        r"(?:deletion|erasure|removal)\s+request|"
        r"my\s+request\s+(?:failed|was\s+not\s+completed)|"
        r"request\s+failed|"
        r"account\s+(?:still\s+)?(?:exists|existed|appears|showing)|"
        r"email\s+is\s+already\s+registered|"
        r"(?:already|previously)\s+(?:deleted|removed|erased)",
        re.IGNORECASE,
    )
    if deletion_follow_up.search(text):
        return True

    return False


def build_evidence_index(manifest):
    index = {}
    data_root = DATA.resolve()
    for row in manifest:
        file_id = row.get("file_id", "").strip()
        relative_path = row.get("file_path", "").strip()
        if not file_id or not relative_path:
            raise ValueError("Evidence manifest contains an empty file_id or file_path")
        path = (DATA / relative_path).resolve()
        if not path.is_relative_to(data_root):
            raise ValueError(f"Evidence path escapes dataset: {relative_path}")
        captured_at = parse_time(row.get("captured_at", ""))
        if captured_at is None:
            raise ValueError(f"Evidence {file_id} has no valid capture timestamp")
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file listed in manifest is missing: {path}")
        index[file_id] = {
            "path": path,
            "captured_at": captured_at,
            "origin": row.get("origin", ""),
        }
    return index


def load_policy_rules(rows):
    rules = {}
    for row in rows:
        category = row.get("data_category", "").strip().upper()
        action = row.get("required_action", "").strip().upper()
        if not category or action not in {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}:
            raise ValueError(f"Invalid deletion policy row: {row!r}")
        if category in rules:
            raise ValueError(f"Duplicate policy category: {category}")
        rules[category] = action
    if len(rules) != 15:
        raise ValueError(f"Expected 15 policy categories; found {len(rules)}")
    return rules


def category_for(system_id, collection, table, record):
    label = " ".join(
        (system_id, collection, table, *record.keys())
    ).casefold()
    if "data_flow" in label or "connector" in label:
        return "DATA_FLOW"
    if "tombstone" in label:
        return "ACCOUNT_TOMBSTONE"
    if "backup" in label or "archive" in label:
        return "BACKUP_ARCHIVE"
    if "security" in label or "audit_record" in label or "legal_hold" in label:
        return "SECURITY_AUDIT_LOG" if "legal" not in label else "LEGAL_HOLD_RECORD"
    if "analytics" in label or "reporting" in label:
        return "ANALYTICS_PROFILE"
    if "telemetry" in label or "event_stream" in label:
        return "PRODUCT_TELEMETRY"
    if "marketing" in label:
        return "MARKETING_PROFILE"
    if "delivery" in label or "email_log" in label:
        return "EMAIL_DELIVERY_LOG"
    if "support_message" in label or "support_case" in label or "ticket" in label:
        return "SUPPORT_MESSAGE"
    if "export" in label or "object_store" in label or "object_storage" in label:
        return "USER_EXPORT"
    if "search" in label or "index" in label:
        return "SEARCH_INDEX_ENTRY"
    if "support" in label or "attachment" in label or "document" in label:
        return "SUPPORT_ATTACHMENT"
    if "cache" in label:
        return "CACHE_ENTRY"
    if "secondary" in label or "identifier" in label:
        return "SECONDARY_IDENTIFIER"
    if "profile" in label or "account" in label or "customer" in label:
        return "USER_PROFILE"
    return ""


def state_for_record(record):
    for key in ("privacy_state", "record_state", "identifier_status", "treatment"):
        value = normalize(record.get(key)).upper().replace(" ", "_")
        if value in {
            "ABSENT",
            "NOT_FOUND",
            "REDACTED",
            "ANONYMIZED",
            "IDENTIFIABLE",
            "EXPOSED",
            "ACTIVE",
            "DISABLED",
            "BLOCKED",
        }:
            return value
    status_code = record.get("status_code")
    if status_code is not None:
        try:
            if int(status_code) == 404:
                return "ABSENT"
        except (TypeError, ValueError):
            pass
    if record.get("profile", object()) is None:
        return "ABSENT"
    if record.get("restore_allowed") is False or normalize(record.get("restore_allowed")) in {"false", "0", "no"}:
        return "BLOCKED"
    if record.get("enabled") is False or normalize(record.get("enabled")) in {"false", "0", "no"}:
        return "DISABLED"
    return "PRESENT"


def infer_system(value):
    value = str(value or "").strip()
    aliases = {
        "backup_restore_entries": "backup_service",
"identity_service": "identity_service",
        "customer_profiles": "account_service",
        "customer_profiles_primary": "account_service",
        "customer_profiles_failover_replica": "account_service",
        "search_documents_primary": "search_service",
        "customer_search_documents": "search_service",
        "customer_analytics_reports": "analytics_platform",
        "customer_export_jobs": "export_service",
        "support_attachments": "support_platform",
        "support_messages": "support_platform",
        "account_tombstones": "account_service",
        "security_audit_records": "security_service",
        "legal_hold_records": "legal_service",
        "customer_backups": "backup_service",
        "support_replica": "support_platform",
        "identity_service": "account_service",
    }
    if value in aliases:
        return aliases[value]
    if value.endswith("_primary") or value.endswith("_failover_replica"):
        value = re.sub(r"_(?:primary|failover_replica)$", "", value)
    return value


def json_observations(evidence_id, item):
    path = item["path"]
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    observations = []

    def add_records(records, system, collection, captured_at):
        if not isinstance(records, list):
            return
        timestamp = parse_time(captured_at) or item["captured_at"]
        for record in records:
            if not isinstance(record, dict):
                continue
            resource_id = str(record.get("resource_id") or record.get("id") or "").strip()
            if not resource_id:
                continue
            system_id = infer_system(system or collection)
            category = category_for(system_id, collection, "", record)
            if category:
                observations.append(
                    Observation(
                        evidence_id,
                        timestamp,
                        system_id,
                        resource_id,
                        category,
                        record,
                        state_for_record(record),
                    )
                )

    known_systems = {
        "account_service",
        "analytics_platform",
        "backup_service",
        "export_service",
        "integration_service",
        "search_service",
        "security_service",
        "support_platform",
        "identity_service",
        "notification_service",
        "cache_service",
        "email_delivery_service",
        "marketing_platform",
        "legal_service",
    }

    def walk(value, system="", collection="", captured_at=None):
        if isinstance(value, list):
            for child in value:
                walk(child, system, collection, captured_at)
            return
        if not isinstance(value, dict):
            return

        local_system = (
            value.get("data_store")
            or value.get("system_id")
            or value.get("service")
            or system
        )
        local_collection = value.get("collection") or value.get("table") or collection
        local_timestamp = (
            value.get("captured_at")
            or value.get("observed_at")
            or value.get("exported_at")
            or captured_at
        )
        if value.get("resource_id") or value.get("id"):
            add_records([value], local_system, local_collection, local_timestamp)
            return

        for key, child in value.items():
            child_system = key if key in known_systems else local_system
            child_collection = key if isinstance(child, list) else local_collection
            if key == "records" and isinstance(child, list):
                add_records(child, local_system, local_collection, local_timestamp)
            else:
                walk(child, child_system, child_collection, local_timestamp)

    walk(data)
    return observations


def sql_observations(evidence_id, item, snapshot_inventory):
    observations = []
    snapshot_inventory[evidence_id] = {}
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(item["path"].read_text(encoding="utf-8-sig"))
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        for (table,) in tables:
            columns = [
                column[1]
                for column in connection.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            ]
            system_id = infer_system(table)
            category = category_for(system_id, "", table, {})
            if category:
                snapshot_inventory[evidence_id].setdefault(
                    (system_id, category, table), set()
                )
            for values in connection.execute(f'SELECT * FROM "{table}"'):
                record = dict(zip(columns, values))
                resource_id = str(record.get("resource_id") or record.get("id") or "").strip()
                if not resource_id:
                    continue
                category = category_for(system_id, "", table, record)
                if category:
                    snapshot_inventory[evidence_id].setdefault(
                        (system_id, category, table), set()
                    ).add(resource_id)
                    observations.append(
                        Observation(
                            evidence_id,
                            item["captured_at"],
                            system_id,
                            resource_id,
                            category,
                            record,
                            state_for_record(record),
                            table,
                        )
                    )
    finally:
        connection.close()
    return observations


def delimited_text_observations(evidence_id, item):
    observations = []
    text = item["path"].read_text(encoding="utf-8-sig", errors="replace")
    for line in text.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 6:
            continue
        timestamp_match = re.search(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?",
            parts[0],
        )
        if not timestamp_match:
            continue
        timestamp = parse_time(timestamp_match.group(0)) or item["captured_at"]
        system_id, resource_id, category, state = parts[1:5]
        if not resource_id or not category:
            continue
        state = state.upper().replace(" ", "_")
        record = {
            "resource_id": resource_id,
            "subject_identifier": parts[5],
            "privacy_state": state,
        }
        observations.append(
            Observation(
                evidence_id,
                timestamp,
                infer_system(system_id),
                resource_id,
                category.upper(),
                record,
                state,
            )
        )
    return observations


def resource_category(system_id, resource_id, events=""):
    events = events.casefold()

    if (
        "support" in system_id.casefold()
        and any(word in events for word in ("message", "ticket", "case"))
    ):
        return "SUPPORT_MESSAGE"

    if "attachment" in events:
        return "SUPPORT_ATTACHMENT"
    prefix = resource_id.split("_", 1)[0].casefold()
    categories = {
        "account": "USER_PROFILE",
        "search": "SEARCH_INDEX_ENTRY",
        "support": "SUPPORT_ATTACHMENT",
        "export": "USER_EXPORT",
        "analytics": "ANALYTICS_PROFILE",
        "cache": "CACHE_ENTRY",
        "backup": "BACKUP_ARCHIVE",
        "audit": "SECURITY_AUDIT_LOG",
        "data": "DATA_FLOW",
        "email": "EMAIL_DELIVERY_LOG",
        "marketing": "MARKETING_PROFILE",
        "tombstone": "ACCOUNT_TOMBSTONE",
    }
    if prefix == "data" and resource_id.casefold().startswith("data_flow_"):
        return "DATA_FLOW"
    if prefix == "audit" and resource_id.casefold().startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    return categories.get(prefix) or category_for(system_id, "", "", {"resource_id": resource_id})


def log_observations(evidence_id, item):
    text = item["path"].read_text(encoding="utf-8-sig", errors="replace")
    groups = {}
    for index, line in enumerate(text.splitlines()):
        trace_match = re.search(r"\b(?:trace_id|requestId)=([A-Za-z0-9_-]+)", line)
        trace_id = trace_match.group(1) if trace_match else f"line_{index}"
        groups.setdefault(trace_id, []).append(line)

    observations = []
    identity_keys = {
        "lookup_key",
        "subject_key",
        "correlation_key",
        "customer_email",
        "email",
        "user_id",
        "subject_ref",
        "customer_reference",
        "subject_reference",
        "owner_email",
    }
    for lines in groups.values():
        trace_text = "\n".join(lines)
        event_text = " ".join(re.findall(r"\bevent=([A-Za-z_]+)", trace_text, re.I))
        identities = {}
        for key, raw_value in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s]+)",
            trace_text,
        ):
            if key.casefold() in identity_keys:
                value = raw_value.strip("\"'")
                if value:
                    identities[key] = value
        if not identities:
            continue

        status = ""
        for line in lines:
            if re.search(r"\bmatched_value=|\bdirect_identifier\b", line, re.I):
                status = "IDENTIFIABLE"
            elif re.search(r"\beligible=true\b.*\bdeletion_block=false\b", line, re.I):
                status = "ACTIVE"
            elif re.search(r"\benabled=false\b", line, re.I):
                status = "DISABLED"
            elif re.search(r"\brestore_allowed=false\b", line, re.I):
                status = "BLOCKED"
            elif re.search(r"\benabled=true\b|restore_allowed=true", line, re.I):
                status = "ACTIVE"
            elif re.search(r"\brows=0\b|http_status=404", line, re.I):
                status = "ABSENT"
            elif re.search(r"\brows=[1-9]\d*\b|last_delivery_status=(?:active|success)", line, re.I):
                status = "PRESENT"
            elif re.search(r"\bresult=hit\b", line, re.I):
                status = "PRESENT"
            elif re.search(
                r"event=[A-Za-z_]*(?:completed|complete|read|query|heartbeat|result)\b",
                line,
                re.I,
            ) and re.search(
                r"\b(?:email|customer_email|requester_email|user_id|display_name)="
                r"(?![\"']?null\b)[\"']?[^ \t\"']+",
                line,
                re.I,
            ):
                status = "PRESENT"
        if not status:
            continue

        resources = {}
        for line in lines:
            resource_match = re.search(
                r"\bresource_id=([\"']?)([A-Za-z][A-Za-z0-9_-]*_[A-Za-z0-9_-]+)\1",
                line,
            )
            if not resource_match:
                continue
            resource_id = resource_match.group(2)
            service_match = re.search(r"\bservice=([A-Za-z0-9_-]+)", line)
            system_id = service_match.group(1) if service_match else resource_id.split("_", 1)[0]
            resources[resource_id] = infer_system(system_id)
        for resource_id, system_id in resources.items():
            category = resource_category(system_id, resource_id, event_text)
            record = dict(identities)
            record.update({"resource_id": resource_id, "privacy_state": status})
            observations.append(
                Observation(
                    evidence_id,
                    item["captured_at"],
                    system_id,
                    resource_id,
                    category,
                    record,
                    status,
                )
            )
    return observations


def extract_document_text(path):
    if path.suffix.casefold() != ".pdf":
        return ""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError(
            "PDF evidence is present but pypdf is not installed. "
            "Install code/requirements.txt to audit document evidence."
        ) from exc
    reader = PdfReader(str(path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def extract_image_text(path):
    executable = shutil.which("tesseract")
    if executable:
        result = subprocess.run(
            [executable, str(path), "stdout", "--psm", "6"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result.stdout

    try:
        from rapidocr import RapidOCR
    except ImportError:
        warnings.warn(
            f"Image evidence {path.name} was not OCR-processed; install "
            "code/requirements.txt or Tesseract to include screenshots.",
            RuntimeWarning,
        )
        return ""

    global _rapid_ocr
    if _rapid_ocr is None:
        _rapid_ocr = RapidOCR()
    result = _rapid_ocr(str(path))
    return "\n".join(result.txts or [])


def scalar_values(value):
    if isinstance(value, dict):
        for child in value.values():
            yield from scalar_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_values(child)
    elif value is not None and isinstance(value, (str, int, float)):
        yield str(value)


def matched_identifiers(record, identity_fields):
    expected = set()
    expected_phones = set()
    for field, values in identity_fields.items():
        for value in values:
            normalized = normalize(value)
            if normalized:
                expected.add(normalized)
            if field == "phone":
                normalized_phone = normalize_phone(value)
                if normalized_phone:
                    expected_phones.add(normalized_phone)
    for value in scalar_values(record):
        if normalize(value) in expected or normalize_phone(value) in expected_phones:
            return True
    return False


def has_identifying_fields(record, identity_fields, permit_stable_reference=False):
    if normalize(record.get("privacy_state")) in {"identifiable", "exposed"}:
        return True
    for key, value in record.items():
        key_normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
        is_direct = key_normalized in {
            "name",
            "fullname",
            "displayname",
            "email",
            "phone",
            "emailhash",
        } or key_normalized.endswith(("email", "phone", "emailhash"))
        is_stable = key_normalized in {
            "userid",
            "customerreference",
            "subjectreference",
            "owneruserid",
        }
        if (
            key_normalized == "correlationkey"
            and normalize(value) in {
                normalize(candidate)
                for candidate in identity_fields.get("email_hash", set())
            }
        ):
            return True
        if value in (None, ""):
            continue
        if is_direct and normalize(value) in {
            normalize(v) for values in identity_fields.values() for v in values
        }:
            return True
        if is_stable and not permit_stable_reference:
            if normalize(value) in {
                normalize(v) for values in identity_fields.values() for v in values
            }:
                return True
    return False


def record_is_enabled(record):
    if normalize(record.get("privacy_state")) in {"active", "restorable", "enabled"}:
        return True
    for key, value in record.items():
        if key.casefold() in {"enabled", "is_enabled", "active", "restore_allowed"}:
            if value is True or normalize(value) in {"true", "1", "yes", "enabled", "active"}:
                return True
    return False


def build_observations(evidence_index):
    observations = []
    text_by_evidence = {}
    snapshot_inventory = {}
    for evidence_id, item in evidence_index.items():
        suffix = item["path"].suffix.casefold()
        if suffix == ".json":
            observations.extend(json_observations(evidence_id, item))
        elif suffix == ".sql":
            observations.extend(
                sql_observations(evidence_id, item, snapshot_inventory)
            )
        elif suffix in {".log", ".txt"}:
            text_by_evidence[evidence_id] = item["path"].read_text(
                encoding="utf-8-sig", errors="replace"
            )
            observations.extend(delimited_text_observations(evidence_id, item))
            observations.extend(log_observations(evidence_id, item))
        elif suffix == ".pdf":
            text_by_evidence[evidence_id] = extract_document_text(item["path"])
        elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
            text_by_evidence[evidence_id] = extract_image_text(item["path"])
    return observations, text_by_evidence, snapshot_inventory


def activity_resource_links(activity, by_email, identity_fields):
    links = {}
    for row in activity:
        if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        details = row.get("details", "")
        user_id = ""
        for email in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", details):
            matches = by_email.get(normalize(email), set())
            if len(matches) == 1:
                user_id = next(iter(matches))
                break
        if not user_id:
            for candidate in re.findall(r"\buser_[A-Za-z0-9_-]+\b", details):
                if candidate in identity_fields:
                    user_id = candidate
                    break
        if user_id:
            resource_id = row.get("resource_id", "").strip()
            if resource_id:
                links.setdefault(user_id, set()).add(resource_id)
    return links


def activity_resources_by_request(activity, requests):
    deletion_operations = {
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
    }
    request_times = []
    for request in requests:
        if not request_authorizes_deletion(request.get("request_text", "")):
            continue
        reported_at = parse_time(request.get("reported_at", ""))
        if reported_at is not None:
            request_times.append((request["case_id"], reported_at))

    links = {}
    for row in activity:
        if row.get("event_type", "").upper() not in deletion_operations:
            continue
        resource_id = row.get("resource_id", "").strip()
        activity_at = parse_time(row.get("event_time", ""))
        if not resource_id or activity_at is None:
            continue

        distances = []
        for case_id, candidate_reported_at in request_times:
            distances.append(
                (
                    abs((activity_at - candidate_reported_at).total_seconds()),
                    case_id,
                )
            )
        if not distances:
            continue
        distances.sort()
        nearest_distance, nearest_case_id = distances[0]
        if nearest_distance > timedelta(minutes=15).total_seconds():
            continue
        if len(distances) > 1 and distances[0][0] == distances[1][0]:
            continue
        links.setdefault(nearest_case_id, set()).add(
            (
                infer_system(row.get("target_system", "")),
                resource_id,
            )
        )
    return links


def step_sort_key(step):
    phase = step["phase"]
    order = {
        "FINDING": FINDING_ORDER,
        "REMEDIATION": REMEDIATION_ORDER,
        "VERIFICATION": VERIFICATION_ORDER,
    }[phase]
    return (
        ("FINDING", "REMEDIATION", "VERIFICATION").index(phase),
        order[step["operation"]],
        step["system_id"],
        step["resource_id"],
        step["evidence_id"],
    )


def make_step(phase, system, resource, operation, state, evidence_id):
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def audit_request(
    request,
    by_email,
    identity_fields,
    rules,
    evidence_index,
    observations,
    text_by_evidence,
    resource_links,
    activity_resources=None,
    snapshot_inventory=None,
):
    if not request_authorizes_deletion(request.get("request_text", "")):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps": []}

    matches = by_email.get(normalize(request.get("email")), set())
    if len(matches) != 1:
        return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE", "steps": []}
    user_id = next(iter(matches))
    fields = identity_fields.get(user_id, {})
    audit_at = parse_time(request.get("audit_at", ""))
    if audit_at is None:
        raise ValueError(f"Request {request['case_id']} has no valid audit_at")

    temporal_resources = (activity_resources or {}).get(request["case_id"], set())
    request_resources = set(resource_links.get(user_id, set()))
    request_resources.update(resource_id for _, resource_id in temporal_resources)

    user_observations = []
    for observation in observations:
        if observation.captured_at > audit_at:
            continue
        evidence_time = evidence_index[observation.evidence_id]["captured_at"]
        if evidence_time > audit_at:
            continue
        linked = observation.resource_id in request_resources
        if linked or matched_identifiers(observation.record, fields):
            user_observations.append(observation)

    if snapshot_inventory:
        requested_at = parse_time(request.get("requested_at", ""))
        reported_at = parse_time(request.get("reported_at", ""))
        minimum_snapshot_time = max(
            (value for value in (requested_at, reported_at) if value is not None),
            default=None,
        )
        for evidence_id, categories in snapshot_inventory.items():
            captured_at = evidence_index[evidence_id]["captured_at"]
            if captured_at > audit_at or (
                minimum_snapshot_time is not None
                and captured_at < minimum_snapshot_time
            ):
                continue
            for system_id, resource_id in temporal_resources:
                category = resource_category(system_id, resource_id)
                if not category:
                    continue
                for (
                    snapshot_system,
                    snapshot_category,
                    source_id,
                ), resources in categories.items():
                    if (
                        snapshot_system != system_id
                        or snapshot_category != category
                        or resource_id in resources
                    ):
                        continue
                    user_observations.append(
                        Observation(
                            evidence_id,
                            captured_at,
                            system_id,
                            resource_id,
                            category,
                            {"resource_id": resource_id},
                            "ABSENT",
                            source_id,
                        )
                    )

    evidence_states = []
    known_resources = {item.resource_id for item in user_observations}
    for evidence_id, text in text_by_evidence.items():
        evidence = evidence_index[evidence_id]
        if evidence["captured_at"] > audit_at:
            continue
        lines = text.splitlines()
        identity_lines = []
        for index, line in enumerate(lines):
            has_identity = any(
                normalize(value) in normalize(line)
                for values in fields.values()
                for value in values
                if len(normalize(value)) >= 4
            )
            if has_identity:
                identity_lines.append(index)
        traces = set()
        for index in identity_lines:
            trace = re.search(r"\btrace_id=([A-Za-z0-9_-]+)", lines[index])
            if trace:
                traces.add(trace.group(1))
        related_lines = set(identity_lines)
        if traces:
            for index, line in enumerate(lines):
                trace = re.search(r"\btrace_id=([A-Za-z0-9_-]+)", line)
                if trace and trace.group(1) in traces:
                    related_lines.add(index)
        for line_index in sorted(related_lines):
            line = lines[line_index]
            resource_match = re.search(
                r"\bresource_id=[\"']?"
                r"((?:account|search|support|export|analytics|cache|backup|"
                r"audit_record|data_flow|email_delivery|marketing)_[A-Za-z0-9_-]+)",
                line,
            )
            if not resource_match:
                continue
            resource = resource_match.group(1)
            system_match = re.search(r"\bservice=([A-Za-z0-9_-]+)", line)
            system = system_match.group(1) if system_match else resource.split("_", 1)[0]
            state = ""
            if re.search(
                r"\brows=0\b|http_status=404|enabled=false|restore_allowed=false|"
                r"event=\w+_not_found",
                line,
                re.I,
            ):
                state = "ABSENT"
            elif re.search(
                r"\brows=[1-9]\d*\b|enabled=true|restore_allowed=true|"
                r"event=\w+_found",
                line,
                re.I,
            ):
                state = "PRESENT"
            if state:
                evidence_states.append((evidence_id, system, resource, state))

    latest = {}
    for observation in user_observations:
        key = (
            observation.system_id,
            observation.resource_id,
            observation.category,
            observation.source_id,
        )
        existing = latest.get(key)
        if existing is None or observation.captured_at >= existing.captured_at:
            latest[key] = observation

    findings = []
    remediations = []
    verifications = []
    remediated = set()

    for observation in latest.values():
        action = rules.get(observation.category)
        record = observation.record
        observed_state = normalize(observation.state).upper()
        operation = ""
        remediation = ""
        verification = ""

        if observed_state in {"NOT_FOUND", "ABSENT"}:
            if observation.category == "DATA_FLOW":
                verifications.append(
                    make_step(
                        "VERIFICATION",
                        observation.system_id,
                        observation.resource_id,
                        "VERIFY_DATA_FLOW_DISABLED",
                        "DISABLED",
                        observation.evidence_id,
                    )
                )
                continue
            if observation.category == "BACKUP_ARCHIVE":
                verifications.append(
                    make_step(
                        "VERIFICATION",
                        observation.system_id,
                        observation.resource_id,
                        "VERIFY_RESTORE_BLOCKED",
                        "BLOCKED",
                        observation.evidence_id,
                    )
                )
                continue
            evidence_states.append(
                (
                    observation.evidence_id,
                    observation.system_id,
                    observation.resource_id,
                    "ABSENT",
                )
            )
            continue
        if observation.category == "DATA_FLOW":
            if record_is_enabled(record):
                operation = "REPORT_ACTIVE_DATA_FLOW"
                remediation = "DISABLE_DATA_FLOW"
                verification = "VERIFY_DATA_FLOW_DISABLED"
            else:
                verification = "VERIFY_DATA_FLOW_DISABLED"
            if observed_state == "DISABLED":
                operation = ""
                remediation = ""
        elif action is None:
            continue
        elif observation.category == "BACKUP_ARCHIVE":
            if observed_state in {"BLOCKED", "DISABLED"}:
                verification = "VERIFY_RESTORE_BLOCKED"
            elif record_is_enabled(record) or observed_state in {"ACTIVE", "RESTORABLE"}:
                operation = "REPORT_RESTORE_RISK"
                remediation = "BLOCK_RESTORE"
                verification = "VERIFY_RESTORE_BLOCKED"
            elif action == "RETAIN":
                restore_is_blocked = any(
                    str(key).casefold() == "restore_allowed"
                    and normalize(value) in {"false", "0", "no"}
                    for key, value in record.items()
                ) or observed_state == "BLOCKED"
                if restore_is_blocked:
                    verification = "VERIFY_RESTORE_BLOCKED"
                else:
                    verification = "VERIFY_RECORD_PRESENT"
        elif action == "RETAIN":
            verification = "VERIFY_RECORD_PRESENT"
        elif action in {"REDACT", "ANONYMIZE"}:
            if observed_state in {"REDACTED", "ANONYMIZED"}:
                exposed = False
            else:
                exposed = observed_state in {"IDENTIFIABLE", "EXPOSED", "FOUND"} or has_identifying_fields(
                    record,
                    fields,
                    permit_stable_reference=action == "REDACT",
                )
            if exposed:
                operation = "REPORT_EXPOSED_PII"
                remediation = "REDACT_RECORD" if action == "REDACT" else "ANONYMIZE_RECORD"
                verification = (
                    "VERIFY_RECORD_REDACTED"
                    if action == "REDACT"
                    else "VERIFY_RECORD_ANONYMIZED"
                )
            else:
                verification = (
                    "VERIFY_RECORD_REDACTED"
                    if action == "REDACT"
                    else "VERIFY_RECORD_ANONYMIZED"
                )
        elif action == "DELETE":
            operation, remediation, verification = ACTION_STEPS[action]

        if operation:
            finding_state = "ACTIVE" if "FLOW" in operation or "RESTORE" in operation else "PRESENT"
            findings.append(
                make_step(
                    "FINDING",
                    observation.system_id,
                    observation.resource_id,
                    operation,
                    finding_state,
                    observation.evidence_id,
                )
            )
            remediations.append(
                make_step(
                    "REMEDIATION",
                    observation.system_id,
                    observation.resource_id,
                    remediation,
                    {
                        "DISABLE_DATA_FLOW": "DISABLED",
                        "BLOCK_RESTORE": "BLOCKED",
                        "DELETE_RECORD": "ABSENT",
                        "REDACT_RECORD": "REDACTED",
                        "ANONYMIZE_RECORD": "ANONYMIZED",
                    }[remediation],
                    "",
                )
            )
            remediated.add((observation.system_id, observation.resource_id, verification))
        elif verification:
            verifications.append(
                make_step(
                    "VERIFICATION",
                    observation.system_id,
                    observation.resource_id,
                    verification,
                    {
                        "VERIFY_RECORD_PRESENT": "PRESENT",
                        "VERIFY_RECORD_REDACTED": "REDACTED",
                        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
                        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
                    }[verification],
                    observation.evidence_id,
                )
            )

    for evidence_id, system, resource, state in evidence_states:
        if state == "ABSENT":
            verifications.append(
                make_step(
                    "VERIFICATION",
                    infer_system(system),
                    resource,
                    "VERIFY_RECORD_ABSENT",
                    "ABSENT",
                    evidence_id,
                )
            )

    if not findings and not user_observations and not evidence_states:
        return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE", "steps": []}

    if findings:
        for step in verifications:
            step["evidence_id"] = ""

        for system, resource, operation in remediated:

            state = {
                "VERIFY_RECORD_ABSENT": "ABSENT",
                "VERIFY_RECORD_REDACTED": "REDACTED",
                "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
                "VERIFY_RESTORE_BLOCKED": "BLOCKED",
            }[operation]
            verifications.append(
                make_step(
                    "VERIFICATION",
                    system,
                    resource,
                    operation,
                    state,
                    "",
                )
            )
        status = "INCOMPLETE"
        steps = findings + remediations + verifications
    else:
        account_absence_proven = any(
            step["operation"] == "VERIFY_RECORD_ABSENT"
            and step["system_id"] == "account_service"
            for step in verifications
        )
        status = "COMPLETE" if account_absence_proven else "INCOMPLETE"
        steps = verifications if account_absence_proven else []

    unique = {}
    for step in steps:
        key = tuple(step[field] for field in STEP_FIELDS if field != "step_no")
        unique[key] = step
    steps = sorted(unique.values(), key=step_sort_key)
    for number, step in enumerate(steps, start=1):
        step["step_no"] = number
    return {"case_id": request["case_id"], "deletion_status": status, "steps": steps}


def load_context():
    requests = read_csv(DATA / "deletion_requests.csv")
    identities = read_csv(DATA / "user_identities.csv")
    audit_log = read_csv(DATA / "user_audit_log.csv")
    activity = read_csv(DATA / "system_activity.csv")
    manifest = read_csv(DATA / "evidence_files.csv")
    rules = load_policy_rules(read_csv(DATA / "deletion_rules.csv"))
    by_email, identity_fields = build_identity_index(identities, audit_log)
    evidence_index = build_evidence_index(manifest)
    observations, text_by_evidence, snapshot_inventory = build_observations(
        evidence_index
    )
    links = activity_resource_links(activity, by_email, identity_fields)
    return {
        "by_email": by_email,
        "identity_fields": identity_fields,
        "rules": rules,
        "evidence_index": evidence_index,
        "observations": observations,
        "text_by_evidence": text_by_evidence,
        "resource_links": links,
        "activity": activity,
        "snapshot_inventory": snapshot_inventory,
    }, requests


def run_requests(requests, context):
    request_context = dict(context)
    request_context["activity_resources"] = activity_resources_by_request(
        request_context.pop("activity"), requests
    )
    results = [
        audit_request(request, **request_context)
        for request in requests
    ]
    return sorted(results, key=lambda result: result["case_id"])


def validate_results(results, expected_case_ids):
    expected = sorted(expected_case_ids)
    actual = [result["case_id"] for result in results]
    if actual != expected:
        raise ValueError("Output case IDs do not exactly match the input request IDs")
    for result in results:
        if result["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError(f"Invalid status in {result['case_id']}")
        steps = result["steps"]
        if result["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE case {result['case_id']} has steps")
        for number, step in enumerate(steps, start=1):
            if tuple(step.keys()) != STEP_FIELDS:
                raise ValueError(f"Invalid step fields in {result['case_id']}")
            if step["step_no"] != number:
                raise ValueError(f"Non-consecutive step numbers in {result['case_id']}")


def write_output(results, path=OUTPUT):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(
            target,
            fieldnames=("case_id", "deletion_status", "steps_json"),
            lineterminator="\n",
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result["case_id"],
                    "deletion_status": result["deletion_status"],
                    "steps_json": json.dumps(
                        result["steps"],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )
    temporary.replace(path)


def main():
    context, requests = load_context()
    results = run_requests(requests, context)
    validate_results(results, [request["case_id"] for request in requests])
    write_output(results)
    counts = {
        status: sum(result["deletion_status"] == status for result in results)
        for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
    }
    print(f"Processed {len(results)} requests; wrote {OUTPUT}")
    print(
        "Status counts: "
        + ", ".join(f"{status}={count}" for status, count in counts.items())
    )
    print(
        f"Parsed {len(context['observations'])} structured observations from "
        f"{len(context['evidence_index'])} evidence files"
    )


if __name__ == "__main__":
    main()
