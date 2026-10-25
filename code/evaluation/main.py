import csv
import json
import sys
from collections import Counter
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as agent  # noqa: E402


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def validate_output():
    requests = read_csv(ROOT / "dataset" / "deletion_requests.csv")
    manifest = read_csv(ROOT / "dataset" / "evidence_files.csv")
    valid_evidence = {row["file_id"] for row in manifest}
    rows = read_csv(ROOT / "output.csv")
    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row["case_id"] for row in rows]
    if rows and list(rows[0]) != ["case_id", "deletion_status", "steps_json"]:
        raise ValueError("output.csv header does not match the contract")
    if actual_ids != expected_ids:
        raise ValueError("output.csv must contain every request exactly once, sorted")

    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    step_count = 0
    for row in rows:
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError(f"Invalid deletion status for {row['case_id']}")
        steps = json.loads(row["steps_json"])
        if not isinstance(steps, list):
            raise ValueError(f"steps_json must be an array for {row['case_id']}")
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE case {row['case_id']} must have no steps")
        remediated_resources = {
            (step["system_id"], step["resource_id"])
            for step in steps
            if step["phase"] == "REMEDIATION"
        }
        for number, step in enumerate(steps, start=1):
            if list(step) != list(agent.STEP_FIELDS):
                raise ValueError(f"Invalid step fields for {row['case_id']}")
            if step["step_no"] != number:
                raise ValueError(f"Non-consecutive step numbers for {row['case_id']}")
            if step["phase"] not in phase_order:
                raise ValueError(f"Invalid phase for {row['case_id']}")
            if step["evidence_id"]:
                if step["evidence_id"] not in valid_evidence:
                    raise ValueError(f"Unknown evidence ID in {row['case_id']}")
            if step["phase"] == "REMEDIATION" and step["evidence_id"]:
                raise ValueError(f"Remediation must not cite evidence for {row['case_id']}")
            if (
                row["deletion_status"] == "INCOMPLETE"
                and step["phase"] == "VERIFICATION"
                and step["evidence_id"]
                and (step["system_id"], step["resource_id"]) in remediated_resources
            ):
                raise ValueError(
                    f"Future verification for a remediated resource must not cite "
                    f"evidence for {row['case_id']}"
                )
            if step["phase"] == "FINDING" and not step["evidence_id"]:
                raise ValueError(f"Finding must cite evidence for {row['case_id']}")
            if row["deletion_status"] == "COMPLETE" and (
                step["phase"] != "VERIFICATION" or not step["evidence_id"]
            ):
                raise ValueError(f"COMPLETE case must cite current verification evidence")
            step_count += 1
    return {
        "requests": len(requests),
        "output_rows": len(rows),
        "steps": step_count,
        "status_counts": dict(Counter(row["deletion_status"] for row in rows)),
    }


def evaluate_public_samples(context):
    sample_requests = read_csv(ROOT / "dataset" / "sample_deletion_requests.csv")
    expected_rows = {
        row["case_id"]: row
        for row in read_csv(ROOT / "dataset" / "sample_output.csv")
    }
    predictions = agent.run_requests(sample_requests, context)
    status_correct = 0
    exact_rows = 0
    expected_steps = []
    predicted_steps = []
    aligned_field_matches = 0
    aligned_field_total = 0
    sequence_correct = 0
    for prediction in predictions:
        expected = expected_rows[prediction["case_id"]]
        expected_status = expected["deletion_status"]
        expected_objects = json.loads(expected["steps_json"])
        actual_objects = prediction["steps"]
        status_correct += prediction["deletion_status"] == expected_status
        sequence_correct += actual_objects == expected_objects
        exact_rows += (
            prediction["deletion_status"] == expected_status
            and actual_objects == expected_objects
        )
        expected_steps.extend(
            json.dumps(step, sort_keys=True) for step in expected_objects
        )
        predicted_steps.extend(
            json.dumps(step, sort_keys=True) for step in actual_objects
        )
        for index in range(max(len(expected_objects), len(actual_objects))):
            expected_step = expected_objects[index] if index < len(expected_objects) else {}
            actual_step = actual_objects[index] if index < len(actual_objects) else {}
            for field in agent.STEP_FIELDS:
                aligned_field_total += 1
                aligned_field_matches += expected_step.get(field) == actual_step.get(field)

    expected_counter = Counter(expected_steps)
    predicted_counter = Counter(predicted_steps)
    true_positive = sum((expected_counter & predicted_counter).values())
    precision = true_positive / len(predicted_steps) if predicted_steps else 0.0
    recall = true_positive / len(expected_steps) if expected_steps else 0.0
    return {
        "sample_count": len(sample_requests),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(sample_requests),
        "exact_rows": exact_rows,
        "sequence_correct": sequence_correct,
        "sequence_accuracy": sequence_correct / len(sample_requests),
        "expected_step_count": len(expected_steps),
        "predicted_step_count": len(predicted_steps),
        "exact_step_matches": true_positive,
        "step_precision": precision,
        "step_recall": recall,
        "field_matches": aligned_field_matches,
        "field_total": aligned_field_total,
        "field_accuracy": aligned_field_matches / aligned_field_total if aligned_field_total else 0.0,
    }


def evaluate_custom_cases():
    cases = (
        ("explicit English deletion", "Please delete my account.", True),
        ("information access only", "Please export my data.", False),
        ("explicitly negated deletion", "Do not delete my account; correct my email.", False),
        ("Spanish deletion", "Solicito la eliminación de mi cuenta.", True),
        ("Japanese deletion", "このアカウントの削除をお願いします。", True),
    )
    failures = [
        name
        for name, text, expected in cases
        if agent.request_authorizes_deletion(text) != expected
    ]
    return {"custom_cases": len(cases), "custom_failures": failures}


def main():
    output_summary = validate_output()
    context, _ = agent.load_context()
    sample_summary = evaluate_public_samples(context)
    custom_summary = evaluate_custom_cases()
    print(json.dumps(
        {
            "output": output_summary,
            "public_samples": sample_summary,
            "custom_cases": custom_summary,
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()
