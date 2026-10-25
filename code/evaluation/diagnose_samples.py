
import csv
import json
import sys
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as agent


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main():
    requests = read_csv(ROOT / "dataset" / "sample_deletion_requests.csv")
    expected_rows = {
        row["case_id"]: row
        for row in read_csv(ROOT / "dataset" / "sample_output.csv")
    }

    context, _ = agent.load_context()
    predictions = agent.run_requests(requests, context)
    mismatches = 0

    for prediction in predictions:
        case_id = prediction["case_id"]
        expected = expected_rows[case_id]
        expected_steps = json.loads(expected["steps_json"])
        actual_steps = prediction["steps"]

        if (
            prediction["deletion_status"] == expected["deletion_status"]
            and actual_steps == expected_steps
        ):
            continue

        mismatches += 1
        print(f"\n{'=' * 50}")
        print(f"CASE: {case_id}")
        print(f"Expected status: {expected['deletion_status']}")
        print(f"Actual status:   {prediction['deletion_status']}")
        print(f"Expected steps: {len(expected_steps)}")
        print(f"Actual steps:   {len(actual_steps)}")

        differences = 0
        for i in range(max(len(expected_steps), len(actual_steps))):
            exp = expected_steps[i] if i < len(expected_steps) else None
            act = actual_steps[i] if i < len(actual_steps) else None

            if exp != act:
                print(f"\nPosition {i + 1}")
                print("EXPECTED:", json.dumps(exp, ensure_ascii=False))
                print("ACTUAL:  ", json.dumps(act, ensure_ascii=False))
                differences += 1
                if differences == 3:
                    print("Further differences omitted.")
                    break

    print(f"\nMismatched cases: {mismatches}/{len(requests)}")


if __name__ == "__main__":
    main()
