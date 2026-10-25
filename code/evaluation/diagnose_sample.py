
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
    mismatch_count = 0

    for prediction in predictions:
        case_id = prediction["case_id"]
        expected = expected_rows[case_id]
        expected_steps = json.loads(expected["steps_json"])
        actual_steps = prediction["steps"]

        status_ok = (
            prediction["deletion_status"] == expected["deletion_status"]
        )
        steps_ok = actual_steps == expected_steps

        if status_ok and steps_ok:
            continue

        mismatch_count += 1
        print("\n" + "=" * 60)
        print(f"CASE: {case_id}")
        print(
            f"Status: expected={expected['deletion_status']}, "
            f"actual={prediction['deletion_status']}"
        )
        print(
            f"Steps: expected={len(expected_steps)}, "
            f"actual={len(actual_steps)}"
        )

        shown = 0
        max_steps = max(len(expected_steps), len(actual_steps))

        for index in range(max_steps):
            exp = expected_steps[index] if index < len(expected_steps) else None
            act = actual_steps[index] if index < len(actual_steps) else None

            if exp == act:
                continue

            print(f"\nStep position {index + 1}")
            print("EXPECTED:", json.dumps(exp, ensure_ascii=False))
            print("ACTUAL:  ", json.dumps(act, ensure_ascii=False))

            shown += 1
            if shown >= 3:
                print("Showing up to 3 differences for this case.")
                break

    print(f"\nMismatched sample cases: {mismatch_count}/{len(requests)}")


if __name__ == "__main__":
    main()
