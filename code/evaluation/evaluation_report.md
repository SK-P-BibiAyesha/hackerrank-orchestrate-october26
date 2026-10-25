# Evaluation report

## Measured results

The implementation was run against the 32 public sample requests and their
provided `sample_output.csv` answers. These numbers are **sample-set results**,
not hidden evaluation-set accuracy.

| Metric | Result |
|---|---:|
| Public sample cases | 32 |
| Deletion-status accuracy | 24/32 (75.00%) |
| Exact output rows (status and ordered steps) | 9/32 (28.13%) |
| Exact step sequences | 9/32 (28.13%) |
| Expected steps | 193 |
| Predicted steps | 168 |
| Exact step matches | 83 |
| Step precision | 49.40% |
| Step recall | 43.01% |
| Aligned field accuracy | 756/1,547 (48.87%) |

The aligned field metric compares each field at the same step position and
counts a missing or extra step as mismatching fields. Step precision and recall
use exact step objects, including evidence references and ordering.

The full evaluation output was checked for the exact header, one sorted row per
input case, valid JSON arrays, the required step fields, consecutive step
numbers, valid cited evidence IDs, and evidence-free future steps for
remediated resources. The validated output contains 518 rows and 1,365 steps:
42 `COMPLETE`, 425 `INCOMPLETE`, and 51 `NOT_APPLICABLE`.

## Additional test cases

These participant-created cases exercise request authorization:

1. `Please delete my account.` → deletion authorized.
2. `Please export my data.` → not a deletion request.
3. `Do not delete my account; correct my email.` → deletion not authorized.
4. `Solicito la eliminación de mi cuenta.` → deletion authorized.
5. `このアカウントの削除をお願いします。` → deletion authorized.

All five passed. The unit suite also covers historical email resolution,
tombstone redaction, and timezone-aware timestamps.

## Failures found and improvements made

- The initial starter only printed dataset diagnostics. It was replaced with a
  runnable pipeline that resolves historical emails, parses JSON/SQL/log/text
  and PDF evidence, filters evidence by `audit_at`, applies policy actions, and
  writes the root-level `output.csv`.
- Sample tests exposed errors in deletion-intent classification, search-index
  category assignment, tombstone handling, and trace correlation. These were
  corrected and covered by focused tests.
- Sample accuracy remains limited: indirect resource links, replicated
  snapshots, and records whose association depends on operational context can
  still be missed or misclassified. The public sample score is a diagnostic,
  not a guarantee of hidden-set accuracy.
- The run now uses RapidOCR locally for all 11 screenshot files. Its OCR text
  improves evidence coverage, but OCR recognition and matching are not perfect.
- The parser now correlates deletion activity to the nearest request report,
  checks SQL snapshot inventory for absent linked resources, keeps primary and
  failover observations separate, and avoids classifying records from
  incidental field values such as a `signup_channel` containing “search”.
- No organizer answer key was used or available. Hidden-set status, step,
  field, and sequence accuracy are therefore not measured by this report.

The current predictions are a deterministic baseline and must not be treated
as proof that all 518 cases are correctly adjudicated.
