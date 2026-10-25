# Usage report

## Final full-dataset run

The final run executed `python code/main.py` locally and generated the
repository-root `output.csv` for all 518 requests. It uses deterministic
Python rules and local parsing. RapidOCR 3.10 ran locally through ONNX Runtime
to inspect the 11 screenshot evidence files; no hosted language model or
inference API was called.

| Measure | Final run |
|---|---:|
| Provider | RapidOCR / ONNX Runtime (local OCR); no hosted provider |
| Model names | PP-OCRv6_det_small, ch_ppocr_mobile_v2.0_cls_mobile, PP-OCRv6_rec_small |
| Local OCR inferences | 11 images |
| Hosted LLM/API calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated model/API cost | $0.00 |
| Estimated cost per request | $0.00 |

OCR uses image and text inputs rather than tokenized LLM requests, so input and
output token counts and per-token costs are not applicable (reported as zero
for the token-based usage totals). No provider/API cost was incurred. Overall
hosted-call totals are zero; local OCR inference counts are reported above.
These figures do not estimate local CPU time, electricity, or package/model
download costs.

The run parsed 2,186 structured observations from 94 evidence files and
processed all 11 screenshots with local OCR.
