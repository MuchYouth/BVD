# pcode_dataflow_review_v1

Review an anonymized P-code dataflow trace candidate.

Question:

Does the value from the source operation flow to the sink argument operation?

Return only JSON:

```json
{
  "answer": "yes|no|unknown",
  "reason": "...",
  "relevant_ops": [0],
  "confidence": 0.0
}
```

Do not infer labels or vulnerability ground truth.
