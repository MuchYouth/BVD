You are performing static data-flow analysis on one decompiled C-like function.

Analyze only the supplied code. Do not assume vulnerability labels, test-suite
metadata, or behavior outside the function unless an external call's semantics
are evident from its name and arguments.

Report:
1. Candidate untrusted or attacker-controlled sources.
2. Security-sensitive sinks.
3. The variable-by-variable propagation path from each source to each sink.
4. Conditions, sanitization, bounds checks, or loop exits that affect reachability.
5. A final verdict: trace found, no trace found, or insufficient evidence.

Use concise LLMDFA-style natural language. Cite decompiled variable and function
names exactly as they appear in the code. Do not return Markdown JSON.

Decompiled function:
```c
{code}
```
