# CWE Support Matrix

Status value의 의미는 다음과 같다.

- `supported`: 현재 P-code trace builder에서 source, sink, trace rule이 정의되어 있고 구현되어 있다.
- `partially_supported`: 일부 rule은 존재하지만 reliable trace extraction을 위해 추가 modeling이 필요하다.
- `unsupported`: Discovery는 해당 CWE를 기록할 수 있지만, analysis는 pipeline 실패 없이 skip해야 한다.

| CWE | status | source_rule_defined | sink_rule_defined | trace_rule_defined | requires_call_arguments | requires_memory_model | requires_interprocedural_analysis | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CWE78 | supported | yes | yes | yes | yes | partial | no for MVP | MVP target. External input을 command execution sink의 command/path argument로 trace한다. `-O0`, unstripped binary에서 intraprocedural def-use로 시작한다. |
| CWE134 | partially_supported | yes | yes | planned | yes | partial | no for initial extension | Next extension. External input string을 printf/syslog-style sink의 format string argument로 trace한다. 정확한 argument index handling이 필요하다. |
| all other discovered CWEs | unsupported | no | no | no | varies | varies | varies | Discovery는 이 CWE들을 manifest에 포함해야 한다. Pipeline stage는 unsupported status를 기록하고 계속 진행해야 한다. |

## MVP Interpretation

CWE-78은 첫 MVP에서 유일한 active CWE이다. CWE-134는 문서화하고 초기 rule file stub을 두되, CWE-78 MVP를 막지 않아야 한다.

Support matrix는 궁극적으로 `configs/cwe_rules/*.yaml`과 implementation capability metadata에서 생성되어야 한다. 그 전까지 이 문서는 사람이 읽는 planning source로 사용한다.
