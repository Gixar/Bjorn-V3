# Smart Planner V2 — deterministic local adaptation

Smart Planner V2 improves useful completed work per hour without an LLM, cloud service or model
runtime. It combines Bjorn's existing static evidence with local measurements from this Pi.

## Runtime flow

1. `Planner.collect()` applies target, port, parent and retry gates.
2. Cold-start candidates use 85% of the existing heuristic plus 15% of deterministic
   value/duration priors, providing an immediate improvement without discarding proven rules.
3. Once an action has history, its static score is blended with:
   - Beta-smoothed success probability;
   - exponentially weighted duration;
   - the relative value of its expected output.
4. The orchestrator logs the score and reason before execution.
5. Legacy or typed action results are normalised to one `ActionOutcome`.
6. Aggregated history is flushed atomically once per cycle to
   `data/action_telemetry.json`.

The telemetry file contains no credentials, loot, banners or command output. Per-target records
are capped at 512 and the oldest entries are removed first.

## Score

Measured utility is proportional to:

```text
relative_value * estimated_success_probability / estimated_duration
```

Cold start gives the utility prior 15% influence. Confidence then increases gradually with
completed samples and is capped at 80%, preserving static
evidence such as a satisfied parent, known CVEs, service hints and open ports. Beta(1,1) smoothing
prevents one early outcome from becoming 0% or 100% certainty.

Reasons remain inspectable in the log, for example:

```text
Planner chose: HTTPFingerprint@192.168.1.20 - never tried - :80 - smart:p=0.82,t=5s,n=9
```

## Retry adaptation

Retries are scoped to `(action, target)` so one failing host does not penalise another.

| Outcome | Policy |
| --- | --- |
| `resource_busy` | Retry in about 30 seconds; do not reduce success probability. |
| `failed`, `timeout`, `error` | Exponential backoff by consecutive failures, capped at six hours. |
| `auth_failed` | Four times the configured base delay. |
| `no_findings` | Three times the base delay. |
| `unavailable` | At least one hour, avoiding repeated missing-tool attempts. |
| `success` | Reset the target-action failure streak. |
| `skipped` | Leave no telemetry or netkb trace. |

Existing string-returning actions work unchanged. Modules can migrate gradually by returning an
`ActionOutcome` or a mapping containing `status`, `reason` and `evidence_count`.

## Configuration and rollback

The upgrade adds this default:

```json
"smart_planner_enabled": true
```

Set it to `false` through the existing configuration UI/file to restore the previous static score
and fixed retry behavior. Telemetry may continue collecting so a later re-enable does not discard
history. Delete `data/action_telemetry.json` while the service is stopped to reset learning.

## Evaluation commands

```bash
# Show the redacted history learned by this Pi.
python3 scripts/planner_report.py

# Compare old and new selection against the exact same deterministic fixture.
python3 scripts/planner_benchmark.py --require-improvement 30
```

The benchmark is a scheduling regression fixture, not a promise for a real network. Hardware
evaluation must compare useful outcomes, action mix, duration, load and temperature over equivalent
authorized test windows.

## Future IA boundary

A future local or remote model may propose value adjustments or candidate annotations. It should
not bypass eligibility, blacklists, resource limits, retry rules or the deterministic executor.
