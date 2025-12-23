# RFC 001: Observability, Security, and Production Readiness

| Metadata | Details |
| :--- | :--- |
| **Status** | Draft |
| **Author** | Olori Kendricj|
| **Created** | 2024-12-21 |
| **Target Version** | 0.2.0 |
| **Priority** | P0 (Blocker for Production) |

## Executive Summary

This RFC proposes critical improvements to `django-otp-actions` to make it production-ready. Currently, the library is a "black box" with no observability, missing security hardening, and limited debugging capabilities.

This proposal addresses these gaps through:
1.  **Security Hardening** - Fix cryptographic weaknesses.
2.  **Observability Layer** - Add signals, OpenTelemetry tracing/metrics, and structured logging.
3.  **Admin Interface** - Enable support/debugging workflows.
4.  **Performance Documentation** - Provide benchmarks and capacity planning data.

**Timeline**: Undecided
**Breaking Changes**: Minimal (configuration only)

---

## 1. Problem Statement

### 1.1 Current Issues

**Security Vulnerabilities:**
* Using `random.randint()` instead of cryptographically secure `secrets` module.
* Non-constant-time OTP comparison (timing attack vulnerability).
* No rate limiting guidance or built-in protection.

**Observability Gaps:**
* Zero visibility into OTP lifecycle events.
* No metrics for monitoring success/failure rates.
* Cannot debug production issues.
* No audit trail for compliance.

**Operational Challenges:**
* Support teams cannot debug user OTP issues.
* No health check endpoint for monitoring.

### 1.2 Impact

* **Security**: Vulnerabilities are unacceptable for financial transactions.
* **Reliability**: Lack of observability means being blind to production issues.
* **Production Readiness Score**: 3/10.

---

## 2. Proposed Solution

### 2.1 Architecture Overview

The solution introduces an event-driven architecture and OpenTelemetry instrumentation:

* **Core Services** (`generate_otp`, `validate_otp`) emit **Signals** and create **OTel Spans**.
* **Listeners** handle Logging and Audit Logs.
* **OpenTelemetry SDK** exports traces and metrics to collectors (e.g., Jaeger, Prometheus).

---

## 3. Detailed Design

### 3.1 Security Hardening

#### [SEC-001] Cryptographically Secure Randomness
* **Change**: Replace `random.randint` with `secrets.randbelow`.
* **Rationale**: `random` is not cryptographically secure.

#### [SEC-002] Constant-Time Verification
* **Change**: Use `secrets.compare_digest` for OTP verification.
* **Rationale**: Prevents timing attacks where attackers guess OTPs based on response time.

#### [SEC-003] Context Size Limits
* **Change**: Enforce strict byte limits on metadata (5KB) and context (10KB).
* **Rationale**: Prevents DoS via memory exhaustion.

#### [SEC-004] Rate Limiting Documentation
* **Action**: Add explicit warning in `SECURITY.md` regarding application-level rate limiting.
* **Rationale**: The library is stateless; rate limiting must be handled by the host application (e.g., `django-ratelimit`).

### 3.2 Observability & OpenTelemetry

#### [OBS-001] Signal Infrastructure
We will introduce standard Django signals in `signals.py`:
* `otp_generated`
* `otp_validation_attempt`
* `otp_succeeded`
* `otp_failed` (includes reason)
* `otp_exhausted`

#### [OBS-003] OpenTelemetry Tracing
We will instrument `services.py` using the `opentelemetry-api`.
* **Spans**:
    * `generate_otp`: Records generation duration. Attributes: `otp.identifier` (masked).
    * `validate_otp`: Records validation flow. Attributes: `otp.retry_count`, `otp.result`.
* **Error Handling**: Exceptions (like `InvalidOTPException`) will be recorded as Span Events.

#### [OBS-004] OpenTelemetry Metrics
Instead of raw StatsD, we will use OTel Metrics:
* **Counters**:
    * `otp.generated_total`: Count of OTPs generated.
    * `otp.validated_total`: Count of validation attempts (tagged by `status`).
* **Histograms**:
    * `otp.validation_duration_ms`: Latency distribution.

#### [OBS-005] Structured Logging with Trace Correlation
* **Change**: Implement a JSON log handler.
* **Feature**: Inject `trace_id` and `span_id` from the active OTel context into log records to correlate logs with traces.

### 3.3 Admin & Operations

#### [OPS-001] Audit Log Model
* **Model**: `OTPAuditLog` (Optional, enabled via settings).
* **Fields**: `identifier`, `action`, `status`, `retry_count`, `metadata`, `trace_id`, `created_at`.

#### [OPS-002] Admin Interface
* **Features**: Read-only interface, filtering by status/identifier, and CSV export.

#### [OPS-003] Health Check Endpoint
* **URL**: `/health/otp/`
* **Checks**: Encryption key validity, generation/validation round-trip, latency check (< 100ms).

---

## 4. Implementation Plan

### Phase 1: Security (Completed)
* [✓] [SEC-001] Replace `random` with `secrets`.
* [✓] [SEC-002] Implement constant-time comparison.
* [x] [SEC-003] Add size limits for context.

### Phase 2: Observability - Signals & OTel (Current Priority)
* [ ] [OBS-001] Create `signals.py` infrastructure.
* [ ] [OBS-002] Integrate signals into `services.py`.
* [ ] [OBS-003] Add OpenTelemetry Tracing instrumentation.
* [ ] [OBS-004] Add OpenTelemetry Metrics instrumentation.
* [ ] [OBS-005] Implement Structured Logging with trace correlation.

### Phase 3: Admin & Ops
* [ ] [OPS-001] Create Audit Log model.
* [ ] [OPS-002] Build Admin interface.
* [ ] [OPS-003] Create Health Check endpoint.

---

## 5. Success Metrics

* **Security**: Zero use of non-cryptographic random; All comparisons constant-time.
* **Observability**: 100% of lifecycle events emit Signals and OTel Spans.
* **Performance**: Generation < 1ms; Validation < 2ms (p95).
* **Quality**: Test coverage >= 95%.
