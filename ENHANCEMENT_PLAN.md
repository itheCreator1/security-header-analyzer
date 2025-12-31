# Security Header Analyzer Enhancement Plan: Sharpening Existing Analyzers

## Executive Summary

This plan focuses on **deepening the analysis quality** of existing security header analyzers rather than adding new headers. The goal is to position this tool as having the **most accurate and thorough analysis** in the market.

**Strategic Focus:** Quality over quantity - going from "good analysis of 15 headers" to "expert-level analysis of 15 headers"

---

## Phase 1: Enhancement Priority Strategy

### Current State Assessment

**Analyzer Quality Distribution:**
- **Tier 1 - Highly Sophisticated (3 analyzers):** CSP (9/10), Set-Cookie (8/10), Permissions-Policy (7/10)
- **Tier 2 - Moderately Sophisticated (6 analyzers):** HSTS (7/10), Referrer-Policy (6/10), Cache-Control (6/10), X-Frame-Options (5/10), Expect-CT (5.5/10), X-Content-Type-Options (3/10)
- **Tier 3 - Basic Implementation (6 analyzers):** COEP (4/10), COOP (4/10), CORP (4/10), X-XSS-Protection (3/10), X-Permitted-Cross-Domain-Policies (3/10), X-Download-Options (2.5/10)

**Key Finding:** 9 analyzers use basic value-matching patterns with significant room for enhancement.

### Enhancement Priority Matrix

#### 🔴 **PHASE 1A: High-Impact Enhancements** (Immediate Priority)

**1. CSP Analyzer Enhancement** ⭐ HIGHEST VALUE
- **Current State:** Already sophisticated (9/10), 500+ lines with complex parsing
- **Enhancement Opportunities:**
  - CSP bypass detection (common misconfigurations that attackers exploit)
  - Report endpoint validation (report-uri, report-to)
  - Directive syntax validation (detect malformed directives)
  - Nonce/hash quality warnings (detect weak patterns)
  - Frame-ancestors vs X-Frame-Options conflict detection
  - Data URI detection in script-src/img-src (security risk)

- **Impact:** HIGH - CSP is the most complex and critical header
- **Effort:** MEDIUM - Foundation already solid, adding specific checks
- **Files to Modify:**
  - `sha/analyzers/csp.py`
  - `tests/test_csp.py`
  - `docs/analyzer-reference.md`
  - `docs/headers/content-security-policy.md`

---

**2. Set-Cookie Analyzer Enhancement** ⭐ HIGH VALUE
- **Current State:** Sophisticated (8/10), handles multiple cookies
- **Enhancement Opportunities:**
  - Cookie prefix validation (`__Secure-`, `__Host-` prefixes)
  - Domain/Path scope analysis (detect overly broad scopes)
  - Cookie name pattern analysis (flag session/auth cookies without proper security)
  - SameSite=None frequency warnings (third-party cookie risks)
  - Partition attribute support (CHIPS - Cookies Having Independent Partitioned State)

- **Impact:** HIGH - Cookies are a primary attack vector
- **Effort:** MEDIUM - Multi-cookie handling already works well
- **Files to Modify:**
  - `sha/analyzers/set_cookie.py`
  - `tests/test_set_cookie.py`
  - `docs/analyzer-reference.md`
  - `docs/headers/set-cookie.md`

---

**3. Cache-Control Analyzer Enhancement** ⭐ MEDIUM-HIGH VALUE
- **Current State:** Basic (6/10), parses directives but limited validation
- **Enhancement Opportunities:**
  - Directive conflict detection (public + private, no-store + max-age)
  - Response-type aware validation (HTML vs static assets vs API)
  - Privacy leak detection (caching sensitive endpoints)
  - Stale-while-revalidate/stale-if-error support
  - Missing must-revalidate with long max-age warnings

- **Impact:** MEDIUM-HIGH - Caching mistakes can leak sensitive data
- **Effort:** LOW-MEDIUM - Parser exists, add validation logic
- **Files to Modify:**
  - `sha/analyzers/cache_control.py`
  - `tests/test_cache_control.py`
  - `docs/analyzer-reference.md`
  - Create `docs/headers/cache-control.md` (currently missing)

---

#### 🟡 **PHASE 1B: Cross-Origin Headers Enhancement** (Secondary Priority)

**4. COEP/COOP/CORP Interaction Validation** ⭐ MEDIUM VALUE
- **Current State:** Basic (4/10 each), simple value matching
- **Enhancement Opportunities:**
  - **Cross-header interaction validation:**
    - COEP + COOP pair detection for SharedArrayBuffer eligibility
    - CORP + COEP compatibility checking
    - Warn about partial cross-origin isolation
  - **Isolation level analysis:**
    - Detect full isolation (COEP: require-corp + COOP: same-origin)
    - Detect credentialless isolation (COEP: credentialless)
  - **SharedArrayBuffer eligibility detection**

- **Impact:** MEDIUM - Important for modern web apps using SharedArrayBuffer
- **Effort:** MEDIUM - Need to coordinate across 3 analyzers
- **Files to Modify:**
  - `sha/analyzers/coep.py`
  - `sha/analyzers/coop.py`
  - `sha/analyzers/corp.py`
  - Create new `sha/analyzers/cross_origin_validator.py` for interaction logic
  - `tests/test_coep.py`, `tests/test_coop.py`, `tests/test_corp.py`
  - `docs/analyzer-reference.md`
  - Update `docs/headers/coep.md`, `docs/headers/coop.md`, `docs/headers/corp.md`

---

**5. Permissions-Policy Enhancement** ⭐ MEDIUM VALUE
- **Current State:** Medium-High (7/10), tracks 7 sensitive features
- **Enhancement Opportunities:**
  - Feature allowlist syntax validation (detect malformed values)
  - Expand sensitive feature list (payment, usb, serial, bluetooth, etc.)
  - Feature risk categorization (high-risk vs medium-risk features)
  - Warn about features NOT explicitly restricted
  - Detect unknown/deprecated feature names

- **Impact:** MEDIUM - Privacy protection is increasingly important
- **Effort:** LOW - Foundation is solid, expand feature tracking
- **Files to Modify:**
  - `sha/analyzers/permissions_policy.py`
  - `tests/test_permissions_policy.py`
  - `docs/analyzer-reference.md`
  - `docs/headers/permissions-policy.md`

---

#### 🟢 **PHASE 1C: Refinement Enhancements** (Lower Priority)

**6. HSTS Enhancement** ⭐ LOW-MEDIUM VALUE
- **Current State:** Mature (7/10)
- **Enhancement Opportunities:**
  - HSTS preload list eligibility validation (all 3 conditions required)
  - Subdomain configuration conflict warnings
  - Max-age syntax validation improvements

- **Impact:** LOW-MEDIUM - Already well-implemented
- **Effort:** LOW
- **Files to Modify:**
  - `sha/analyzers/hsts.py`
  - `tests/test_hsts.py`
  - `docs/analyzer-reference.md`

---

**7. X-Frame-Options Enhancement** ⭐ LOW VALUE
- **Current State:** Mature (5/10)
- **Enhancement Opportunities:**
  - CSP frame-ancestors conflict detection (warn if both present)
  - ALLOW-FROM deprecation education

- **Impact:** LOW - Header is mature and simple
- **Effort:** LOW
- **Files to Modify:**
  - `sha/analyzers/xframe.py`
  - `tests/test_xframe.py`
  - `docs/analyzer-reference.md`

---

**8. Referrer-Policy Enhancement** ⭐ LOW-MEDIUM VALUE
- **Current State:** Basic (6/10)
- **Enhancement Opportunities:**
  - Context-aware recommendations (e-commerce vs blog vs API)
  - Comma-separated fallback value order validation
  - Deprecated policy detection

- **Impact:** LOW-MEDIUM - Relatively mature
- **Effort:** LOW
- **Files to Modify:**
  - `sha/analyzers/referrer_policy.py`
  - `tests/test_referrer_policy.py`
  - `docs/analyzer-reference.md`

---

#### ⚪ **PHASE 1D: Legacy Headers** (Maintenance Only)

**No Enhancements Planned:**
- X-Content-Type-Options (intentionally simple)
- X-XSS-Protection (deprecated, intentionally minimal)
- X-Download-Options (IE-specific legacy)
- X-Permitted-Cross-Domain-Policies (Flash EOL)
- Expect-CT (deprecated, adequate implementation)

**Rationale:** These headers are either deprecated or intentionally simple. Enhancing them provides minimal value.

---

## Phase 2: Implementation Roadmap

### Recommended Implementation Order

**Sprint 1: CSP Deep Dive** (Weeks 1-2)
- Enhance CSP analyzer with bypass detection and advanced validation
- Add comprehensive tests (target: 30+ new test cases)
- Update documentation with new capabilities
- **Deliverable:** CSP analyzer at 10/10 quality level

**Sprint 2: Cookie Security** (Week 3)
- Enhance Set-Cookie analyzer with prefix validation and scope analysis
- Add cookie pattern recognition
- Update documentation
- **Deliverable:** Set-Cookie analyzer hardened against common mistakes

**Sprint 3: Cache Security** (Week 4)
- Enhance Cache-Control with conflict detection and context-awareness
- Create comprehensive header documentation file
- Add response-type specific recommendations
- **Deliverable:** Cache-Control analyzer with smart validation

**Sprint 4: Cross-Origin Isolation** (Weeks 5-6)
- Implement COEP/COOP/CORP interaction validation
- Create cross-origin validator module
- Document SharedArrayBuffer eligibility requirements
- **Deliverable:** Industry-leading cross-origin isolation analysis

**Sprint 5: Polish & Permissions** (Week 7)
- Enhance Permissions-Policy with expanded feature tracking
- Refine HSTS, X-Frame-Options, Referrer-Policy
- Documentation consistency pass
- **Deliverable:** All top-tier analyzers at 8/10+ quality

---

### Documentation Strategy

Following existing documentation framework:

#### **1. analyzer-reference.md Updates** (Quick Reference)
For each enhanced analyzer:
- Update "How It Works" section with new validation rules
- Add new good/bad configuration examples
- Update references with new resources
- Keep descriptions concise (scan-friendly)

#### **2. Individual Header Docs** (Deep Dive)
Create/update files in `docs/headers/`:
- `cache-control.md` (NEW - currently missing)
- Update existing files for CSP, Set-Cookie, COEP, COOP, CORP, Permissions-Policy
- Add "Enhanced Validation" section documenting new checks
- Include attack scenarios that new validation prevents
- Add configuration examples showing new features

#### **3. Architecture Documentation Updates**
- `docs/architecture/components.md`: Update analyzer examples if patterns change
- `docs/architecture/extensibility-guide.md`: Add advanced patterns if new techniques used
- No major architectural changes expected (Registry Pattern remains)

#### **4. CHANGELOG.md Updates**
Track all enhancements:
```markdown
## [Unreleased]

### Added - Analyzer Enhancements
- **CSP Analyzer:** Bypass detection, report endpoint validation, directive syntax checking
- **Set-Cookie Analyzer:** Cookie prefix validation, domain/path scope analysis
- **Cache-Control Analyzer:** Directive conflict detection, response-type awareness
- **COEP/COOP/CORP:** Cross-header interaction validation, SharedArrayBuffer eligibility
- **Permissions-Policy:** Expanded feature tracking, allowlist syntax validation
```

#### **5. Documentation Consistency Checklist**
For each enhancement:
- [ ] Update analyzer-reference.md (quick reference)
- [ ] Update/create individual header doc in docs/headers/
- [ ] Add attack scenarios for new validation
- [ ] Include good/bad configuration examples
- [ ] Update CHANGELOG.md
- [ ] Cross-link related headers
- [ ] Use consistent severity terminology
- [ ] Use consistent status markers (✅ ⚠️ ❌)
- [ ] Add references to standards/specs

---

### Testing Strategy

#### **Test Coverage Goals**
- Maintain 97%+ overall coverage
- Each enhanced analyzer: 100% coverage
- Add edge case tests for new validation logic
- Add integration tests for cross-header interactions

#### **Test Categories per Enhancement**

**CSP Enhancement Tests:**
- Bypass detection tests (15+ bypass patterns)
- Report endpoint validation tests
- Directive syntax validation tests
- Nonce/hash quality tests
- Frame-ancestors conflict tests

**Set-Cookie Enhancement Tests:**
- Cookie prefix validation tests (`__Secure-`, `__Host-`)
- Domain/Path scope tests
- Cookie name pattern tests
- SameSite=None frequency tests

**Cache-Control Enhancement Tests:**
- Directive conflict tests (all combinations)
- Response-type specific tests
- Privacy leak detection tests
- Stale-while-revalidate tests

**Cross-Origin Enhancement Tests:**
- COEP+COOP interaction tests
- SharedArrayBuffer eligibility tests
- Isolation level detection tests
- Compatibility matrix tests

**Permissions-Policy Enhancement Tests:**
- Allowlist syntax validation tests
- Unknown feature detection tests
- Risk categorization tests

#### **Testing Framework Additions**
- Create test fixtures for complex multi-header scenarios
- Add parametrized tests for directive combinations
- Create helper functions for common validation patterns

---

### Success Metrics

**Quality Metrics:**
- CSP analyzer: 9/10 → 10/10
- Set-Cookie analyzer: 8/10 → 9/10
- Cache-Control analyzer: 6/10 → 8/10
- COEP/COOP/CORP analyzers: 4/10 → 7/10
- Permissions-Policy analyzer: 7/10 → 8/10

**Coverage Metrics:**
- Test coverage: Maintain 97%+
- New tests added: 100+ comprehensive tests
- Documentation coverage: 100% of enhanced features documented

**Market Positioning:**
- "Most accurate CSP analysis" claim backed by bypass detection
- "Industry-leading cross-origin isolation validation"
- "Comprehensive cookie security analysis with prefix validation"

---

### Technical Implementation Notes

#### **Cross-Analyzer Coordination**

For COEP/COOP/CORP interaction validation, create:
```python
# sha/analyzers/cross_origin_validator.py
def validate_cross_origin_isolation(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate cross-origin header interactions.

    Checks:
    - COEP + COOP pairing for SharedArrayBuffer
    - Full isolation vs credentialless isolation
    - CORP compatibility with COEP
    """
    pass
```

Call from analyzer.py after individual analyzers run:
```python
# sha/analyzer.py
findings = []
for header_key, analyze_func in ANALYZER_REGISTRY.items():
    finding = analyze_func(headers.get(header_key))
    findings.append(finding)

# NEW: Cross-header validation
cross_origin_finding = validate_cross_origin_isolation(headers)
if cross_origin_finding:
    findings.append(cross_origin_finding)
```

#### **Backward Compatibility**

All enhancements maintain backward compatibility:
- Existing CONFIG structure unchanged
- Existing return value schema unchanged
- No breaking changes to public API
- Only additive changes (new validation, not changes to existing)

#### **Code Style Consistency**

Follow existing patterns:
- Use helper functions for complex validation
- Normalize values (lowercase, strip whitespace)
- Return consistent Finding dictionaries
- Document attack scenarios in code comments
- Type hints throughout

---

## Alternative: Quick Wins (If Time Constrained)

If full implementation isn't feasible, prioritize:

**Week 1: CSP Bypass Detection** (Highest value-add)
- Add 10 common CSP bypasses
- Document in attack scenarios
- 80% of Phase 1A value in 20% of time

**Week 2: Set-Cookie Prefix Validation** (High visibility)
- Add `__Secure-` and `__Host-` validation
- Simple to implement, high security value

**Week 3: Cache-Control Conflicts** (Low-hanging fruit)
- Detect public+private, no-store+max-age
- Easy to implement, clear value

---

## Summary

This plan focuses on **sharpening existing analyzers** to create the most accurate and thorough security header analysis tool available. By enhancing the top 5-6 headers with sophisticated validation logic, we position this tool as having expert-level analysis depth rather than just breadth.

**Recommended Next Step:** Start with Phase 1A - CSP, Set-Cookie, and Cache-Control enhancements for maximum impact.
