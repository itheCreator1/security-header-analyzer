# Documentation Standards

> Comprehensive documentation management guidelines for the Security Header Analyzer project

---

## Quick Reference

**Core Principles:** Brevity • Conciseness • Accuracy

**Update Checklist:**
- [ ] Code changes documented inline (docstrings)
- [ ] Related markdown docs updated
- [ ] Cross-links added/verified
- [ ] Examples tested and working
- [ ] Spelling/grammar checked
- [ ] Links validated (no 404s)

**Documentation Locations:**
- Header guides → `docs/headers/`
- Architecture docs → `docs/architecture/`
- User guides → `docs/`
- Repository rules → `docs/repo-rules/`
- Python docstrings → Module-level in `.py` files

---

## Documentation Philosophy

### Core Principles (from DOCUMENTATION_IMPLEMENTATION_PLAN.md)

**1. Brevity**
- No unnecessary words
- Get straight to the point
- Eliminate fluff and filler

**2. Conciseness**
- Each section has a clear, singular purpose
- No redundancy between sections
- Remove duplicate information

**3. Accuracy**
- All technical details verified against implementation
- Code examples tested and runnable
- Links point to existing, correct resources
- Patterns match actual codebase

**4. Transferability**
- Templates and patterns reusable for similar projects
- Document the "why" not just the "what"
- Provide context for decisions

###

 Solo Developer Workflow

**Efficient Documentation Practices:**
- **Update docs during development**, not after (memory is fresh)
- **Use templates** (consistency without thinking)
- **Link liberally** (let readers navigate, don't repeat)
- **Automate validation** (broken link checkers, spell checkers)
- **Document decisions** (future you will forget why)

**When to Skip:**
- Obvious changes (typo fixes, formatting)
- Experimental/throwaway code
- Internal refactoring that doesn't change behavior

---

## File Organization

### Directory Structure

```
docs/
├── README.md                          # Master navigation hub
│
├── User Documentation (Getting Started)
│   ├── installation-guide.md
│   ├── usage-guide.md
│   └── quick-start-tutorial.md
│
├── Security Headers (Reference)
│   └── headers/
│       ├── README.md                  # Header index
│       ├── hsts.md                    # 15 individual header guides
│       ├── csp.md
│       └── ...
│
├── Architecture (Design & Patterns)
│   └── architecture/
│       ├── README.md                  # Architecture index
│       ├── system-design.md
│       ├── data-flow.md
│       ├── components.md
│       ├── registry-pattern.md
│       ├── extensibility-guide.md
│       ├── security-implementation.md
│       └── future-roadmap.md
│
├── Advanced Topics
│   ├── real-world-attack-scenarios.md
│   ├── deployment-guide.md
│   └── testing-guide.md
│
├── Reference
│   ├── api-reference.md
│   └── analyzer-reference.md
│
└── Repository Rules (THIS DIRECTORY)
    └── repo-rules/
        ├── README.md
        ├── python-code-standards.md
        ├── git-practices.md
        ├── testing-standards.md
        ├── debugging-practices.md
        ├── documentation-standards.md  # ← YOU ARE HERE
        └── security-headers-best-practices.md
```

### Navigation Hubs

**Purpose:** Central indexes that organize related documentation

**Required Hubs:**
1. **`docs/README.md`** - Master index (role-based: User, Developer, Security Engineer)
2. **`docs/headers/README.md`** - Header documentation index (severity-based)
3. **`docs/architecture/README.md`** - Architecture documentation index
4. **`docs/repo-rules/README.md`** - Repository standards index

**Hub Characteristics:**
- Quick links at top
- Organized by role or topic
- Brief descriptions (1 line per link)
- ASCII directory tree
- External resource links

---

## Documentation Types

### 1. Header Documentation (Template)

**Location:** `docs/headers/<header-name>.md`

**Length:** 150-250 lines

**Template Structure:**
```markdown
# [Header Name] Security Header

## Quick Reference
- **Header:** [Full header name]
- **Purpose:** [One-sentence purpose]
- **Severity if Missing:** [Critical/High/Medium/Low]
- **Implementation Complexity:** [Easy/Medium/Hard]

**Best Practice:**
```
[Code block with recommended configuration]
```

## What It Does
[2-3 paragraphs explaining purpose in plain English]

## How It Works
[Technical explanation with directive/syntax details]
[3-4 paragraphs covering key concepts]

## Real-World Attack Scenarios

### Attack 1: [Attack Name]
**Without Header:**
[Description of vulnerability and exploitation]

**With Header:**
[How the header prevents the attack]

**Example:**
```
[Code example showing before/after]
```

### Attack 2: [Attack Name]
[Same structure]

## Configuration Examples

### ✅ Good Configuration
```
[Best practice example]
```
**Why:** [Explanation]

### ⚠️ Acceptable Configuration
```
[Acceptable example with trade-offs]
```
**Why:** [Explanation of trade-offs]

### ❌ Bad Configuration
```
[Common mistake]
```
**Why:** [Explanation of why it's bad]

## Common Mistakes
1. **[Mistake 1]** - [How to fix]
2. **[Mistake 2]** - [How to fix]
3. **[Mistake 3]** - [How to fix]

## Implementation Guide

### Framework-Specific Instructions
**Express.js:**
```javascript
[Code example]
```

**Django:**
```python
[Code example]
```

**NGINX:**
```nginx
[Code example]
```

### Testing Your Configuration
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Monitoring
- [What to monitor]
- [How to detect issues]

## Browser Compatibility
| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | XX+     | Full    |
| Firefox | XX+     | Full    |
| Safari  | XX+     | Full    |
| Edge    | XX+     | Full    |

## Additional Resources
- [MDN: Header Name](URL)
- [OWASP: Header Name](URL)
- [RFC XXXX: Specification](URL)

**Related Headers:**
- [Related Header 1](../headers/related1.md)
- [Related Header 2](../headers/related2.md)

**See Also:**
- [Attack Scenarios](../real-world-attack-scenarios.md#relevant-section)
- [Best Practices](../repo-rules/security-headers-best-practices.md#section)
- [Analyzer Implementation](../../sha/analyzers/header_name.py)
```

**Key Characteristics:**
- Progressive disclosure (quick ref → details → examples)
- Attack scenarios make it practical
- Multiple configuration examples (good/acceptable/bad)
- Cross-links to related content
- Framework-specific examples

---

### 2. Architecture Documentation (Pattern)

**Location:** `docs/architecture/<topic>.md`

**Length:** 100-200 lines per file

**Patterns:**
- High-level diagrams (ASCII art)
- Component responsibilities clearly defined
- Design pattern explanations with rationale
- Cross-references to actual code files (with line numbers when relevant)
- Sequence diagrams for complex flows

**Example Structure (from system-design.md):**
```markdown
# System Design

## High-Level Architecture
[ASCII diagram showing layers]

## Layer Responsibilities

### CLI Layer (main.py)
**Purpose:** [Purpose]
**Responsibilities:**
- [Responsibility 1]
- [Responsibility 2]

**Implementation:** [sha/main.py](../../sha/main.py)

### [Other layers...]

## Design Patterns Used

### Registry Pattern
**Why:** [Rationale]
**Where:** [sha/analyzers/__init__.py](../../sha/analyzers/__init__.py)
**See Also:** [registry-pattern.md](registry-pattern.md)
```

---

### 3. Python Docstring Standards

**Location:** Top of every `.py` file

**Template:**
```python
"""
[Module Name] - [One-line description]

Module: [full.module.path]

Purpose:
    [2-3 sentences: WHAT this module does and WHY it exists]

Overview:
    [4-6 sentences: architectural context, design decisions, how it fits
    in the system]

Key Functions/Classes:
    - function_name(arg1: Type1, arg2: Type2) -> ReturnType
      [Brief description of what it does and when to use it]

    - ClassName
      [Brief description of the class purpose]

[OPTIONAL SECTIONS - Include if relevant:]

Security Considerations:
    [Only if module handles security-critical operations]
    - [Consideration 1]
    - [Consideration 2]

Configuration:
    [Only if module has configuration requirements]
    - [Config item 1]
    - [Config item 2]

Related Modules:
    - sha.module_name - [How it's related]
    - sha.another_module - [How it's related]

Example Usage:
    >>> from sha.module import function
    >>> result = function(param)
    >>> print(result)
    Expected output

See Also:
    - docs/architecture/SECTION.md - [Brief description]
    - docs/headers/HEADER.md - [Brief description]
    - Related code references
"""
```

**Function Docstrings:**
```python
def analyze(value: Optional[str]) -> Finding:
    """
    [One-line summary of what function does]

    [Optional: Extended description if needed, 2-3 sentences max]

    Args:
        value: [Description of parameter]

    Returns:
        [Description of return value with structure if complex]
        Example for dict returns:
        {
            "key1": str,    # Description
            "key2": int,    # Description
        }

    Raises:
        ExceptionType: [When this is raised]

    Example:
        >>> analyze("max-age=31536000")
        {"status": "good", ...}

    Notes:
        - [Important note 1]
        - [Important note 2]

    See Also:
        - [Related function or doc]
    """
```

---

### 4. API Reference Documentation

**Location:** `docs/api-reference.md`

**Structure:**
- Module-by-module breakdown
- All public functions documented
- Type signatures included
- Usage examples for each function
- Links to related architecture docs

---

## Cross-Linking Strategy

### Bidirectional Linking Rules

**Rule 1:** Every documentation file should link to related content
**Rule 2:** Navigation hubs should link to all subordinate files
**Rule 3:** Specialized docs should link back to navigation hubs

### Link Types

**1. Python Docstring → Markdown Docs:**
```python
See Also:
    - docs/architecture/components.md#analyzer-layer
    - docs/headers/hsts.md
```

**2. Markdown → Python Code:**
```markdown
**Implementation:** [sha/analyzers/hsts.py](../../sha/analyzers/hsts.py)
**Tests:** [tests/analyzers/test_hsts.py](../../tests/analyzers/test_hsts.py)
```

**3. Markdown → Markdown (Relative Paths):**
```markdown
See also: [Architecture Overview](../architecture/README.md)
Related: [Testing Standards](testing-standards.md)
```

**4. Code Line References (When Useful):**
```markdown
The registry is defined at [sha/analyzers/__init__.py#L15-L30](../../sha/analyzers/__init__.py#L15-L30)
```

### Cross-Reference Checklist

For **every new/updated documentation file**:
- [ ] Links to related headers (for header docs)
- [ ] Links to architecture docs (for implementation guides)
- [ ] Links to code files (for technical docs)
- [ ] Links from navigation hubs updated
- [ ] Backlinks from related docs added

---

## Updating Documentation

### When Code Changes

**Required Updates:**

| Code Change | Documentation Updates Required |
|-------------|-------------------------------|
| New analyzer added | 1. Header doc in `docs/headers/`<br>2. Update `docs/headers/README.md`<br>3. Update `docs/analyzer-reference.md`<br>4. Module docstring in analyzer file<br>5. Update summary table in `docs/repo-rules/security-headers-best-practices.md` |
| Analyzer enhanced | 1. Update header doc with new features<br>2. Update analyzer-reference.md<br>3. Update module docstring<br>4. Add examples in docs |
| API changed | 1. Update api-reference.md<br>2. Update related code examples<br>3. Update function docstrings<br>4. Update usage-guide.md if user-facing |
| Architecture changed | 1. Update architecture docs<br>2. Update system diagrams<br>3. Update component descriptions |

### Documentation Update Workflow (Solo Developer)

**During Development:**
1. Update module docstrings as you write code
2. Note documentation TODOs in comments: `# DOC: Need to update headers/csp.md`
3. Update related markdown files before committing

**Before Commit:**
1. Review changed files for documentation impact
2. Update affected markdown files
3. Verify links still work
4. Run spell checker if available

**Sprint Completion (Multi-Step Features):**
1. Review all documentation touched during sprint
2. Ensure consistency across related docs
3. Update navigation hubs if new files added
4. Create summary of changes for CHANGELOG.md

---

## Quality Checklist

### For All Documentation

**Content Quality:**
- [ ] Clear, concise language (no jargon without explanation)
- [ ] Accurate technical details (verified against code)
- [ ] Examples are tested and work
- [ ] No spelling or grammar errors
- [ ] Follows Brevity/Conciseness/Accuracy principles

**Structure Quality:**
- [ ] Consistent formatting (headers, code blocks, lists)
- [ ] Logical flow (simple → complex)
- [ ] Appropriate length (not too long, not too short)
- [ ] Sections have clear purposes

**Navigation Quality:**
- [ ] All links work (no 404s)
- [ ] Cross-references are bidirectional
- [ ] Related content is linked
- [ ] Navigation hub updated

**Technical Quality:**
- [ ] Code examples use correct syntax
- [ ] Type annotations match implementation
- [ ] Security considerations noted where relevant
- [ ] Deprecated features marked clearly

---

## Enhancement Documentation (from ENHANCEMENT_PLAN.md)

### Sprint-Based Tracking

**Pattern from 5 Completed Sprints:**

When implementing multi-step enhancements, document:

**1. Current State Assessment**
```markdown
### Current State: [Analyzer Name]
**Quality Rating:** X/10
**Characteristics:**
- [Strength 1]
- [Limitation 1]
- [Limitation 2]
```

**2. Enhancement Objectives**
```markdown
### Enhancement Goals
- [Goal 1 with rationale]
- [Goal 2 with rationale]
- [Goal 3 with rationale]

**Target Quality:** Y/10
**Impact:** [High/Medium/Low] - [Why]
```

**3. Implementation Tracking**
```markdown
### Sprint N: [Feature Name] ✅ COMPLETED (YYYY-MM-DD)

**Deliverables:**
- ✅ [Deliverable 1]
- ✅ [Deliverable 2]
- ✅ [Deliverable 3]

**Files Modified:**
- `path/to/file1.py` - [What changed]
- `path/to/file2.py` - [What changed]
- `docs/file.md` - [What changed]

**Quality Improvement:** X/10 → Y/10 ⭐

**Tests Added:** N comprehensive tests (100% coverage)

**Key Features:**
- [Feature 1 description]
- [Feature 2 description]
```

**4. Quality Metrics**

Track before/after ratings:
- CSP: 9/10 → 10/10 ✅ (bypass detection added)
- Set-Cookie: 8/10 → 9/10 ✅ (prefix validation added)
- Cache-Control: 6/10 → 8/10 ✅ (conflict detection added)
- COEP/COOP/CORP: 4/10 → 7/10 ✅ (cross-header validation added)
- Permissions-Policy: 7/10 → 8/10 ✅ (risk categorization added)

---

## Deprecated Files Management

### When to Archive vs Delete

**Delete:**
- Planning files after completion (e.g., ENHANCEMENT_PLAN.md, DOCUMENTATION_IMPLEMENTATION_PLAN.md)
- Temporary TODO files
- Draft files that were superseded
- Files with no historical value

**Archive (Move to `docs/archive/` or similar):**
- Design decisions that might be revisited
- Research documents with useful context
- Old specifications that explain evolution
- Rejected approaches with valuable rationale

**Keep in Current Location:**
- Active documentation
- Reference materials
- Standards and guidelines
- User-facing guides

### Extracting Knowledge Before Deletion

**Pattern:** Before deleting planning files, extract:
1. **Methodologies** (how work was organized)
2. **Templates** (reusable patterns)
3. **Lessons Learned** (what worked/didn't work)
4. **Quality Standards** (metrics, checklists)

**Integration:** Merge extracted knowledge into permanent docs:
- Methodologies → `git-practices.md`, `documentation-standards.md`
- Templates → This file, `python-code-standards.md`
- Lessons Learned → Architecture docs, README notes
- Quality Standards → `testing-standards.md`, quality checklists

---

## Documentation Workflow for Solo Developers

### Efficient Practices

**1. Template-Driven Development**
- Use templates from this file (copy/paste, fill in)
- Don't reinvent structure for each doc
- Consistency is automatic

**2. Just-In-Time Documentation**
- Document as you code (context is fresh)
- Don't batch documentation for later (you'll forget)
- Quick notes now > perfect docs never

**3. Link-First Approach**
- Link to existing docs instead of repeating
- Trust readers to navigate
- Reduces maintenance burden

**4. Automation**
- Use spell checker: `codespell docs/`
- Link checker: `markdown-link-check docs/**/*.md`
- Format checker: `markdownlint docs/`
- Pre-commit hooks catch issues early

**5. Progressive Enhancement**
- Start with minimal docs (purpose, usage, examples)
- Add details as questions arise
- Don't over-document simple code

### Time-Saving Shortcuts

**Quick Documentation Wins:**
- One-line module docstrings initially, expand later
- Link to external resources (MDN, OWASP) instead of explaining basics
- Use "See Also" sections liberally (let readers explore)
- Example code > paragraphs of explanation

**When to Skip Documentation:**
- Internal implementation details (unless complex)
- Obvious utility functions
- Test helper functions
- Temporary/experimental code

---

## Key Learnings from Enhancement Plans

### Sprint-Based Organization (from ENHANCEMENT_PLAN.md)

**Methodology:**
1. Assess current state (quality rating X/10)
2. Define enhancement goals with impact justification
3. Track implementation with file-level changes
4. Measure improvement (quality rating Y/10)
5. Document in CHANGELOG.md

**Benefits:**
- Clear progress tracking
- Before/after comparison
- Focused scope per sprint
- Measurable outcomes

### Template Consistency (from DOCUMENTATION_IMPLEMENTATION_PLAN.md)

**Key Insight:** Consistent templates reduce cognitive load

**Templates Created:**
- Header documentation (15 headers, same structure)
- Python module docstrings (23 modules, same sections)
- Architecture docs (8 files, consistent style)

**Result:** Readers know exactly where to find information

---

## Validation Tools

### Automated Checks

**Spell Checking:**
```bash
# Using codespell
codespell docs/ sha/ --skip="*.pyc,*.git"
```

**Link Validation:**
```bash
# Check markdown links
find docs -name "*.md" -exec markdown-link-check {} \;
```

**Markdown Linting:**
```bash
# Using markdownlint
markdownlint docs/**/*.md --config .markdownlint.json
```

**Documentation Coverage:**
```bash
# Using interrogate (Python docstrings)
interrogate sha/ --verbose
```

### Manual Review Checklist

Before committing documentation changes:
- [ ] Read through docs as if you're a new user
- [ ] Click all links to verify they work
- [ ] Run code examples to ensure they execute
- [ ] Check that diagrams/ASCII art render correctly
- [ ] Verify cross-references are bidirectional
- [ ] Ensure new content matches existing style

---

## Documentation Principles in Action

### Brevity Example

**❌ Verbose:**
> "The HSTS analyzer is responsible for analyzing and validating the Strict-Transport-Security header. It takes the header value as input and returns a finding dictionary containing information about whether the header is configured correctly or not."

**✅ Brief:**
> "Analyzes Strict-Transport-Security headers and returns validation findings."

### Conciseness Example

**❌ Redundant:**
> "The module provides a function called `analyze()` which analyzes the header. This analyze function is the main function of the module."

**✅ Concise:**
> "The `analyze()` function validates the header value."

### Accuracy Example

**❌ Inaccurate:**
> "The function returns a dictionary with status, severity, and message."

**✅ Accurate:**
> "Returns a Finding dictionary with 7 required keys: `header_name`, `status`, `severity`, `message`, `actual_value`, `recommendation`, and `analysis_details`."

---

## Summary

This documentation standards guide ensures:
- ✅ Consistent structure across all documentation
- ✅ Efficient solo developer workflow
- ✅ Knowledge preservation (extracted from planning files)
- ✅ Clear quality standards (Brevity, Conciseness, Accuracy)
- ✅ Bidirectional cross-linking
- ✅ Template-driven documentation
- ✅ Automation-friendly validation

**Remember:** Good documentation is maintained documentation. Keep it updated, keep it linked, keep it concise.

---

**Last Updated:** 2026-01-01
**Extracted Knowledge From:** ENHANCEMENT_PLAN.md, DOCUMENTATION_IMPLEMENTATION_PLAN.md (now deprecated)
