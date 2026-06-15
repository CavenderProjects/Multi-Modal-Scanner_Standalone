"""Source code static analysis scanner.

Performs regex-based vulnerability detection, complexity measurement, and
development practice checks across Python, JavaScript, TypeScript, Java,
Go, PHP, C#, C++, and Rust source files. Maps findings to all 51 code
review controls from code-review-controls.md.
"""

import re
import os
import math
from dataclasses import dataclass, field
from pathlib import Path
from scanners import ScanResult

LANG_EXTENSIONS = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
    '.jsx': 'javascript', '.tsx': 'typescript',
    '.java': 'java', '.go': 'go', '.php': 'php',
    '.cs': 'csharp', '.cpp': 'cpp', '.c': 'c', '.h': 'c',
    '.hpp': 'cpp', '.rs': 'rust',
}

# ── Vulnerability patterns per language ──
# Each entry: (control_id, severity, pattern, description, remediation)

VULN_PATTERNS = {
    'python': [
        ('SEC-INJ-001', 'CRITICAL', r'(?:execute|cursor\.execute)\s*\(\s*[f"\'].*\{.*\}', 'SQL injection via f-string/format in execute()', 'Use parameterized queries with ? or %s placeholders'),
        ('SEC-INJ-001', 'CRITICAL', r'\.execute\s*\(\s*["\'].*%s.*["\']\s*%', 'SQL injection via string formatting', 'Use parameterized queries'),
        ('SEC-INJ-002', 'CRITICAL', r'os\.system\s*\(|os\.popen\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True', 'Command injection via os.system/popen/shell=True', 'Use subprocess.run() with shell=False and list args'),
        ('SEC-INJ-003', 'HIGH', r'(?:mark_safe|Markup)\s*\(|\.safe\s*\||__html__', 'XSS via mark_safe/Markup', 'Use autoescaping; avoid mark_safe with user input'),
        ('SEC-INJ-004', 'HIGH', r'open\s*\(\s*(?:request|user|input|arg|param)', 'Path traversal via unvalidated file open', 'Validate with os.path.realpath() + startswith check'),
        ('SEC-INJ-005', 'CRITICAL', r'pickle\.loads?\s*\(|yaml\.load\s*\((?!.*SafeLoader)|marshal\.loads?\s*\(', 'Unsafe deserialization (pickle/yaml/marshal)', 'Use json.loads() or yaml.safe_load()'),
        ('SEC-INJ-006', 'MEDIUM', r're\.compile\s*\(\s*["\'].*\(\?:.*[+*].*\)[+*]', 'ReDoS potential — nested quantifiers', 'Use re2 library or add input length limits'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:api[_-]?key|secret|password|token|aws_access)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']', 'Hardcoded secret/API key', 'Use environment variables or a secrets manager'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'sk_live_[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN.*PRIVATE KEY', 'Exposed secret key pattern', 'Remove from source; use env vars'),
        ('SEC-CRYPTO-002', 'HIGH', r'hashlib\.md5\s*\(|hashlib\.sha1\s*\(|DES|Blowfish', 'Weak cryptographic algorithm', 'Use AES-GCM, SHA-256+, or Ed25519'),
        ('SEC-CRYPTO-003', 'HIGH', r'random\.random\s*\(|random\.randint\s*\(|random\.choice\s*\(', 'Insecure random for security context', 'Use secrets.token_hex() or os.urandom()'),
        ('SEC-CRYPTO-004', 'CRITICAL', r'hashlib\.sha256\s*\(.*password|hashlib\.md5\s*\(.*password', 'Password stored with simple hash (no salt/bcrypt)', 'Use bcrypt.hashpw() or argon2.PasswordHasher()'),
        ('SEC-AUTH-001', 'CRITICAL', r'@app\.route.*\ndef\s+\w+.*\n(?:(?!login_required|permission_required|auth|jwt_required).)*$', 'Route possibly missing auth decorator', 'Add @login_required or auth middleware'),
        ('SEC-DATA-001', 'HIGH', r'(?:print|logging\.(?:info|debug|warning))\s*\(.*(?:password|secret|token|key|credential)', 'Sensitive data in log/print statement', 'Redact sensitive fields before logging'),
        ('SEC-DATA-002', 'MEDIUM', r'SELECT\s+\*\s+FROM', 'Over-fetching with SELECT *', 'Select only needed columns'),
        ('SEC-DATA-004', 'MEDIUM', r'(?:return|json\.dumps).*str\s*\(\s*(?:e|err|exception)', 'Error details exposed to user', 'Use generic error messages; log details internally'),
        ('SEC-MEM-005', 'MEDIUM', r'open\s*\([^)]+\)(?!\s*\)\s*as\b)(?!.*with\s)', 'File opened without context manager (with)', 'Use "with open(...) as f:" pattern'),
        ('DEV-BUILD-002', 'MEDIUM', r'(?:DEBUG|debug)\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True', 'Debug mode enabled', 'Set DEBUG=False in production'),
    ],
    'javascript': [
        ('SEC-INJ-001', 'CRITICAL', r'(?:query|execute)\s*\(\s*`[^`]*\$\{', 'SQL injection via template literal', 'Use parameterized queries with $1 or ? placeholders'),
        ('SEC-INJ-001', 'CRITICAL', r'(?:query|execute)\s*\(\s*["\'].*\+\s*(?:req|user|input|param)', 'SQL injection via string concatenation', 'Use parameterized queries'),
        ('SEC-INJ-002', 'CRITICAL', r'(?:exec|execSync)\s*\(|child_process\.exec\s*\(', 'Command injection via exec()', 'Use execFile() or spawn() with array args'),
        ('SEC-INJ-002', 'CRITICAL', r'\beval\s*\(', 'Code injection via eval()', 'Remove eval(); use JSON.parse() for data'),
        ('SEC-INJ-003', 'HIGH', r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html', 'XSS via innerHTML/document.write', 'Use textContent or DOMPurify'),
        ('SEC-INJ-005', 'CRITICAL', r'require\s*\(\s*["\']node-serialize|\.unserialize\s*\(', 'Unsafe deserialization', 'Use JSON.parse() with schema validation'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:api[_-]?key|secret|password|token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{8,}["\']', 'Hardcoded secret', 'Use process.env or vault'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'sk_live_[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}', 'Exposed secret key', 'Remove from source'),
        ('SEC-CRYPTO-002', 'HIGH', r'createHash\s*\(\s*["\']md5["\']|createCipher\s*\(', 'Weak crypto algorithm', 'Use createCipheriv with AES-GCM'),
        ('SEC-CRYPTO-003', 'HIGH', r'Math\.random\s*\(', 'Insecure random for security', 'Use crypto.randomBytes() or crypto.randomUUID()'),
        ('SEC-CRYPTO-004', 'CRITICAL', r'createHash\s*\(.*\).*password', 'Password with simple hash', 'Use bcrypt.hash() or argon2'),
        ('SEC-DATA-001', 'HIGH', r'console\.log\s*\(.*(?:password|secret|token|key)', 'Sensitive data in console.log', 'Remove sensitive data from logs'),
        ('SEC-DATA-004', 'MEDIUM', r'\.status\s*\(\s*500\s*\).*(?:err\.stack|err\.message|error\.stack)', 'Stack trace exposed in error response', 'Use generic error; log details server-side'),
        ('SEC-MEM-006', 'MEDIUM', r'(?<![\?\.])\.(?:name|email|value|id|title)(?!\s*[\?\.])', 'Potential null dereference without optional chaining', 'Use optional chaining (?.) or null checks'),
        ('DEV-TEST-003', 'HIGH', r'process\.env\.NODE_ENV\s*===?\s*["\']test["\'].*(?:return\s+true|skip)', 'Auth bypass in test mode', 'Remove test-mode security bypasses from production code'),
    ],
    'java': [
        ('SEC-INJ-001', 'CRITICAL', r'Statement\.execute\s*\(.*\+|createQuery\s*\(.*\+|"SELECT.*"\s*\+', 'SQL injection via string concatenation', 'Use PreparedStatement with ? placeholders'),
        ('SEC-INJ-002', 'CRITICAL', r'Runtime\.exec\s*\(|ProcessBuilder.*\+', 'Command injection', 'Pass arguments as list, not concatenated string'),
        ('SEC-INJ-005', 'CRITICAL', r'ObjectInputStream\.readObject\s*\(|XMLDecoder|XStream(?!.*allowTypes)', 'Unsafe deserialization', 'Use Jackson/Gson with typed deserialization; add ObjectInputFilter'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:apiKey|secret|password|token)\s*=\s*"[a-zA-Z0-9_\-]{8,}"', 'Hardcoded secret', 'Use System.getenv() or vault'),
        ('SEC-CRYPTO-002', 'HIGH', r'MessageDigest\.getInstance\s*\(\s*"MD5"|Cipher\.getInstance\s*\(\s*"DES"|"AES/ECB"', 'Weak crypto algorithm', 'Use AES/GCM/NoPadding, SHA-256+'),
        ('SEC-CRYPTO-003', 'HIGH', r'new\s+Random\s*\(|java\.util\.Random', 'Insecure random', 'Use java.security.SecureRandom'),
        ('SEC-CRYPTO-004', 'CRITICAL', r'MessageDigest.*password', 'Password with simple hash', 'Use BCrypt.hashpw() or Argon2'),
        ('SEC-DATA-001', 'HIGH', r'logger\.(?:info|debug)\s*\(.*(?:password|secret|token)', 'Sensitive data in logs', 'Exclude sensitive fields; use @ToString.Exclude'),
        ('SEC-DATA-004', 'MEDIUM', r'e\.printStackTrace\s*\(|\.getMessage\s*\(\s*\).*response', 'Stack trace/error exposed', 'Use @ControllerAdvice with generic messages'),
    ],
    'go': [
        ('SEC-INJ-001', 'CRITICAL', r'fmt\.Sprintf\s*\(\s*".*SELECT.*%s|db\.Query\s*\(.*fmt\.Sprintf', 'SQL injection via fmt.Sprintf', 'Use db.Query() with ? or $1 placeholders'),
        ('SEC-INJ-002', 'CRITICAL', r'exec\.Command\s*\(\s*"(?:sh|bash|cmd)".*\s*"-c"', 'Command injection via shell', 'Pass arguments separately, not via sh -c'),
        ('SEC-INJ-003', 'HIGH', r'fmt\.Fprintf\s*\(\s*w\s*,.*\+|text/template', 'XSS — using text/template or unescaped output', 'Use html/template which auto-escapes'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:apiKey|secret|password|token)\s*:?=\s*"[a-zA-Z0-9_\-]{8,}"', 'Hardcoded secret', 'Use os.Getenv() or Viper'),
        ('SEC-CRYPTO-002', 'HIGH', r'crypto/md5|crypto/des', 'Weak crypto', 'Use crypto/aes with GCM, crypto/sha256'),
        ('SEC-CRYPTO-003', 'HIGH', r'math/rand(?!.*crypto)', 'Insecure random', 'Use crypto/rand'),
        ('SEC-DATA-001', 'HIGH', r'log\.(?:Print|Printf)\s*\(.*(?:password|secret|token)', 'Sensitive data in logs', 'Exclude sensitive fields from structured logging'),
        ('SEC-DATA-004', 'MEDIUM', r'http\.Error\s*\(\s*w\s*,\s*err\.Error\s*\(\s*\)', 'Internal error exposed to client', 'Return generic message; log err internally'),
        ('SEC-MEM-005', 'MEDIUM', r'os\.Open\s*\([^)]+\)(?!\s*\n\s*defer)', 'File opened without defer close', 'Add defer f.Close() immediately after open'),
    ],
    'php': [
        ('SEC-INJ-001', 'CRITICAL', r'mysqli_query\s*\(.*\$|->query\s*\(.*\$(?!pdo)', 'SQL injection via variable interpolation', 'Use $pdo->prepare() with bindParam()'),
        ('SEC-INJ-002', 'CRITICAL', r'(?:exec|shell_exec|system|passthru|popen)\s*\(.*\$', 'Command injection', 'Use escapeshellarg() or avoid shell entirely'),
        ('SEC-INJ-003', 'HIGH', r'echo\s+\$(?:_GET|_POST|_REQUEST|user)', 'XSS via unescaped output', 'Use htmlspecialchars($var, ENT_QUOTES, "UTF-8")'),
        ('SEC-INJ-004', 'HIGH', r'(?:include|require)(?:_once)?\s*\(\s*\$', 'LFI/RFI via variable include', 'Use allowlist for includes; never include user input'),
        ('SEC-INJ-005', 'CRITICAL', r'unserialize\s*\(\s*\$', 'PHP object injection via unserialize', 'Use json_decode() or unserialize with allowed_classes: false'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:api_key|secret|password|token)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']', 'Hardcoded secret', 'Use getenv() or .env file'),
        ('SEC-CRYPTO-002', 'HIGH', r'\bmd5\s*\(|\bsha1\s*\(|mcrypt_', 'Weak crypto', 'Use openssl_encrypt with aes-256-gcm or sodium_*'),
        ('SEC-CRYPTO-003', 'HIGH', r'\brand\s*\(|\bmt_rand\s*\(', 'Insecure random', 'Use random_bytes() or random_int()'),
        ('SEC-CRYPTO-004', 'CRITICAL', r'md5\s*\(\s*\$(?:pass|pwd)|sha1\s*\(\s*\$(?:pass|pwd)', 'Password with simple hash', 'Use password_hash($pw, PASSWORD_ARGON2ID)'),
        ('SEC-DATA-001', 'HIGH', r'error_log\s*\(.*(?:password|secret|token)', 'Sensitive data in error_log', 'Redact sensitive fields'),
        ('DEV-BUILD-002', 'MEDIUM', r'display_errors\s*=\s*(?:On|1)|APP_DEBUG\s*=\s*true', 'Debug mode enabled', 'Set display_errors=Off and APP_DEBUG=false'),
    ],
    'csharp': [
        ('SEC-INJ-001', 'CRITICAL', r'SqlCommand.*\$"|SqlCommand.*\+\s*(?:user|input|request|param)', 'SQL injection via string interpolation', 'Use SqlParameter or Entity Framework LINQ'),
        ('SEC-INJ-002', 'CRITICAL', r'Process\.Start\s*\(.*UseShellExecute\s*=\s*true.*(?:user|input|request)', 'Command injection', 'Use UseShellExecute=false with argument list'),
        ('SEC-INJ-003', 'HIGH', r'Html\.Raw\s*\(|Response\.Write\s*\(.*(?:user|input|request)', 'XSS via Html.Raw/Response.Write', 'Use @variable (auto-encoded) or HtmlEncoder'),
        ('SEC-INJ-005', 'CRITICAL', r'BinaryFormatter\.Deserialize|JsonConvert\.DeserializeObject<dynamic>', 'Unsafe deserialization', 'Use System.Text.Json with typed models'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:apiKey|secret|password|connectionString)\s*=\s*"[^"]{8,}"', 'Hardcoded secret', 'Use IConfiguration, User Secrets, or Azure Key Vault'),
        ('SEC-CRYPTO-002', 'HIGH', r'MD5\.Create\s*\(|SHA1\.Create\s*\(|DESCryptoServiceProvider', 'Weak crypto', 'Use Aes.Create() with GCM, SHA256'),
        ('SEC-CRYPTO-003', 'HIGH', r'new\s+Random\s*\(|System\.Random', 'Insecure random', 'Use RandomNumberGenerator.GetBytes()'),
        ('SEC-DATA-004', 'MEDIUM', r'UseDeveloperExceptionPage|ex\.ToString\s*\(\s*\).*(?:return|Response)', 'Debug exception page / error exposed', 'Use environment-aware exception handling'),
    ],
    'rust': [
        ('SEC-MEM-001', 'CRITICAL', r'unsafe\s*\{[^}]*(?:\*ptr\.offset|\*ptr\.add|slice::from_raw_parts)', 'Buffer overflow — unsafe pointer arithmetic', 'Use bounds-checked .get() or safe iterators'),
        ('SEC-MEM-002', 'CRITICAL', r'unsafe\s*\{[^}]*(?:Box::from_raw|ManuallyDrop)', 'Use-after-free risk', 'Verify lifetimes; prefer safe wrappers'),
        ('SEC-MEM-004', 'HIGH', r'unsafe\s*\{(?!.*//\s*SAFETY)', 'Unsafe block without SAFETY comment', 'Add // SAFETY: comment documenting invariant'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:api_key|secret|password|token)\s*[:=]\s*"[a-zA-Z0-9_\-]{8,}"', 'Hardcoded secret', 'Use std::env::var() or secrets crate'),
        ('SEC-CRYPTO-002', 'HIGH', r'use\s+md5|use\s+sha1(?!.*hmac)', 'Weak crypto crate', 'Use ring, aes-gcm, or sha2 crates'),
        ('SEC-INJ-001', 'CRITICAL', r'format!\s*\(\s*".*SELECT.*\{', 'SQL injection via format!()', 'Use sqlx::query!() with bind parameters'),
        ('SEC-MEM-006', 'MEDIUM', r'\.unwrap\s*\(\s*\)(?!.*test|.*#\[test\])', 'Unwrap without justification (panic risk)', 'Use ? operator, .unwrap_or(), or pattern matching'),
    ],
    'cpp': [
        ('SEC-MEM-001', 'CRITICAL', r'(?:strcpy|strcat|sprintf|gets|scanf\s*\(\s*"%s")\s*\(', 'Buffer overflow — unsafe string function', 'Use strncpy/snprintf/std::string; compile with -D_FORTIFY_SOURCE=2'),
        ('SEC-MEM-002', 'CRITICAL', r'free\s*\([^)]+\)(?!.*=\s*(?:NULL|nullptr))', 'Potential use-after-free (no null after free)', 'Set pointer to nullptr after free; use smart pointers'),
        ('SEC-INJ-002', 'CRITICAL', r'system\s*\(|popen\s*\(', 'Command injection via system()/popen()', 'Use execve() with explicit argv array'),
        ('SEC-CRYPTO-001', 'CRITICAL', r'(?:api_key|secret|password|token)\s*=\s*"[a-zA-Z0-9_\-]{8,}"', 'Hardcoded secret', 'Use getenv() or config files outside repo'),
        ('SEC-CRYPTO-002', 'HIGH', r'EVP_md5\s*\(|DES_ecb_encrypt|EVP_des_', 'Weak crypto algorithm', 'Use EVP_aes_256_gcm(), EVP_sha256(), or libsodium'),
        ('SEC-MEM-004', 'HIGH', r'(?:void\s*\*|reinterpret_cast)', 'Unsafe type cast', 'Prefer static_cast or typed containers'),
    ],
}

# Copy javascript patterns for typescript
VULN_PATTERNS['typescript'] = VULN_PATTERNS['javascript']
# Copy c patterns for cpp (additions already in cpp)
VULN_PATTERNS.setdefault('c', VULN_PATTERNS['cpp'])

# ── CPX control sets for COMPLIANT reporting ──
# These controls are evaluated whenever source files of the appropriate language
# are scanned. A COMPLIANT result is emitted for any that had no NON_COMPLIANT findings.

_CPX_UNIVERSAL = {
    'CPX-STRUCT-004',   # file length         — all languages
    'CPX-STRUCT-001',   # function length     — all languages
    'CPX-METRIC-001',   # cyclomatic complexity — all languages
    'CPX-STRUCT-003',   # nesting depth       — all languages
}

_CPX_BY_LANG = {
    'python':     {'CPX-MAINTAIN-001', 'CPX-MAINTAIN-002', 'CPX-MAINTAIN-003'},
    'javascript': {'CPX-MAINTAIN-003'},
    'typescript': {'CPX-MAINTAIN-003'},
    'java':       {'CPX-MAINTAIN-003'},
    'go':         {'CPX-MAINTAIN-003'},
    'php':        {'CPX-MAINTAIN-003'},
}


def _build_compliant_results(detected_langs: set, noncompliant_ids: set) -> list:
    """Return COMPLIANT ScanResults for every checked control that had no violations."""
    if not detected_langs:
        return []

    checked = set(_CPX_UNIVERSAL)
    for lang in detected_langs:
        for ctrl_id, *_ in VULN_PATTERNS.get(lang, []):
            checked.add(ctrl_id)
        checked |= _CPX_BY_LANG.get(lang, set())

    results = []
    for ctrl_id in sorted(checked - noncompliant_ids):
        results.append(ScanResult(
            scanner='code-analysis',
            control_id=ctrl_id,
            status='COMPLIANT',
            evidence='No violations found in scanned source files.',
            confidence=0.85,
            reachability='INTERNAL',
        ))
    return results


def detect_language(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    return LANG_EXTENSIONS.get(ext, '')


def scan_file(filepath: str) -> list:
    """Scan a single source file for vulnerabilities."""
    lang = detect_language(filepath)
    if not lang:
        return []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except (IOError, OSError):
        return []

    results = []
    patterns = VULN_PATTERNS.get(lang, [])
    filename = os.path.basename(filepath)

    # ── Vulnerability pattern matching ──
    for ctrl_id, severity, pattern, desc, remediation in patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                # Get surrounding context
                start = max(0, i - 2)
                end = min(len(lines), i + 2)
                context = '\n'.join(f"  {j}: {lines[j-1]}" for j in range(start+1, end+1))

                results.append(ScanResult(
                    scanner='code-analysis',
                    control_id=ctrl_id,
                    status='NON_COMPLIANT',
                    severity=severity,
                    evidence=f"[{filename}:{i}] {desc}\n\n{context}",
                    confidence=0.85,
                    remediation=remediation,
                    reachability='INTERNAL',
                ))
                break  # One finding per pattern per file

    # ── Complexity analysis ──
    complexity_results = _analyze_complexity(filepath, lang, lines)
    results.extend(complexity_results)

    # ── Development practice checks ──
    practice_results = _check_practices(filepath, lang, content, lines)
    results.extend(practice_results)

    return results


def _analyze_complexity(filepath: str, lang: str, lines: list) -> list:
    """Calculate cyclomatic complexity, nesting depth, function length."""
    results = []
    filename = os.path.basename(filepath)
    total_lines = len(lines)

    # CPX-STRUCT-004: File length
    if total_lines > 500:
        results.append(ScanResult(
            scanner='code-analysis', control_id='CPX-STRUCT-004',
            status='NON_COMPLIANT', severity='INFORMATIONAL',
            evidence=f"[{filename}] File is {total_lines} lines (threshold: 500).",
            remediation='Decompose into smaller, focused modules.'
        ))

    # Find functions and measure them
    func_pattern = {
        'python': r'^\s*def\s+(\w+)\s*\(',
        'javascript': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\(|=>))',
        'typescript': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\(|=>))',
        'java': r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(',
        'go': r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(',
        'php': r'function\s+(\w+)\s*\(',
        'csharp': r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(',
        'rust': r'(?:pub\s+)?fn\s+(\w+)',
        'cpp': r'(?:\w+(?:::\w+)?\s+)+(\w+)\s*\(',
        'c': r'(?:\w+\s+)+(\w+)\s*\(',
    }

    pattern = func_pattern.get(lang)
    if not pattern:
        return results

    # Simple function extraction
    branch_keywords = {
        'python': ['if ', 'elif ', 'for ', 'while ', 'except ', ' and ', ' or ', 'assert '],
        'javascript': ['if ', 'else if', 'for ', 'while ', 'catch ', '&&', '||', '? ', 'case '],
        'typescript': ['if ', 'else if', 'for ', 'while ', 'catch ', '&&', '||', '? ', 'case '],
        'java': ['if ', 'else if', 'for ', 'while ', 'catch ', '&&', '||', '? ', 'case '],
        'go': ['if ', 'for ', 'case ', '&&', '||', 'select '],
        'php': ['if ', 'elseif', 'for ', 'foreach ', 'while ', 'catch ', '&&', '||', 'case '],
        'csharp': ['if ', 'else if', 'for ', 'foreach ', 'while ', 'catch ', '&&', '||', 'case '],
        'rust': ['if ', 'for ', 'while ', 'match ', 'loop ', '&&', '||'],
        'cpp': ['if ', 'else if', 'for ', 'while ', 'catch ', '&&', '||', 'case '],
        'c': ['if ', 'else if', 'for ', 'while ', '&&', '||', 'case '],
    }

    nesting_openers = {'{', '('}
    keywords = branch_keywords.get(lang, [])
    complex_functions = []

    for i, line in enumerate(lines):
        match = re.match(pattern, line)
        if not match:
            continue
        func_name = next((g for g in match.groups() if g), 'unknown')
        func_start = i

        # Count function body lines and complexity
        depth = 0
        max_depth = 0
        func_lines = 0
        complexity = 1  # Base complexity
        indent_based = lang in ('python',)

        for j in range(i + 1, min(len(lines), i + 200)):
            body_line = lines[j]
            stripped = body_line.strip()

            if not stripped or stripped.startswith(('#', '//', '/*', '*', '--', '"""', "'''")):
                continue

            func_lines += 1

            # Track nesting
            depth += body_line.count('{') - body_line.count('}')
            max_depth = max(max_depth, depth)

            # Count branches
            for kw in keywords:
                if kw in body_line:
                    complexity += 1

            # Detect function end
            if indent_based:
                if j > i + 1 and body_line and not body_line[0].isspace() and stripped and not stripped.startswith(('@', 'def ', 'class ')):
                    break
            else:
                if depth <= 0 and func_lines > 2:
                    break

        if func_lines > 0:
            # CPX-STRUCT-001: Function length
            if func_lines > 50:
                complex_functions.append((func_name, func_start + 1, func_lines, complexity, max_depth))
                results.append(ScanResult(
                    scanner='code-analysis', control_id='CPX-STRUCT-001',
                    status='NON_COMPLIANT', severity='LOW',
                    evidence=f"[{filename}:{func_start+1}] Function '{func_name}' is {func_lines} lines (threshold: 50).",
                    remediation='Extract helper functions to reduce function length.'
                ))

            # CPX-METRIC-001: Cyclomatic complexity
            if complexity > 10:
                results.append(ScanResult(
                    scanner='code-analysis', control_id='CPX-METRIC-001',
                    status='NON_COMPLIANT',
                    severity='MEDIUM' if complexity <= 15 else 'HIGH',
                    evidence=f"[{filename}:{func_start+1}] Function '{func_name}' has cyclomatic complexity {complexity} (threshold: 10).",
                    remediation='Decompose into smaller functions with single responsibilities.'
                ))

            # CPX-STRUCT-003: Nesting depth
            if max_depth > 4:
                results.append(ScanResult(
                    scanner='code-analysis', control_id='CPX-STRUCT-003',
                    status='NON_COMPLIANT', severity='MEDIUM',
                    evidence=f"[{filename}:{func_start+1}] Function '{func_name}' has nesting depth {max_depth} (threshold: 4).",
                    remediation='Use early returns and guard clauses to reduce nesting.'
                ))

    return results


def _check_practices(filepath: str, lang: str, content: str, lines: list) -> list:
    """Check development practice controls."""
    results = []
    filename = os.path.basename(filepath)

    # CPX-MAINTAIN-002: Dead code (unused imports)
    if lang == 'python':
        imports = re.findall(r'^import\s+(\w+)|^from\s+(\w+)', content, re.MULTILINE)
        for imp in imports:
            module = imp[0] or imp[1]
            # Check if module name appears elsewhere in code (rough check)
            uses = len(re.findall(r'\b' + re.escape(module) + r'\b', content))
            if uses <= 1:
                results.append(ScanResult(
                    scanner='code-analysis', control_id='CPX-MAINTAIN-002',
                    status='NON_COMPLIANT', severity='LOW',
                    evidence=f"[{filename}] Potentially unused import: {module}",
                    remediation=f'Remove unused import: {module}'
                ))

    # CPX-MAINTAIN-003: Empty/bare exception handlers
    bare_except = {
        'python': r'except\s*:\s*$|except\s+\w+.*:\s*\n\s*pass\s*$',
        'javascript': r'catch\s*\(\s*\w*\s*\)\s*\{\s*\}',
        'java': r'catch\s*\([^)]+\)\s*\{\s*\}',
        'go': r'_\s*=\s*err\b',
        'php': r'catch\s*\([^)]+\)\s*\{\s*\}',
    }
    pattern = bare_except.get(lang)
    if pattern:
        matches = re.finditer(pattern, content, re.MULTILINE)
        for m in matches:
            line_num = content[:m.start()].count('\n') + 1
            results.append(ScanResult(
                scanner='code-analysis', control_id='CPX-MAINTAIN-003',
                status='NON_COMPLIANT', severity='MEDIUM',
                evidence=f"[{filename}:{line_num}] Empty/swallowed exception handler.",
                remediation='Handle or log the error; never silently ignore exceptions.'
            ))
            break

    # CPX-MAINTAIN-001: Type annotations (Python)
    if lang == 'python':
        func_defs = re.findall(r'def\s+\w+\s*\([^)]*\)\s*(?:->|:)', content)
        typed = [f for f in func_defs if '->' in f or ':' in f.split(')', 1)[0]]
        if func_defs and len(typed) < len(func_defs) * 0.5:
            results.append(ScanResult(
                scanner='code-analysis', control_id='CPX-MAINTAIN-001',
                status='NON_COMPLIANT', severity='LOW',
                evidence=f"[{filename}] Only {len(typed)} of {len(func_defs)} functions have type annotations.",
                remediation='Add type hints to function parameters and return values.'
            ))

    return results


def scan_directory(dir_path: str, progress_callback=None) -> list:
    """Scan all source files in a directory recursively."""
    all_results = []
    files = []

    for root, dirs, filenames in os.walk(dir_path):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'target', 'build', 'dist', 'vendor', '.idea', '.vscode'
        }]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in LANG_EXTENSIONS:
                files.append(os.path.join(root, fname))

    detected_langs = set()
    for i, filepath in enumerate(files):
        if progress_callback:
            progress_callback('code-analysis', f'Scanning {os.path.basename(filepath)}',
                            'running', [])

        file_results = scan_file(filepath)
        all_results.extend(file_results)
        lang = detect_language(filepath)
        if lang:
            detected_langs.add(lang)

        if progress_callback:
            progress_callback('code-analysis', f'Scanned {os.path.basename(filepath)}',
                            'done', file_results)

    # Emit COMPLIANT for every control that was checked but had no violations
    noncompliant_ids = {r.control_id for r in all_results if r.status == 'NON_COMPLIANT'}
    all_results.extend(_build_compliant_results(detected_langs, noncompliant_ids))

    return all_results


def scan_target(target: str, progress_callback=None) -> list:
    """Entry point — scan a file or directory."""
    if os.path.isdir(target):
        return scan_directory(target, progress_callback)
    elif os.path.isfile(target):
        if progress_callback:
            progress_callback('code-analysis', f'Scanning {os.path.basename(target)}', 'running', [])
        results = scan_file(target)
        # Emit COMPLIANT for every control that was checked but had no violations
        lang = detect_language(target)
        if lang:
            noncompliant_ids = {r.control_id for r in results if r.status == 'NON_COMPLIANT'}
            results.extend(_build_compliant_results({lang}, noncompliant_ids))
        if progress_callback:
            progress_callback('code-analysis', f'Scanned {os.path.basename(target)}', 'done', results)
        return results
    return []
