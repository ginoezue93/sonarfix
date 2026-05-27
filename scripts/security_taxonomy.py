import re

TAXONOMY = {
    "cookies": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe_ids": [614],
        "keywords": [
            "cookie", "secure flag", "httponly", "samesite",
        ],
        "knowledge_file": "cookies.txt",
    },
    "injection": {
        "owasp": "A03:2021 - Injection",
        "cwe_ids": [89, 90, 78, 77, 74, 564, 917],
        "keywords": [
            "sql", "ldap", "xpath", "command", "query", "statement",
            "injection", "executequery", "runtime.exec", "preparedstatement",
        ],
        "knowledge_file": "injection.txt",
    },
    "cryptography": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe_ids": [326, 327, 328, 330, 325, 338, 780, 916],
        "keywords": [
            "cipher", "crypto", "cryptographic", "padding", "aes", "rsa",
            "des", "ecb", "cbc", "encryption", "decrypt", "encrypt",
            "keygenerator", "messagedigest", "md5", "sha1", "sha-1",
            "weak algorithm", "insecure algorithm",
        ],
        "knowledge_file": "cryptography.txt",
    },
    "authentication": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe_ids": [287, 259, 798, 306, 307, 319, 522],
        "keywords": [
            "password", "credential", "secret", "token", "apikey",
            "hardcoded", "authentication", "cleartext", "plaintext",
            "passwordauth", "kerberoskey", "drivermanager",
        ],
        "knowledge_file": "authentication.txt",
    },
    "xss": {
        "owasp": "A03:2021 - Injection (XSS / HTTP Response Splitting)",
        "cwe_ids": [79, 80, 81, 82, 83, 84, 85, 86, 87, 113],
        "keywords": [
            "xss", "cross-site", "html", "javascript", "response.write",
            "addcookie", "setheader", "addheader", "sendredirect",
            "response splitting", "http response",
        ],
        "knowledge_file": "xss.txt",
    },
    "ssrf": {
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "cwe_ids": [918],
        "keywords": [
            "urlconnection", "httpclient", "openconnection",
            "geturl", "outbound",
        ],
        "knowledge_file": "ssrf.txt",
    },
    "path_traversal": {
        "owasp": "A01:2021 - Broken Access Control (Path Traversal)",
        "cwe_ids": [22, 23, 36, 37, 38, 39, 40],
        "keywords": [
            "path", "directory", "filepath", "traversal",
            "canonicalize", "getcanonicalpath", "relative path", "absolute path",
        ],
        "knowledge_file": "path_traversal.txt",
    },
    "deserialization": {
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe_ids": [502],
        "keywords": [
            "deserializ", "serializ", "objectinputstream", "readobject", "unmarshal",
        ],
        "knowledge_file": "deserialization.txt",
    },
    "generic": {
        "owasp": "General Security",
        "cwe_ids": [],
        "keywords": [],
        "knowledge_file": "generic.txt",
    },
}

RULE_CATEGORIES = {
    "java:S2092": "cookies",
    "java:S2068": "authentication",
    "java:S6437": "authentication",
    "java:S5542": "cryptography",
}


def extract_cwe_from_filename(filename: str) -> int | None:
    match = re.search(r"CWE(\d+)", str(filename), re.IGNORECASE)
    return int(match.group(1)) if match else None


def classify_by_cwe(cwe_id: int) -> tuple[str, dict]:
    for category, data in TAXONOMY.items():
        if cwe_id in data["cwe_ids"]:
            return category, data
    return "generic", TAXONOMY["generic"]


def classify_by_keywords(text: str) -> tuple[str, dict]:
    lower = text.lower()
    for category, data in TAXONOMY.items():
        if any(kw in lower for kw in data["keywords"]):
            return category, data
    return "generic", TAXONOMY["generic"]


def classify_issue(issue: dict) -> tuple[str, dict]:
    rule_category = RULE_CATEGORIES.get(issue.get("rule", ""))
    if rule_category:
        return rule_category, TAXONOMY[rule_category]

    # Priority 2: CWE from SonarQube metadata
    for raw in issue.get("cwe", []):
        try:
            num = int(str(raw).upper().replace("CWE-", "").replace("CWE", ""))
            cat, data = classify_by_cwe(num)
            if cat != "generic":
                return cat, data
        except ValueError:
            pass

    # Priority 3: keyword matching on SonarQube message + rule
    text = issue.get("message", "") + " " + issue.get("rule", "")
    cat, data = classify_by_keywords(text)
    if cat != "generic":
        return cat, data

    # Priority 4: CWE from benchmark filename (last resort)
    cwe = extract_cwe_from_filename(issue.get("file", ""))
    if cwe:
        cat, data = classify_by_cwe(cwe)
        if cat != "generic":
            return cat, data

    return "generic", TAXONOMY["generic"]
