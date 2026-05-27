RULE_GUIDANCE: dict[str, str] = {

    "java:S6437": (
        "Replace the hardcoded string literal with an environment variable read.\n"
        "    Before:  \"hardcoded_secret\"\n"
        "    After:   System.getenv(\"APP_SECRET\")\n"
        "    Before:  \"hardcoded\".toCharArray()\n"
        "    After:   System.getenv(\"APP_SECRET\").toCharArray()\n"
        "Change only the string literal. Keep the variable name, type, and structure identical."
    ),

    "java:S2068": (
        "Replace the hardcoded password string literal with an environment variable read.\n"
        "    Before:  password = \"Password1234!\";\n"
        "    After:   password = System.getenv(\"DB_PASSWORD\");\n"
        "Change only the string literal. Keep the variable name and assignment structure identical."
    ),

    "java:S5542": (
        "Replace the insecure cipher algorithm string with a secure one.\n"
        "    \"AES\"             → \"AES/GCM/NoPadding\"\n"
        "    \"AES/ECB/...\"     → \"AES/GCM/NoPadding\"\n"
        "    \"MD5\"             → \"SHA-256\"\n"
        "    \"SHA-1\"           → \"SHA-256\"\n"
        "Change only the string argument to getInstance(). Nothing else."
    ),

    "java:S5443": (
        "Replace the insecure temp file path with a system-managed temp file.\n"
        "    Before:  new File(\"/tmp/\" + name)\n"
        "    After:   File.createTempFile(\"prefix\", \".tmp\")\n"
        "Change only the file creation call. Nothing else."
    ),

    "java:S3330": (
        "Add the HttpOnly flag to the cookie.\n"
        "Insert on the next line after the cookie constructor:\n"
        "    <variable>.setHttpOnly(true);\n"
        "Return only that one additional line."
    ),

    "java:S2076": (
        "Remove or sanitize the user-controlled value before passing it to the OS command.\n"
        "Replace direct use of unsanitized input with a validated or allowlisted value."
    ),

    "java:S2078": (
        "Sanitize or encode the user-controlled value before using it in the LDAP query.\n"
        "Replace direct concatenation with proper LDAP escaping."
    ),
}


CATEGORY_GUIDANCE: dict[str, str] = {

    "cookies": (
        "A required cookie security flag is missing.\n"
        "Add the missing flag (setSecure(true) or setHttpOnly(true)) on the line "
        "immediately after the cookie constructor.\n"
        "Return only that one additional line."
    ),

    "authentication": (
        "A hardcoded credential string literal is present in source code.\n"
        "Replace the string literal with System.getenv(\"ENV_VAR_NAME\").\n"
        "Change only the string literal. Keep the variable name and structure identical."
    ),

    "cryptography": (
        "An insecure cryptographic algorithm or configuration is used.\n"
        "Replace the algorithm string:\n"
        "    \"AES\" or \"AES/ECB/...\" → \"AES/GCM/NoPadding\"\n"
        "    \"MD5\" or \"SHA-1\"       → \"SHA-256\"\n"
        "Change only the string argument to getInstance(). Nothing else."
    ),

    "injection": (
        "User input is used directly in a database query without parameterization.\n"
        "Replace string concatenation in the query with a PreparedStatement placeholder (?).\n"
        "Change only the minimum required."
    ),

    "xss": (
        "User input is reflected into an HTTP response without encoding.\n"
        "Encode the value with URLEncoder.encode(value, \"UTF-8\") before using it.\n"
        "Change only the minimum required."
    ),

    "path_traversal": (
        "A file path is constructed from user input without canonicalization.\n"
        "Resolve the canonical path and verify it starts with the allowed base directory.\n"
        "Change only the minimum required."
    ),

    "ssrf": (
        "A URL is constructed from user input and used for an outbound connection.\n"
        "Validate the target against an allowlist before connecting.\n"
        "Change only the minimum required."
    ),

    "deserialization": (
        "Untrusted data is passed directly to ObjectInputStream.readObject().\n"
        "Replace with a type-safe alternative or validate the class before deserialization.\n"
        "Change only the minimum required."
    ),

    "generic": (
        "A security vulnerability exists on the marked line.\n"
        "Apply the minimum change required to fix the issue described in the Rule and Issue fields."
    ),
}


def get_guidance(rule: str, category: str) -> str:
    return RULE_GUIDANCE.get(rule) or CATEGORY_GUIDANCE.get(category) or CATEGORY_GUIDANCE["generic"]


def build_prompt(issue: dict, category: str, context: str, vulnerable_line: str) -> str:
    guidance = get_guidance(issue.get("rule", ""), category)
    return (
        f"You are a Java security engineer. Apply the minimum fix required. Do not refactor.\n\n"
        f"Rule: {issue.get('rule', '')}\n"
        f"Issue: {issue.get('message', '')}\n\n"
        f"How to fix:\n{guidance}\n\n"
        f"Code context:\n{context}\n"
        f"Line to fix:\n{vulnerable_line.rstrip()}\n\n"
        "Return only the fixed replacement code in a ```java block.\n"
        "Same indentation. No new imports. No comments. No explanation. Minimal change only."
    )
