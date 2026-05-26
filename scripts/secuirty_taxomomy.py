# ============================================
# security_taxonomy.py
# ============================================

SECURITY_TAXONOMY = {

    # ========================================
    # INJECTION
    # ========================================
    "injection": {

        "owasp":
            "A03 Injection",

        "knowledge_file":
            "knowledge/injection.txt",

        "keywords": [
            "sql",
            "ldap",
            "xpath",
            "command",
            "query",
            "statement",
            "injection",
            "executequery",
            "runtime.exec"
        ]
    },

    # ========================================
    # CRYPTOGRAPHY
    # ========================================
    "cryptography": {

        "owasp":
            "A02 Cryptographic Failures",

        "knowledge_file":
            "knowledge/cryptography.txt",

        "keywords": [
            "cipher",
            "crypto",
            "cryptographic",
            "padding",
            "aes",
            "rsa",
            "des",
            "ecb",
            "cbc",
            "encryption",
            "decrypt",
            "encrypt"
        ]
    },

    # ========================================
    # AUTHENTICATION
    # ========================================
    "authentication": {

        "owasp":
            "A07 Identification and Authentication Failures",

        "knowledge_file":
            "knowledge/authentication.txt",

        "keywords": [
            "password",
            "credential",
            "secret",
            "token",
            "apikey",
            "hardcoded",
            "authentication"
        ]
    },

    # ========================================
    # XSS
    # ========================================
    "xss": {

        "owasp":
            "A03 Injection",

        "knowledge_file":
            "knowledge/xss.txt",

        "keywords": [
            "xss",
            "script",
            "html",
            "javascript",
            "response.write"
        ]
    },

    # ========================================
    # SSRF
    # ========================================
    "ssrf": {

        "owasp":
            "A10 Server-Side Request Forgery",

        "knowledge_file":
            "knowledge/ssrf.txt",

        "keywords": [
            "url",
            "uri",
            "request",
            "urlconnection",
            "httpclient"
        ]
    },

    # ========================================
    # PATH TRAVERSAL
    # ========================================
    "path_traversal": {

        "owasp":
            "A01 Broken Access Control",

        "knowledge_file":
            "knowledge/path_traversal.txt",

        "keywords": [
            "path",
            "directory",
            "filepath",
            "../",
            "file"
        ]
    },

    # ========================================
    # DESERIALIZATION
    # ========================================
    "deserialization": {

        "owasp":
            "A08 Software and Data Integrity Failures",

        "knowledge_file":
            "knowledge/deserialization.txt",

        "keywords": [
            "deserialize",
            "serialization",
            "objectinputstream",
            "readobject"
        ]
    },

    # ========================================
    # GENERIC
    # ========================================
    "generic": {

        "owasp":
            "Unknown",

        "knowledge_file":
            "knowledge/generic.txt",

        "keywords": []
    }
}