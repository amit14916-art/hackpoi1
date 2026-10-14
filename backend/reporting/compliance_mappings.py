from typing import Dict, List, Any

# ==============================================================================
# SOC 2 Trust Services Criteria (2017 / 2022)
# ==============================================================================
SOC2_CRITERIA_INFO: Dict[str, Dict[str, str]] = {
    "CC6.1": {
        "title": "Logical Access Controls & Boundary Defense",
        "category": "Security",
        "description": "The entity implements logical access security software, infrastructure, and architectures over protected assets.",
    },
    "CC6.6": {
        "title": "Perimeter Security & Injection Prevention",
        "category": "Security",
        "description": "The entity implements logical boundaries to protect against unauthorized remote access, injection, and perimeter exploits.",
    },
    "CC6.7": {
        "title": "Data Transmission Encryption & Key Management",
        "category": "Confidentiality & Security",
        "description": "The entity protects transmission of confidential data using verified cryptography and strong cipher suites.",
    },
    "CC7.1": {
        "title": "Vulnerability Detection & Security Baseline",
        "category": "Security",
        "description": "To meet operational security objectives, the entity uses automated tooling to identify technical vulnerabilities.",
    },
    "CC7.2": {
        "title": "Security Monitoring & Anomalous Activity",
        "category": "Security",
        "description": "The entity monitors system components to detect anomalies, rate limiting violations, or indicators of compromise.",
    },
    "A1.2": {
        "title": "Environmental & Service Availability Controls",
        "category": "Availability",
        "description": "The entity authorizes, designs, and monitors system availability, including email routing hygiene (SPF/DMARC) and DoS protection.",
    },
    "C1.1": {
        "title": "Information Disclosure & Secret Protection",
        "category": "Confidentiality",
        "description": "The entity identifies and protects confidential information from unintended exposure via source files, bundles, or debug dumps.",
    },
}

# Mapping: CWE ID -> List of SOC 2 Criteria
CWE_TO_SOC2_MAP: Dict[str, List[str]] = {
    "CWE-79": ["CC6.6", "CC7.1"],       # XSS
    "CWE-89": ["CC6.6", "CC7.1"],       # SQLi
    "CWE-94": ["CC6.6"],                # Code Injection
    "CWE-200": ["C1.1", "CC6.1"],       # Information Disclosure
    "CWE-284": ["CC6.1"],               # Improper Access Control
    "CWE-287": ["CC6.1"],               # Authentication
    "CWE-290": ["A1.2", "CC6.6"],       # Email Spoofing (SPF/DMARC)
    "CWE-295": ["CC6.7"],               # Certificate Validation
    "CWE-311": ["CC6.7"],               # Missing Encryption (Mixed Content)
    "CWE-312": ["CC6.7", "C1.1"],       # Cleartext Storage of Sensitive Info
    "CWE-319": ["CC6.7"],               # Cleartext Transmission
    "CWE-326": ["CC6.7"],               # Inadequate Encryption Strength
    "CWE-327": ["CC6.7"],               # Broken/Risky Cryptographic Algorithm
    "CWE-352": ["CC6.6"],               # CSRF
    "CWE-353": ["CC7.1"],               # Missing Subresource Integrity (SRI)
    "CWE-525": ["CC7.1", "C1.1"],       # Use of Web Browser Cache Containing Sensitive Information
    "CWE-548": ["C1.1"],                # Exposure of Information Through Directory Listing
    "CWE-601": ["CC6.6"],               # Open Redirect
    "CWE-693": ["CC7.1"],               # Protection Mechanism Failure (Headers)
    "CWE-770": ["CC7.2", "A1.2"],       # Missing Rate Limiting
    "CWE-798": ["CC6.1", "C1.1"],       # Hardcoded Credentials / Secrets
    "CWE-862": ["CC6.1"],               # Missing Authorization
    "CWE-863": ["CC6.1"],               # Incorrect Authorization
    "CWE-918": ["CC6.6"],               # SSRF
    "CWE-1004": ["CC7.1", "C1.1"],      # Sensitive Cookie Without HttpOnly
    "CWE-1021": ["CC7.1"],              # Clickjacking (X-Frame-Options)
}

# ==============================================================================
# ISO 27001:2022 Annex A Controls
# ==============================================================================
ISO27001_CONTROLS_INFO: Dict[str, Dict[str, str]] = {
    "A.5.15": {
        "title": "Access Control",
        "clause": "Organizational controls",
        "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented.",
    },
    "A.8.8": {
        "title": "Management of Technical Vulnerabilities",
        "clause": "Technological controls",
        "description": "Information about technical vulnerabilities of information systems being used shall be obtained, evaluation performed, and measures taken.",
    },
    "A.8.20": {
        "title": "Network Security & Domain Boundaries",
        "clause": "Technological controls",
        "description": "Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.",
    },
    "A.8.24": {
        "title": "Use of Cryptography",
        "clause": "Technological controls",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
    },
    "A.8.26": {
        "title": "Application Security Requirements",
        "clause": "Technological controls",
        "description": "Information security requirements shall be identified, specified, and approved when developing or acquiring applications.",
    },
    "A.8.28": {
        "title": "Secure Coding & Input Validation",
        "clause": "Technological controls",
        "description": "Secure coding principles shall be applied to software development to prevent injection, tampering, and information leaks.",
    },
}

# Mapping: CWE ID -> List of ISO 27001 Control IDs
CWE_TO_ISO27001_MAP: Dict[str, List[str]] = {
    "CWE-79": ["A.8.26", "A.8.28"],     # XSS
    "CWE-89": ["A.8.26", "A.8.28"],     # SQLi
    "CWE-94": ["A.8.26", "A.8.28"],     # Code Injection
    "CWE-200": ["A.8.28", "A.5.15"],    # Info Disclosure
    "CWE-284": ["A.5.15"],              # Access Control
    "CWE-287": ["A.5.15"],              # Auth
    "CWE-290": ["A.8.20"],              # Spoofing (SPF/DMARC)
    "CWE-295": ["A.8.24"],              # Cert validation
    "CWE-311": ["A.8.24"],              # Missing Encryption
    "CWE-312": ["A.8.24"],              # Cleartext Storage
    "CWE-319": ["A.8.24"],              # Cleartext Transmission
    "CWE-326": ["A.8.24"],              # Inadequate Encryption
    "CWE-327": ["A.8.24"],              # Broken Crypto
    "CWE-352": ["A.8.26"],              # CSRF
    "CWE-353": ["A.8.8", "A.8.26"],     # SRI
    "CWE-525": ["A.8.8"],               # Cache Control
    "CWE-548": ["A.8.8"],               # Dir listing
    "CWE-601": ["A.8.20", "A.8.26"],    # Open Redirect
    "CWE-693": ["A.8.8", "A.8.26"],     # Missing Headers
    "CWE-770": ["A.8.20"],              # Rate Limiting
    "CWE-798": ["A.5.15", "A.8.28"],    # Hardcoded Secrets
    "CWE-862": ["A.5.15"],              # Missing Authorization
    "CWE-863": ["A.5.15"],              # Incorrect Authorization
    "CWE-918": ["A.8.20"],              # SSRF
    "CWE-1004": ["A.8.26"],             # Cookie HttpOnly
    "CWE-1021": ["A.8.26"],             # Clickjacking
}
