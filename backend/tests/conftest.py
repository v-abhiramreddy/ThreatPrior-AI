import pytest
from typing import Dict, Any

MOCK_CISA_CATALOG: Dict[str, Any] = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.10.15",
    "dateReleased": "2026-10-15T12:00:00Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 JNDI RCE vulnerability allows unauthenticated attackers...",
            "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Target of Federal Binding Directive 22-01.",
            "cwes": ["CWE-20", "CWE-400", "CWE-502"],
        },
        {
            "cveID": "CVE-2023-38606",
            "vendorProject": "Apple",
            "product": "iOS and macOS",
            "vulnerabilityName": "Apple Kernel Memory Map Privilege Escalation",
            "dateAdded": "2023-07-28",
            "shortDescription": "Hardware MMIO page table register bypass...",
            "requiredAction": "Apply vendor updates immediately.",
            "dueDate": "2023-08-18",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "Exploited in Operation Triangulation.",
            "cwes": ["CWE-284"],
        },
    ],
}

MOCK_NVD_LOG4SHELL: Dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-10-16T06:50:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "security@apache.org",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2026-08-11T19:33:44.513",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration do not protect against LDAP endpoints.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 6.0,
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-502"}],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    ],
}

MOCK_NVD_CVSS_V2_ONLY: Dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2008-0001",
                "published": "2008-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Legacy vulnerability with CVSS v2 only."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                            },
                            "baseSeverity": "HIGH",
                        }
                    ]
                },
            }
        }
    ],
}

MOCK_EPSS_LOG4SHELL: Dict[str, Any] = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2021-44228",
            "epss": "0.974100000",
            "percentile": "0.998000000",
            "date": "2026-10-15",
        }
    ],
}

MOCK_EPSS_EMPTY: Dict[str, Any] = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "total": 0,
    "data": [],
}
