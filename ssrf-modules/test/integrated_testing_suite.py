"""
Integrated Testing Suite - Comprehensive SSRF Testing
Combines all advanced techniques: Security layers, Playwright automation, and Adaptive payloads
"""

import asyncio
import json
import time
import random
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys
import os

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'fuzzer'))

from adaptive_payload_engine import AdaptivePayloadEngine, PayloadResult, EncodingTechnique, EvasionStrategy

class IntegratedSSRFTester:
    """Comprehensive SSRF testing suite integrating all advanced capabilities"""

    def __init__(self):
        self.adaptive_engine = AdaptivePayloadEngine()
        self.test_results = []
        self.discovered_vulnerabilities = []

        # Realistic enterprise targets with varying security levels
        self.enterprise_targets = self._initialize_enterprise_targets()

    def _initialize_enterprise_targets(self) -> List[Dict[str, Any]]:
        """Initialize realistic enterprise testing targets"""

        return [
            {
                "name": "Financial Services API",
                "url": "https://api.bank.secure.com/v2/transfer",
                "param_name": "destination_url",
                "method": "POST",
                "type": "cloud",
                "security_level": "high",
                "expected_protections": [
                    "Cloudflare Enterprise",
                    "Advanced Rate Limiting",
                    "IP Reputation Filtering",
                    "DDoS Protection",
                    "Bot Management",
                    "TLS Fingerprinting",
                    "Behavioral Analysis"
                ],
                "additional_headers": {
                    "X-API-Key": "bank_api_key_12345",
                    "X-Request-ID": "req_" + str(random.randint(100000, 999999)),
                    "Content-Type": "application/json"
                },
                "request_body": {
                    "amount": 100.00,
                    "currency": "USD",
                    "callback_url": "{PAYLOAD}"
                }
            },
            {
                "name": "Healthcare Data Platform",
                "url": "https://health.platform.gov/api/webhook",
                "param_name": "notification_endpoint",
                "method": "POST",
                "type": "internal",
                "security_level": "high",
                "expected_protections": [
                    "Government-grade WAF",
                    "HIPAA Compliance Filters",
                    "Multi-layer Authentication",
                    "Geo-blocking",
                    "Advanced Monitoring"
                ],
                "additional_headers": {
                    "Authorization": "Bearer gov_token_abcdef",
                    "X-Client-ID": "healthcare_client",
                    "Content-Type": "application/json"
                },
                "request_body": {
                    "patient_id": "PATIENT_12345",
                    "data_type": "lab_results",
                    "webhook_url": "{PAYLOAD}"
                }
            },
            {
                "name": "E-commerce Marketplace",
                "url": "https://marketplace.shop.com/api/integrations/webhook",
                "param_name": "callback_uri",
                "method": "POST",
                "type": "cloud",
                "security_level": "medium",
                "expected_protections": [
                    "AWS WAF",
                    "Rate Limiting",
                    "API Gateway",
                    "CloudFront Protection"
                ],
                "additional_headers": {
                    "X-Shop-Token": "shop_token_xyz789",
                    "User-Agent": "ShopApp/2.1.0",
                    "Content-Type": "application/json"
                },
                "request_body": {
                    "merchant_id": "MERCHANT_456",
                    "event_type": "order_completed",
                    "notification_url": "{PAYLOAD}"
                }
            },
            {
                "name": "Legacy Enterprise System",
                "url": "https://legacy.corp.internal/system/import",
                "param_name": "source_url",
                "method": "GET",
                "type": "file_server",
                "security_level": "low",
                "expected_protections": [
                    "Basic WAF",
                    "IP Whitelist",
                    "Simple Authentication"
                ],
                "additional_headers": {
                    "X-Legacy-Token": "legacy_12345",
                    "X-System-Version": "1.0"
                },
                "request_body": None
            },
            {
                "name": "Cloud Microservices Gateway",
                "url": "https://api.microservices.cloud/v3/fetch",
                "param_name": "external_resource",
                "method": "POST",
                "type": "cloud",
                "security_level": "advanced",
                "expected_protections": [
                    "Kong Enterprise",
                    "JWT Validation",
                    "Request Signing",
                    "Advanced Rate Limiting",
                    "Circuit Breaker"
                ],
                "additional_headers": {
                    "Authorization": "JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                    "X-Service-ID": "fetch_service_v3",
                    "Content-Type": "application/json"
                },
                "request_body": {
                    "resource_type": "external_api",
                    "timeout": 30,
                    "url": "{PAYLOAD}"
                }
            }
        ]

    async def simulate_realistic_request(self, target: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Simulate realistic HTTP request with all security considerations"""

        print(f"    Testing: {target['name']}")
        print(f"      Security Level: {target['security_level']}")
        print(f"      Payload: {payload[:80]}...")

        # Simulate realistic timing
        await asyncio.sleep(random.uniform(0.5, 2.0))

        # Prepare request details
        request_details = {
            "url": target["url"],
            "method": target["method"],
            "headers": target["additional_headers"].copy(),
            "payload": payload,
            "parameter": target["param_name"]
        }

        # Add realistic browser headers for Playwright simulation
        browser_headers = self._generate_realistic_browser_headers()
        request_details["headers"].update(browser_headers)

        # Prepare request body
        if target["request_body"]:
            body = target["request_body"].copy()
            # Replace payload placeholder
            for key, value in body.items():
                if isinstance(value, str) and "{PAYLOAD}" in value:
                    body[key] = value.replace("{PAYLOAD}", payload)
            request_details["body"] = body

        # Simulate security layer processing
        security_results = await self._simulate_security_processing(target, request_details)

        # Simulate backend processing if not blocked
        backend_result = {"vulnerable": False, "type": "none"}
        if not security_results["blocked"]:
            backend_result = await self._simulate_backend_vulnerability_check(target, payload)

        return {
            "target": target["name"],
            "request_details": request_details,
            "security_results": security_results,
            "backend_result": backend_result,
            "final_result": {
                "success": not security_results["blocked"],
                "vulnerable": backend_result["vulnerable"],
                "confidence": backend_result.get("confidence", 0.0)
            },
            "timestamp": time.time()
        }

    def _generate_realistic_browser_headers(self) -> Dict[str, str]:
        """Generate realistic browser headers for evasion"""

        browser_profiles = [
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"'
            },
            {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br"
            },
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1"
            }
        ]

        return random.choice(browser_profiles)

    async def _simulate_security_processing(self, target: Dict[str, Any], request_details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate comprehensive security layer processing"""

        security_layers = []
        blocked = False
        block_reason = ""

        # WAF Detection
        waf_result = await self._simulate_waf_detection(target, request_details["payload"])
        security_layers.append(waf_result)
        if waf_result["blocked"]:
            blocked = True
            block_reason = waf_result["reason"]

        # Rate Limiting (if not already blocked)
        if not blocked:
            rate_limit_result = await self._simulate_rate_limiting(target)
            security_layers.append(rate_limit_result)
            if rate_limit_result["blocked"]:
                blocked = True
                block_reason = rate_limit_result["reason"]

        # Browser Fingerprinting (if not already blocked)
        if not blocked:
            fingerprint_result = await self._simulate_browser_fingerprinting(request_details["headers"])
            security_layers.append(fingerprint_result)
            if fingerprint_result["blocked"]:
                blocked = True
                block_reason = fingerprint_result["reason"]

        # Behavioral Analysis (if not already blocked)
        if not blocked:
            behavior_result = await self._simulate_behavioral_analysis(target)
            security_layers.append(behavior_result)
            if behavior_result["blocked"]:
                blocked = True
                block_reason = behavior_result["reason"]

        return {
            "blocked": blocked,
            "reason": block_reason,
            "layers_processed": security_layers,
            "response_code": 403 if blocked else 200,
            "response_time": random.uniform(0.1, 2.0)
        }

    async def _simulate_waf_detection(self, target: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Simulate WAF detection with realistic patterns"""

        waf_triggers = {
            "high": ["127.0.0.1", "localhost", "file://", "169.254.169.254", "metadata", "gopher://", "dict://"],
            "medium": ["127.0.0.1", "localhost", "file://", "169.254.169.254"],
            "low": ["127.0.0.1", "file://"],
            "advanced": ["127.0.0.1", "localhost", "file://", "169.254.169.254", "metadata", "gopher://", "dict://", "internal", "private"]
        }

        security_level = target["security_level"]
        triggers = waf_triggers.get(security_level, waf_triggers["medium"])

        for trigger in triggers:
            if trigger.lower() in payload.lower():
                # Different WAF bypass success rates based on security level
                bypass_rates = {
                    "high": 0.15,     # 15% bypass rate for high security
                    "advanced": 0.12, # 12% bypass rate for advanced security
                    "medium": 0.25,   # 25% bypass rate for medium security
                    "low": 0.45       # 45% bypass rate for low security
                }

                bypass_chance = bypass_rates.get(security_level, 0.25)

                if random.random() > bypass_chance:
                    return {
                        "layer": "WAF",
                        "blocked": True,
                        "reason": f"WAF rule triggered: {trigger}",
                        "confidence": random.uniform(0.8, 0.95)
                    }

        return {
            "layer": "WAF",
            "blocked": False,
            "reason": "Passed WAF inspection",
            "confidence": random.uniform(0.1, 0.3)
        }

    async def _simulate_rate_limiting(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate rate limiting based on target characteristics"""

        # Simulate different rate limiting strictness
        rate_limit_chance = {
            "high": 0.2,      # 20% chance to hit rate limit
            "advanced": 0.18, # 18% chance
            "medium": 0.1,    # 10% chance
            "low": 0.05       # 5% chance
        }

        chance = rate_limit_chance.get(target["security_level"], 0.1)

        if random.random() < chance:
            return {
                "layer": "Rate Limiting",
                "blocked": True,
                "reason": "Rate limit exceeded",
                "confidence": 1.0
            }

        return {
            "layer": "Rate Limiting",
            "blocked": False,
            "reason": "Within rate limits",
            "confidence": 0.0
        }

    async def _simulate_browser_fingerprinting(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Simulate browser fingerprinting detection"""

        user_agent = headers.get("User-Agent", "")

        # Check for automated tool signatures
        bot_signatures = ["python", "curl", "wget", "requests", "urllib", "httpx"]
        for sig in bot_signatures:
            if sig.lower() in user_agent.lower():
                return {
                    "layer": "Browser Fingerprinting",
                    "blocked": True,
                    "reason": f"Automated tool detected: {sig}",
                    "confidence": 0.9
                }

        # Check header consistency (simplified)
        required_headers = ["Accept", "Accept-Language"]
        missing_headers = [h for h in required_headers if h not in headers]

        if missing_headers and random.random() < 0.3:
            return {
                "layer": "Browser Fingerprinting",
                "blocked": True,
                "reason": f"Missing headers: {', '.join(missing_headers)}",
                "confidence": 0.7
            }

        return {
            "layer": "Browser Fingerprinting",
            "blocked": False,
            "reason": "Browser fingerprint accepted",
            "confidence": 0.1
        }

    async def _simulate_behavioral_analysis(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate behavioral analysis"""

        # Simulate detection based on request patterns
        detection_rates = {
            "high": 0.15,
            "advanced": 0.12,
            "medium": 0.08,
            "low": 0.03
        }

        rate = detection_rates.get(target["security_level"], 0.08)

        if random.random() < rate:
            reasons = [
                "Suspicious timing pattern",
                "Anomalous request sequence",
                "Behavioral anomaly detected"
            ]
            return {
                "layer": "Behavioral Analysis",
                "blocked": True,
                "reason": random.choice(reasons),
                "confidence": random.uniform(0.6, 0.8)
            }

        return {
            "layer": "Behavioral Analysis",
            "blocked": False,
            "reason": "Normal behavior detected",
            "confidence": 0.1
        }

    async def _simulate_backend_vulnerability_check(self, target: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Simulate backend SSRF vulnerability assessment"""

        # Base vulnerability rates by security level
        vuln_rates = {
            "high": 0.05,      # 5% vulnerability rate
            "advanced": 0.08,  # 8% vulnerability rate
            "medium": 0.15,    # 15% vulnerability rate
            "low": 0.30        # 30% vulnerability rate
        }

        base_rate = vuln_rates.get(target["security_level"], 0.15)

        # Adjust based on payload type
        if "127.0.0.1" in payload or "localhost" in payload:
            vuln_type = "Internal Network Access"
            evidence = ["Internal service response", "Network timing anomaly"]
        elif "file://" in payload:
            vuln_type = "File System Access"
            evidence = ["File content in response", "Directory listing"]
            base_rate *= 0.8  # File access slightly less likely
        elif "169.254.169.254" in payload or "metadata" in payload:
            vuln_type = "Cloud Metadata Access"
            evidence = ["Metadata response", "Instance credentials"]
            base_rate *= 0.7  # Metadata access less likely
        elif "gopher://" in payload or "dict://" in payload:
            vuln_type = "Protocol Smuggling"
            evidence = ["Protocol response", "Service information"]
            base_rate *= 0.6  # Protocol smuggling least likely
        else:
            vuln_type = "Generic SSRF"
            evidence = ["External request detected", "DNS resolution"]

        if random.random() < base_rate:
            return {
                "vulnerable": True,
                "type": vuln_type,
                "evidence": evidence,
                "confidence": random.uniform(0.7, 0.95)
            }

        return {
            "vulnerable": False,
            "type": "none",
            "evidence": [],
            "confidence": 0.0
        }

    async def run_comprehensive_integrated_test(self) -> Dict[str, Any]:
        """Run comprehensive integrated testing suite"""

        print("Integrated SSRF Testing Suite Started")
        print("Advanced Security + Playwright + Adaptive Payloads")
        print(f"Enterprise Targets: {len(self.enterprise_targets)}")
        print("=" * 80)

        all_test_results = []
        total_vulnerabilities = []

        # Test each enterprise target
        for target_index, target in enumerate(self.enterprise_targets, 1):
            print(f"\nTarget {target_index}/{len(self.enterprise_targets)}: {target['name']}")
            print(f"  URL: {target['url']}")
            print(f"  Security Level: {target['security_level']}")
            print(f"  Expected Protections: {len(target['expected_protections'])}")

            # Generate adaptive payloads for this target
            target_info = {
                "type": target["type"],
                "security_level": target["security_level"],
                "detected_waf": target["expected_protections"][0] if target["expected_protections"] else None
            }

            print(f"  Generating optimized payloads...")
            optimized_payloads = self.adaptive_engine.get_optimized_payloads_for_target(target_info)
            print(f"  Generated {len(optimized_payloads)} adaptive payloads")

            target_results = []

            # Test subset of payloads to avoid excessive runtime
            test_payloads = optimized_payloads[:8]  # Test first 8 optimized payloads

            for payload_index, payload in enumerate(test_payloads, 1):
                print(f"\n  Payload {payload_index}/{len(test_payloads)}:")

                # Add realistic delay between tests
                await asyncio.sleep(random.uniform(1.0, 3.0))

                # Run integrated test (Security + Playwright + Adaptive)
                test_result = await self.simulate_realistic_request(target, payload)
                target_results.append(test_result)

                # Create PayloadResult for adaptive learning
                payload_result = PayloadResult(
                    payload=payload,
                    original_template=target["type"],
                    encoding_applied=[EncodingTechnique.URL_ENCODE],  # Simplified for demo
                    evasion_applied=[EvasionStrategy.CASE_VARIATION],  # Simplified for demo
                    success=test_result["final_result"]["success"],
                    response_code=test_result["security_results"]["response_code"],
                    response_time=test_result["security_results"]["response_time"],
                    waf_triggered=test_result["security_results"]["blocked"],
                    vulnerability_detected=test_result["final_result"]["vulnerable"],
                    confidence=test_result["final_result"]["confidence"]
                )

                # Adaptive learning
                self.adaptive_engine.adapt_based_on_response(payload_result)

                # Display result
                if test_result["final_result"]["vulnerable"]:
                    vulnerability = {
                        "target": target["name"],
                        "payload": payload,
                        "vulnerability_type": test_result["backend_result"]["type"],
                        "confidence": test_result["final_result"]["confidence"],
                        "evidence": test_result["backend_result"]["evidence"],
                        "security_bypassed": not test_result["security_results"]["blocked"],
                        "timestamp": test_result["timestamp"]
                    }
                    total_vulnerabilities.append(vulnerability)
                    print(f"      VULNERABILITY FOUND: {vulnerability['vulnerability_type']}")
                    print(f"        Confidence: {vulnerability['confidence']:.1%}")

                elif test_result["security_results"]["blocked"]:
                    print(f"      BLOCKED: {test_result['security_results']['reason']}")

                else:
                    print(f"      PASSED SECURITY: No vulnerability detected")

            all_test_results.extend(target_results)

        # Generate comprehensive report
        report = self._generate_integrated_report(all_test_results, total_vulnerabilities)

        return report

    def _generate_integrated_report(self, test_results: List[Dict], vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive integrated testing report"""

        total_tests = len(test_results)
        blocked_tests = len([r for r in test_results if r["security_results"]["blocked"]])
        successful_tests = total_tests - blocked_tests
        vulnerable_tests = len([r for r in test_results if r["final_result"]["vulnerable"]])

        # Analyze security effectiveness by target
        target_analysis = {}
        for result in test_results:
            target_name = result["target"]
            if target_name not in target_analysis:
                target_analysis[target_name] = {
                    "total": 0,
                    "blocked": 0,
                    "vulnerable": 0,
                    "security_layers": []
                }

            target_analysis[target_name]["total"] += 1
            if result["security_results"]["blocked"]:
                target_analysis[target_name]["blocked"] += 1
            if result["final_result"]["vulnerable"]:
                target_analysis[target_name]["vulnerable"] += 1

            # Collect security layer info
            for layer in result["security_results"]["layers_processed"]:
                if layer["layer"] not in target_analysis[target_name]["security_layers"]:
                    target_analysis[target_name]["security_layers"].append(layer["layer"])

        # Calculate effectiveness rates
        for target in target_analysis:
            stats = target_analysis[target]
            stats["block_rate"] = stats["blocked"] / stats["total"] if stats["total"] > 0 else 0
            stats["vulnerability_rate"] = stats["vulnerable"] / stats["total"] if stats["total"] > 0 else 0

        # Analyze payload effectiveness
        payload_analysis = {}
        for vuln in vulnerabilities:
            payload_type = self._categorize_payload(vuln["payload"])
            payload_analysis[payload_type] = payload_analysis.get(payload_type, 0) + 1

        # Get adaptive engine insights
        engine_report = self.adaptive_engine.generate_report()

        return {
            "test_summary": {
                "methodology": "Integrated Security + Playwright + Adaptive Payloads",
                "timestamp": time.time(),
                "total_tests": total_tests,
                "blocked_by_security": blocked_tests,
                "passed_security": successful_tests,
                "vulnerabilities_found": vulnerable_tests,
                "overall_security_effectiveness": blocked_tests / total_tests if total_tests > 0 else 0,
                "vulnerability_discovery_rate": vulnerable_tests / total_tests if total_tests > 0 else 0
            },
            "target_analysis": target_analysis,
            "payload_effectiveness": payload_analysis,
            "adaptive_engine_performance": engine_report,
            "discovered_vulnerabilities": vulnerabilities,
            "detailed_results": test_results[:20],  # First 20 results for brevity
            "security_insights": self._generate_security_insights(test_results, vulnerabilities),
            "recommendations": self._generate_recommendations(target_analysis, vulnerabilities)
        }

    def _categorize_payload(self, payload: str) -> str:
        """Categorize payload type"""
        if "127.0.0.1" in payload or "localhost" in payload:
            return "Internal Network"
        elif "file://" in payload:
            return "File System"
        elif "169.254.169.254" in payload or "metadata" in payload:
            return "Cloud Metadata"
        elif "gopher://" in payload or "dict://" in payload:
            return "Protocol Smuggling"
        else:
            return "Generic SSRF"

    def _generate_security_insights(self, test_results: List[Dict], vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Generate security insights from test results"""

        insights = {}

        # Security layer effectiveness
        layer_effectiveness = {}
        for result in test_results:
            for layer in result["security_results"]["layers_processed"]:
                layer_name = layer["layer"]
                if layer_name not in layer_effectiveness:
                    layer_effectiveness[layer_name] = {"total": 0, "blocked": 0}

                layer_effectiveness[layer_name]["total"] += 1
                if layer["blocked"]:
                    layer_effectiveness[layer_name]["blocked"] += 1

        for layer in layer_effectiveness:
            stats = layer_effectiveness[layer]
            stats["effectiveness"] = stats["blocked"] / stats["total"] if stats["total"] > 0 else 0

        insights["security_layer_effectiveness"] = layer_effectiveness

        # Vulnerability patterns
        if vulnerabilities:
            vuln_by_confidence = {
                "high": len([v for v in vulnerabilities if v["confidence"] >= 0.8]),
                "medium": len([v for v in vulnerabilities if 0.6 <= v["confidence"] < 0.8]),
                "low": len([v for v in vulnerabilities if v["confidence"] < 0.6])
            }
            insights["vulnerability_confidence_distribution"] = vuln_by_confidence

        return insights

    def _generate_recommendations(self, target_analysis: Dict, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations"""

        recommendations = []

        # Analyze target security gaps
        for target_name, stats in target_analysis.items():
            if stats["vulnerability_rate"] > 0.15:  # More than 15% vulnerability rate
                recommendations.append(f"Strengthen security for {target_name}: {stats['vulnerability_rate']:.1%} vulnerability rate")

            if stats["block_rate"] < 0.7:  # Less than 70% block rate
                recommendations.append(f"Improve blocking effectiveness for {target_name}: Only {stats['block_rate']:.1%} blocked")

        # General recommendations
        if len(vulnerabilities) > 5:
            recommendations.append("Consider implementing additional security layers across all targets")

        if any(v["confidence"] >= 0.9 for v in vulnerabilities):
            recommendations.append("High-confidence vulnerabilities found - immediate attention required")

        # Payload-specific recommendations
        payload_types = [self._categorize_payload(v["payload"]) for v in vulnerabilities]
        if payload_types.count("Internal Network") > 2:
            recommendations.append("Multiple internal network access vulnerabilities - review network segmentation")

        if payload_types.count("File System") > 1:
            recommendations.append("File system access vulnerabilities found - review input validation")

        return recommendations

async def main():
    """Run integrated testing suite"""

    print("WTFuzz Integrated SSRF Testing Suite")
    print("Enterprise-grade Security Testing with Advanced Techniques\n")

    tester = IntegratedSSRFTester()

    # Run comprehensive integrated testing
    report = await tester.run_comprehensive_integrated_test()

    # Display comprehensive results
    print(f"\n{'='*80}")
    print("INTEGRATED TESTING RESULTS")
    print(f"{'='*80}")

    summary = report["test_summary"]
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Blocked by Security: {summary['blocked_by_security']} ({summary['overall_security_effectiveness']:.1%})")
    print(f"Passed Security: {summary['passed_security']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']} ({summary['vulnerability_discovery_rate']:.1%})")

    print(f"\nTarget Security Analysis:")
    for target_name, stats in report["target_analysis"].items():
        print(f"  {target_name}:")
        print(f"    Block Rate: {stats['block_rate']:.1%}")
        print(f"    Vulnerability Rate: {stats['vulnerability_rate']:.1%}")
        print(f"    Security Layers: {', '.join(stats['security_layers'])}")

    print(f"\nPayload Effectiveness:")
    for payload_type, count in report["payload_effectiveness"].items():
        print(f"  {payload_type}: {count} vulnerabilities")

    print(f"\nAdaptive Engine Performance:")
    engine_perf = report["adaptive_engine_performance"]["engine_performance"]
    print(f"  Success Rate: {engine_perf['success_rate']:.1%}")
    print(f"  Average Confidence: {engine_perf['avg_confidence']:.1%}")

    if report["discovered_vulnerabilities"]:
        print(f"\nTop Vulnerabilities Found:")
        for i, vuln in enumerate(report["discovered_vulnerabilities"][:5], 1):
            print(f"  {i}. {vuln['target']}")
            print(f"     Type: {vuln['vulnerability_type']}")
            print(f"     Confidence: {vuln['confidence']:.1%}")
            print(f"     Security Bypassed: {vuln['security_bypassed']}")

    print(f"\nSecurity Recommendations:")
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"  {i}. {rec}")

    # Save comprehensive report
    output_file = Path("integrated_testing_results.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"\nComprehensive report saved: {output_file}")

if __name__ == "__main__":
    asyncio.run(main())
