"""
멀티레이어 SSRF 탐지 시스템 - 4계층 간접 신호 분석
"""

import time
import re
import statistics
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class TimingData:
    """타이밍 데이터 구조"""
    total_time: float
    dns_time: float
    connect_time: float
    response_time: float
    redirect_time: float = 0.0


@dataclass
class DetectionResult:
    """탐지 결과 구조"""
    ssrf_detected: bool
    confidence: float
    detection_layers: Dict[str, float]
    evidence: List[str]
    risk_level: str
    recommended_actions: List[str]


class TimingDetector:
    """1계층: 타이밍 기반 탐지"""

    def __init__(self):
        self.baseline_times = {}
        self.timeout_threshold = 10.0  # 10초
        self.dns_delay_threshold = 100  # 100ms

    def analyze_timing_patterns(self, payload: str, timing: TimingData, baseline: Optional[TimingData] = None) -> Dict[str, Any]:
        """타이밍 패턴 분석"""
        results = {
            'score': 0.0,
            'indicators': [],
            'anomalies': []
        }

        # DNS 해석 지연 분석
        dns_score = self._analyze_dns_timing(timing)
        results['score'] += dns_score * 0.3

        if dns_score > 0.5:
            results['indicators'].append(f'DNS resolution delay: {timing.dns_time:.2f}ms')

        # 연결 타임아웃 패턴
        timeout_score = self._analyze_timeout_patterns(timing)
        results['score'] += timeout_score * 0.3

        if timeout_score > 0.5:
            results['indicators'].append(f'Connection timeout pattern detected')

        # 응답 시간 변화
        if baseline:
            response_score = self._analyze_response_time_changes(timing, baseline)
            results['score'] += response_score * 0.4

            if response_score > 0.5:
                time_diff = abs(timing.total_time - baseline.total_time)
                results['indicators'].append(f'Response time change: {time_diff:.2f}s')

        # 포트 스캔 패턴 탐지
        port_scan_score = self._detect_port_scan_pattern(timing)
        if port_scan_score > 0.5:
            results['score'] += port_scan_score * 0.3
            results['indicators'].append('Port scanning pattern detected')

        return results

    def _analyze_dns_timing(self, timing: TimingData) -> float:
        """DNS 해석 시간 분석"""
        if timing.dns_time > self.dns_delay_threshold:
            # 외부 DNS 해석으로 인한 지연
            delay_score = min(timing.dns_time / 1000.0, 1.0)  # 1초 = 1.0점
            return delay_score
        return 0.0

    def _analyze_timeout_patterns(self, timing: TimingData) -> float:
        """타임아웃 패턴 분석"""
        if timing.total_time >= self.timeout_threshold:
            # 완전한 타임아웃
            return 0.9
        elif timing.connect_time > 5.0:
            # 연결 지연
            return 0.6
        elif timing.response_time > 3.0:
            # 응답 지연
            return 0.4
        return 0.0

    def _analyze_response_time_changes(self, timing: TimingData, baseline: TimingData) -> float:
        """기준점 대비 응답 시간 변화 분석"""
        time_diff = abs(timing.total_time - baseline.total_time)

        if time_diff > 5.0:
            return 0.8
        elif time_diff > 2.0:
            return 0.6
        elif time_diff > 0.5:
            return 0.3
        return 0.0

    def _detect_port_scan_pattern(self, timing: TimingData) -> float:
        """포트 스캔 패턴 탐지"""
        # 빠른 응답: 포트 닫힘 (connection refused)
        if timing.total_time < 0.1 and timing.connect_time < 0.05:
            return 0.7

        # 느린 응답: 포트 필터링 또는 열림
        if timing.total_time > 5.0 and timing.connect_time > 2.0:
            return 0.6

        return 0.0


class PatternDetector:
    """2계층: 응답 패턴 분석"""

    def __init__(self):
        self.normal_baselines = {}
        self.error_signatures = self._load_error_signatures()

    def analyze_response_patterns(self, payload: str, response: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """응답 패턴 변화 분석"""
        results = {
            'score': 0.0,
            'indicators': [],
            'detected_errors': []
        }

        # 상태 코드 변화
        status_score = self._analyze_status_changes(response, baseline)
        results['score'] += status_score * 0.25

        # 콘텐츠 길이 변화
        length_score = self._analyze_content_length_changes(response, baseline)
        results['score'] += length_score * 0.20

        # 헤더 변화
        header_score = self._analyze_header_changes(response, baseline)
        results['score'] += header_score * 0.15

        # 에러 메시지 탐지
        error_score, detected_errors = self._detect_error_messages(response.get('content', ''))
        results['score'] += error_score * 0.30
        results['detected_errors'] = detected_errors

        # 리다이렉트 체인 분석
        redirect_score = self._analyze_redirect_chains(response)
        results['score'] += redirect_score * 0.10

        # 지표 수집
        if status_score > 0.5:
            results['indicators'].append(f"Status code change: {response.get('status_code')}")

        if length_score > 0.5:
            results['indicators'].append(f"Content length anomaly: {len(response.get('content', ''))}")

        if detected_errors:
            results['indicators'].append(f"Error signatures: {', '.join(detected_errors[:3])}")

        return results

    def _analyze_status_changes(self, response: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> float:
        """상태 코드 변화 분석"""
        current_status = response.get('status_code', 200)

        # 특정 상태 코드는 SSRF 지표
        ssrf_status_codes = {
            500: 0.6,  # Internal Server Error
            502: 0.8,  # Bad Gateway
            503: 0.7,  # Service Unavailable
            504: 0.9,  # Gateway Timeout
            403: 0.4,  # Forbidden (internal resource)
            404: 0.3,  # Not Found (internal resource)
        }

        if current_status in ssrf_status_codes:
            score = ssrf_status_codes[current_status]

            # 기준점과 비교하여 점수 조정
            if baseline and baseline.get('status_code') != current_status:
                score += 0.2  # 변화 자체가 지표

            return min(score, 1.0)

        # 기준점과의 변화만 확인
        if baseline and baseline.get('status_code', 200) != current_status:
            return 0.3

        return 0.0

    def _analyze_content_length_changes(self, response: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> float:
        """콘텐츠 길이 변화 분석"""
        current_length = len(response.get('content', ''))

        if not baseline:
            return 0.0

        baseline_length = len(baseline.get('content', ''))

        if baseline_length == 0:
            return 0.0

        # 상대적 변화율 계산
        length_change = abs(current_length - baseline_length) / baseline_length

        if length_change > 0.8:  # 80% 이상 변화
            return 0.7
        elif length_change > 0.5:  # 50% 이상 변화
            return 0.5
        elif length_change > 0.2:  # 20% 이상 변화
            return 0.3

        return 0.0

    def _analyze_header_changes(self, response: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> float:
        """헤더 변화 분석"""
        current_headers = response.get('headers', {})

        # SSRF 지표가 될 수 있는 헤더
        ssrf_headers = [
            'server', 'x-powered-by', 'x-internal',
            'x-forwarded-for', 'x-real-ip', 'via'
        ]

        score = 0.0
        for header in ssrf_headers:
            if header.lower() in [h.lower() for h in current_headers.keys()]:
                score += 0.1

        # 기준점과 헤더 개수 비교
        if baseline:
            baseline_headers = baseline.get('headers', {})
            header_count_diff = abs(len(current_headers) - len(baseline_headers))

            if header_count_diff > 3:
                score += 0.3

        return min(score, 1.0)

    def _detect_error_messages(self, content: str) -> Tuple[float, List[str]]:
        """에러 메시지 탐지"""
        detected_errors = []
        total_score = 0.0

        for pattern, info in self.error_signatures.items():
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                detected_errors.append(info['description'])
                total_score += info['score']

        return min(total_score, 1.0), detected_errors

    def _analyze_redirect_chains(self, response: Dict[str, Any]) -> float:
        """리다이렉트 체인 분석"""
        redirect_history = response.get('redirect_history', [])

        if len(redirect_history) > 3:
            return 0.6  # 긴 리다이렉트 체인
        elif len(redirect_history) > 1:
            return 0.3  # 리다이렉트 존재

        return 0.0

    def _load_error_signatures(self) -> Dict[str, Dict[str, Any]]:
        """SSRF 관련 에러 시그니처 로드"""
        return {
            r'connection\s+refused': {
                'description': 'Connection refused',
                'score': 0.8
            },
            r'network\s+is\s+unreachable': {
                'description': 'Network unreachable',
                'score': 0.9
            },
            r'host\s+not\s+found': {
                'description': 'Host not found',
                'score': 0.7
            },
            r'connection\s+timed?\s*out': {
                'description': 'Connection timeout',
                'score': 0.8
            },
            r'curl_exec\(\)\s+failed': {
                'description': 'cURL execution failed',
                'score': 0.9
            },
            r'file_get_contents.*failed\s+to\s+open\s+stream': {
                'description': 'PHP file_get_contents failed',
                'score': 0.8
            },
            r'java\.net\.ConnectException': {
                'description': 'Java connection exception',
                'score': 0.8
            },
            r'requests\.exceptions\.ConnectionError': {
                'description': 'Python requests connection error',
                'score': 0.8
            },
            r'nodename\s+nor\s+servname\s+provided': {
                'description': 'DNS resolution error',
                'score': 0.7
            },
            r'couldn\'t\s+connect\s+to\s+host': {
                'description': 'Generic connection failure',
                'score': 0.6
            }
        }


class ContextAnalyzer:
    """4계층: 컨텍스트 기반 분석"""

    def analyze_endpoint_context(self, endpoint_info: Dict[str, Any], responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """엔드포인트 컨텍스트 기반 SSRF 가능성 분석"""
        results = {
            'score': 0.0,
            'risk_factors': [],
            'context_indicators': []
        }

        # URL 파라미터 분석
        url_score = self._analyze_url_parameters(endpoint_info)
        results['score'] += url_score * 0.3

        # 파일 업로드/다운로드 기능 분석
        file_score = self._analyze_file_operations(endpoint_info)
        results['score'] += file_score * 0.25

        # 외부 API 연동 기능 분석
        api_score = self._analyze_api_integration(endpoint_info)
        results['score'] += api_score * 0.2

        # Webhook/콜백 기능 분석
        webhook_score = self._analyze_webhook_functionality(endpoint_info)
        results['score'] += webhook_score * 0.25

        # 지표 수집
        if url_score > 0.5:
            results['context_indicators'].append('URL parameter manipulation possible')

        if file_score > 0.5:
            results['context_indicators'].append('File operation functionality detected')

        if api_score > 0.5:
            results['context_indicators'].append('External API integration detected')

        if webhook_score > 0.5:
            results['context_indicators'].append('Webhook/callback functionality detected')

        return results

    def _analyze_url_parameters(self, endpoint_info: Dict[str, Any]) -> float:
        """URL 파라미터 분석"""
        ssrf_params = endpoint_info.get('ssrf_parameters', [])

        if not ssrf_params:
            return 0.0

        # 고위험 파라미터 가중치
        high_risk_patterns = ['url', 'uri', 'link', 'redirect', 'callback']
        medium_risk_patterns = ['fetch', 'load', 'import', 'file', 'path']

        score = 0.0
        for param in ssrf_params:
            param_name = param.get('name', '').lower()

            for pattern in high_risk_patterns:
                if pattern in param_name:
                    score += 0.4
                    break
            else:
                for pattern in medium_risk_patterns:
                    if pattern in param_name:
                        score += 0.2
                        break

        return min(score, 1.0)

    def _analyze_file_operations(self, endpoint_info: Dict[str, Any]) -> float:
        """파일 작업 기능 분석"""
        url = endpoint_info.get('url', '').lower()
        endpoint_type = endpoint_info.get('endpoint_type', '')

        file_indicators = [
            'upload', 'download', 'file', 'import',
            'export', 'backup', 'restore'
        ]

        score = 0.0
        for indicator in file_indicators:
            if indicator in url:
                score += 0.3

        if endpoint_type == 'file_upload':
            score += 0.5

        return min(score, 1.0)

    def _analyze_api_integration(self, endpoint_info: Dict[str, Any]) -> float:
        """API 연동 기능 분석"""
        url = endpoint_info.get('url', '').lower()
        endpoint_type = endpoint_info.get('endpoint_type', '')

        api_indicators = [
            '/api/', 'webhook', 'callback', 'proxy',
            'forward', 'fetch', 'external'
        ]

        score = 0.0
        for indicator in api_indicators:
            if indicator in url:
                score += 0.25

        if endpoint_type in ['api', 'proxy', 'webhook']:
            score += 0.5

        return min(score, 1.0)

    def _analyze_webhook_functionality(self, endpoint_info: Dict[str, Any]) -> float:
        """Webhook/콜백 기능 분석"""
        url = endpoint_info.get('url', '').lower()
        parameters = endpoint_info.get('ssrf_parameters', [])

        webhook_indicators = ['webhook', 'callback', 'notify', 'ping']

        score = 0.0

        # URL에서 webhook 지표 확인
        for indicator in webhook_indicators:
            if indicator in url:
                score += 0.4

        # 파라미터에서 콜백 URL 확인
        for param in parameters:
            param_name = param.get('name', '').lower()
            if any(indicator in param_name for indicator in webhook_indicators):
                score += 0.3

        return min(score, 1.0)


class MultiLayerSSRFDetector:
    """통합 멀티레이어 SSRF 탐지 시스템"""

    def __init__(self):
        self.timing_detector = TimingDetector()
        self.pattern_detector = PatternDetector()
        self.context_analyzer = ContextAnalyzer()

        # 가중치 설정
        self.layer_weights = {
            'timing': 0.25,
            'pattern': 0.35,
            'context': 0.25,
            'oob': 0.15  # OOB는 별도 처리
        }

    def comprehensive_detection(self,
                              payload: str,
                              response: Dict[str, Any],
                              timing_data: TimingData,
                              endpoint_info: Dict[str, Any],
                              baseline_response: Optional[Dict[str, Any]] = None,
                              baseline_timing: Optional[TimingData] = None,
                              oob_result: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """종합적 SSRF 탐지"""

        detection_layers = {}
        all_evidence = []

        # 1계층: 타이밍 분석
        timing_result = self.timing_detector.analyze_timing_patterns(
            payload, timing_data, baseline_timing
        )
        detection_layers['timing'] = timing_result['score']
        all_evidence.extend(timing_result['indicators'])

        # 2계층: 패턴 분석
        pattern_result = self.pattern_detector.analyze_response_patterns(
            payload, response, baseline_response
        )
        detection_layers['pattern'] = pattern_result['score']
        all_evidence.extend(pattern_result['indicators'])

        # 4계층: 컨텍스트 분석
        context_result = self.context_analyzer.analyze_endpoint_context(
            endpoint_info, [response]
        )
        detection_layers['context'] = context_result['score']
        all_evidence.extend(context_result['context_indicators'])

        # 3계층: OOB 결과 (별도 처리)
        oob_score = 0.0
        if oob_result and oob_result.get('confirmed'):
            oob_score = 1.0  # OOB 확인시 최고점
            all_evidence.append(f"OOB interaction confirmed: {oob_result['type']}")

        detection_layers['oob'] = oob_score

        # 가중 평균 계산
        final_score = sum(
            detection_layers[layer] * self.layer_weights[layer]
            for layer in detection_layers
        )

        # 결과 생성
        return self._generate_detection_result(
            final_score, detection_layers, all_evidence, endpoint_info
        )

    def _generate_detection_result(self,
                                 final_score: float,
                                 detection_layers: Dict[str, float],
                                 evidence: List[str],
                                 endpoint_info: Dict[str, Any]) -> DetectionResult:
        """탐지 결과 생성"""

        # 신뢰도 계산 (다층 합의 기반)
        active_layers = sum(1 for score in detection_layers.values() if score > 0.3)
        confidence = final_score * (active_layers / 4)  # 4개 계층

        # SSRF 탐지 여부
        ssrf_detected = final_score > 0.6

        # 위험도 분류
        if final_score >= 0.8:
            risk_level = 'critical'
        elif final_score >= 0.6:
            risk_level = 'high'
        elif final_score >= 0.4:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        # 권장 조치
        recommended_actions = self._generate_recommendations(
            final_score, detection_layers, endpoint_info
        )

        return DetectionResult(
            ssrf_detected=ssrf_detected,
            confidence=confidence,
            detection_layers=detection_layers,
            evidence=evidence,
            risk_level=risk_level,
            recommended_actions=recommended_actions
        )

    def _generate_recommendations(self,
                                final_score: float,
                                detection_layers: Dict[str, float],
                                endpoint_info: Dict[str, Any]) -> List[str]:
        """권장 조치 생성"""
        recommendations = []

        if final_score > 0.8:
            recommendations.append("즉시 보안팀에 보고")
            recommendations.append("해당 엔드포인트 임시 차단 고려")

        if detection_layers.get('oob', 0) > 0.5:
            recommendations.append("OOB 상호작용 로그 수집 및 분석")

        if detection_layers.get('timing', 0) > 0.6:
            recommendations.append("네트워크 타이밍 패턴 모니터링 강화")

        if detection_layers.get('pattern', 0) > 0.6:
            recommendations.append("응답 패턴 기반 탐지 규칙 추가")

        if endpoint_info.get('endpoint_type') in ['api', 'webhook']:
            recommendations.append("API 엔드포인트 입력 검증 강화")

        return recommendations


def main():
    """테스트 실행"""
    detector = MultiLayerSSRFDetector()

    # 샘플 데이터
    payload = "http://127.0.0.1:22/"
    response = {
        'status_code': 502,
        'content': 'Connection refused to 127.0.0.1:22',
        'headers': {'server': 'nginx/1.18.0'},
        'redirect_history': []
    }

    timing_data = TimingData(
        total_time=5.2,
        dns_time=50.0,
        connect_time=5.0,
        response_time=0.2
    )

    endpoint_info = {
        'url': 'http://example.com/api/fetch',
        'method': 'POST',
        'endpoint_type': 'api',
        'ssrf_parameters': [
            {'name': 'url', 'type': 'text', 'location': 'body'}
        ]
    }

    print("=== 멀티레이어 SSRF 탐지 시스템 테스트 ===")

    result = detector.comprehensive_detection(
        payload, response, timing_data, endpoint_info
    )

    print(f"\nSSRF 탐지: {result.ssrf_detected}")
    print(f"신뢰도: {result.confidence:.2%}")
    print(f"위험도: {result.risk_level}")

    print(f"\n계층별 점수:")
    for layer, score in result.detection_layers.items():
        print(f"  {layer}: {score:.2f}")

    if result.evidence:
        print(f"\n탐지 증거:")
        for evidence in result.evidence:
            print(f"  - {evidence}")

    if result.recommended_actions:
        print(f"\n권장 조치:")
        for action in result.recommended_actions:
            print(f"  - {action}")


if __name__ == "__main__":
    main()