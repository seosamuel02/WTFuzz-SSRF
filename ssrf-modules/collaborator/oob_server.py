"""
OOB (Out-of-Band) Collaborator 서버 - SSRF 블라인드 탐지
DNS/HTTP 인터랙션 캡처로 블라인드 SSRF 탐지
"""

import asyncio
import socket
import json
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import uuid
import re
import logging

# DNS 서버 구현
class DNSServer:
    """DNS 서버 - OOB DNS 쿼리 캡처"""

    def __init__(self, host: str = '0.0.0.0', port: int = 53):
        self.host = host
        self.port = port
        self.interactions = []
        self.running = False
        self.socket = None

    def start(self):
        """DNS 서버 시작"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True

            print(f"[+] DNS 서버 시작: {self.host}:{self.port}")

            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    self._handle_dns_query(data, addr)
                except Exception as e:
                    if self.running:
                        print(f"[!] DNS 쿼리 처리 오류: {e}")

        except Exception as e:
            print(f"[!] DNS 서버 시작 실패: {e}")

    def _handle_dns_query(self, data: bytes, addr: tuple):
        """DNS 쿼리 처리"""
        try:
            # 간단한 DNS 파싱
            query_id = int.from_bytes(data[0:2], 'big')
            flags = int.from_bytes(data[2:4], 'big')

            # 도메인 이름 추출
            domain = self._extract_domain(data[12:])

            interaction = {
                'timestamp': datetime.now().isoformat(),
                'type': 'dns',
                'source_ip': addr[0],
                'source_port': addr[1],
                'query_id': query_id,
                'domain': domain,
                'data': data.hex()
            }

            self.interactions.append(interaction)
            print(f"[DNS] {addr[0]} -> {domain}")

            # DNS 응답 전송 (A 레코드)
            response = self._create_dns_response(data, query_id)
            self.socket.sendto(response, addr)

        except Exception as e:
            print(f"[!] DNS 쿼리 파싱 오류: {e}")

    def _extract_domain(self, data: bytes) -> str:
        """DNS 쿼리에서 도메인 추출"""
        try:
            domain_parts = []
            i = 0

            while i < len(data):
                length = data[i]
                if length == 0:
                    break

                i += 1
                if i + length > len(data):
                    break

                part = data[i:i+length].decode('utf-8', errors='ignore')
                domain_parts.append(part)
                i += length

            return '.'.join(domain_parts)

        except Exception:
            return 'unknown'

    def _create_dns_response(self, query: bytes, query_id: int) -> bytes:
        """DNS 응답 생성"""
        # 기본 DNS 응답 (127.0.0.1로 응답)
        response = bytearray(query)

        # 플래그 설정 (응답, 재귀 가능)
        response[2] = 0x81
        response[3] = 0x80

        # Answer section 추가
        response.extend(b'\xc0\x0c')  # 이름 압축
        response.extend(b'\x00\x01')  # Type A
        response.extend(b'\x00\x01')  # Class IN
        response.extend(b'\x00\x00\x00\x3c')  # TTL (60초)
        response.extend(b'\x00\x04')  # Data length
        response.extend(b'\x7f\x00\x00\x01')  # 127.0.0.1

        # Answer count 설정
        response[6] = 0x00
        response[7] = 0x01

        return bytes(response)

    def stop(self):
        """DNS 서버 중지"""
        self.running = False
        if self.socket:
            self.socket.close()

    def get_interactions(self) -> List[Dict[str, Any]]:
        """DNS 인터랙션 반환"""
        return self.interactions.copy()


# HTTP 서버 구현
class HTTPServer:
    """HTTP 서버 - OOB HTTP 요청 캡처"""

    def __init__(self, host: str = '0.0.0.0', port: int = 80):
        self.host = host
        self.port = port
        self.interactions = []
        self.running = False

    async def start(self):
        """HTTP 서버 시작"""
        try:
            server = await asyncio.start_server(
                self._handle_client, self.host, self.port
            )

            self.running = True
            print(f"[+] HTTP 서버 시작: {self.host}:{self.port}")

            async with server:
                await server.serve_forever()

        except Exception as e:
            print(f"[!] HTTP 서버 시작 실패: {e}")

    async def _handle_client(self, reader, writer):
        """클라이언트 요청 처리"""
        try:
            # HTTP 요청 읽기
            data = await reader.read(4096)
            request = data.decode('utf-8', errors='ignore')

            # 클라이언트 주소
            addr = writer.get_extra_info('peername')

            # 요청 파싱
            lines = request.split('\r\n')
            if lines:
                method_line = lines[0]
                headers = {}

                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

                interaction = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'http',
                    'source_ip': addr[0] if addr else 'unknown',
                    'source_port': addr[1] if addr else 0,
                    'method_line': method_line,
                    'headers': headers,
                    'raw_request': request
                }

                self.interactions.append(interaction)
                print(f"[HTTP] {addr[0] if addr else 'unknown'} -> {method_line}")

            # HTTP 응답 전송
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 15\r\n"
                "\r\n"
                "OOB Server OK\r\n"
            )

            writer.write(response.encode())
            await writer.drain()
            writer.close()

        except Exception as e:
            print(f"[!] HTTP 요청 처리 오류: {e}")

    def stop(self):
        """HTTP 서버 중지"""
        self.running = False

    def get_interactions(self) -> List[Dict[str, Any]]:
        """HTTP 인터랙션 반환"""
        return self.interactions.copy()


# OOB 관리자
class OOBCollaborator:
    """OOB Collaborator - DNS/HTTP 인터랙션 통합 관리"""

    def __init__(self, domain: str = "oob.local", dns_port: int = 53, http_port: int = 80):
        self.domain = domain
        self.dns_server = DNSServer(port=dns_port)
        self.http_server = HTTPServer(port=http_port)

        # 세션 관리
        self.sessions = {}  # session_id -> session_data
        self.payloads = {}  # payload_id -> payload_data

        # 백그라운드 태스크
        self.tasks = []
        self.running = False

    async def start(self):
        """OOB 서버들 시작"""
        print("[+] OOB Collaborator 시작")

        self.running = True

        # DNS 서버 백그라운드 시작
        dns_thread = threading.Thread(target=self.dns_server.start)
        dns_thread.daemon = True
        dns_thread.start()

        # HTTP 서버 시작
        await self.http_server.start()

    def create_session(self, test_name: str = None) -> str:
        """새 테스트 세션 생성"""
        session_id = str(uuid.uuid4())[:8]

        self.sessions[session_id] = {
            'id': session_id,
            'test_name': test_name or f"test_{session_id}",
            'created_at': datetime.now().isoformat(),
            'payloads': [],
            'interactions': []
        }

        print(f"[+] 새 세션 생성: {session_id}")
        return session_id

    def generate_payload(self, session_id: str, payload_type: str = 'dns') -> Dict[str, str]:
        """OOB 페이로드 생성"""
        if session_id not in self.sessions:
            raise ValueError(f"세션을 찾을 수 없음: {session_id}")

        payload_id = str(uuid.uuid4())[:8]

        if payload_type == 'dns':
            payload_url = f"{payload_id}.{session_id}.{self.domain}"
            full_payload = f"http://{payload_url}/"
        elif payload_type == 'http':
            payload_url = f"{self.domain}:{self.http_server.port}/{payload_id}/{session_id}"
            full_payload = f"http://{payload_url}"
        else:
            raise ValueError(f"지원하지 않는 페이로드 타입: {payload_type}")

        payload_data = {
            'payload_id': payload_id,
            'session_id': session_id,
            'type': payload_type,
            'url': payload_url,
            'full_payload': full_payload,
            'created_at': datetime.now().isoformat()
        }

        self.payloads[payload_id] = payload_data
        self.sessions[session_id]['payloads'].append(payload_data)

        return payload_data

    def check_interactions(self, session_id: str, since: datetime = None) -> List[Dict[str, Any]]:
        """세션별 인터랙션 확인"""
        if session_id not in self.sessions:
            return []

        # DNS 인터랙션 확인
        dns_interactions = self.dns_server.get_interactions()
        http_interactions = self.http_server.get_interactions()

        all_interactions = dns_interactions + http_interactions
        session_interactions = []

        for interaction in all_interactions:
            # 세션 ID가 포함된 인터랙션 찾기
            if self._is_session_interaction(interaction, session_id):
                if since is None or datetime.fromisoformat(interaction['timestamp']) > since:
                    session_interactions.append(interaction)

        return session_interactions

    def _is_session_interaction(self, interaction: Dict[str, Any], session_id: str) -> bool:
        """인터랙션이 특정 세션에 속하는지 확인"""
        if interaction['type'] == 'dns':
            domain = interaction.get('domain', '')
            return session_id in domain
        elif interaction['type'] == 'http':
            request = interaction.get('raw_request', '')
            return session_id in request

        return False

    def detect_ssrf(self, session_id: str, timeout: int = 10) -> Dict[str, Any]:
        """SSRF 탐지 결과 반환"""
        if session_id not in self.sessions:
            return {'error': '세션을 찾을 수 없음'}

        session = self.sessions[session_id]
        start_time = datetime.fromisoformat(session['created_at'])

        # 타임아웃 시간까지 대기
        end_time = start_time + timedelta(seconds=timeout)
        interactions = []

        while datetime.now() < end_time:
            interactions = self.check_interactions(session_id, start_time)
            if interactions:
                break
            time.sleep(1)

        # 결과 분석
        result = {
            'session_id': session_id,
            'test_name': session['test_name'],
            'payloads_sent': len(session['payloads']),
            'interactions_received': len(interactions),
            'ssrf_detected': len(interactions) > 0,
            'confidence': self._calculate_confidence(interactions),
            'interactions': interactions,
            'analysis': self._analyze_interactions(interactions)
        }

        return result

    def _calculate_confidence(self, interactions: List[Dict[str, Any]]) -> float:
        """탐지 신뢰도 계산"""
        if not interactions:
            return 0.0

        # 인터랙션 수와 타입을 고려한 신뢰도
        base_confidence = min(len(interactions) * 0.3, 0.9)

        # DNS와 HTTP 모두 있으면 높은 신뢰도
        has_dns = any(i['type'] == 'dns' for i in interactions)
        has_http = any(i['type'] == 'http' for i in interactions)

        if has_dns and has_http:
            base_confidence += 0.1

        return min(base_confidence, 1.0)

    def _analyze_interactions(self, interactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """인터랙션 분석"""
        if not interactions:
            return {'summary': '인터랙션 없음'}

        analysis = {
            'total_interactions': len(interactions),
            'dns_interactions': len([i for i in interactions if i['type'] == 'dns']),
            'http_interactions': len([i for i in interactions if i['type'] == 'http']),
            'unique_sources': len(set(i['source_ip'] for i in interactions)),
            'first_interaction': min(i['timestamp'] for i in interactions),
            'last_interaction': max(i['timestamp'] for i in interactions),
            'domains_queried': [i['domain'] for i in interactions if i['type'] == 'dns'],
            'http_methods': [i['method_line'].split()[0] for i in interactions if i['type'] == 'http' and i['method_line']]
        }

        # 패턴 분석
        if analysis['dns_interactions'] > 0:
            analysis['dns_pattern'] = 'DNS lookup detected - possible blind SSRF'

        if analysis['http_interactions'] > 0:
            analysis['http_pattern'] = 'HTTP request detected - confirmed SSRF'

        return analysis

    def stop(self):
        """OOB 서버들 중지"""
        print("[+] OOB Collaborator 중지")
        self.running = False
        self.dns_server.stop()
        self.http_server.stop()

    def get_session_summary(self) -> Dict[str, Any]:
        """전체 세션 요약"""
        return {
            'total_sessions': len(self.sessions),
            'total_payloads': len(self.payloads),
            'active_sessions': [s for s in self.sessions.values()],
            'server_status': {
                'dns_running': self.dns_server.running,
                'http_running': self.http_server.running
            }
        }


async def main():
    """테스트 실행"""
    collaborator = OOBCollaborator(domain="ssrf-test.local")

    try:
        # 서버 시작 (실제 환경에서는 별도 프로세스로 실행)
        print("OOB Collaborator 테스트 시작")

        # 테스트 세션 생성
        session_id = collaborator.create_session("SSRF Test")

        # DNS 페이로드 생성
        dns_payload = collaborator.generate_payload(session_id, 'dns')
        print(f"DNS 페이로드: {dns_payload['full_payload']}")

        # HTTP 페이로드 생성
        http_payload = collaborator.generate_payload(session_id, 'http')
        print(f"HTTP 페이로드: {http_payload['full_payload']}")

        print("\n실제 테스트에서는 이 페이로드들을 SSRF 취약점에 전송하고")
        print("10초 후 결과를 확인합니다...")

        # 10초 대기 후 결과 확인
        await asyncio.sleep(10)

        result = collaborator.detect_ssrf(session_id, timeout=5)
        print("\n=== SSRF 탐지 결과 ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    except KeyboardInterrupt:
        print("\n[!] 사용자 중단")
    finally:
        collaborator.stop()


if __name__ == "__main__":
    asyncio.run(main())