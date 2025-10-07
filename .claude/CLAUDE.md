# WTFuzz - SSRF 블랙박스 퍼저

OWASP WSTG 표준 기반 블랙박스 SSRF 취약점 탐지 도구

## 🎯 목표
- 크롤러 JSON → SSRF 퍼징 자동화
- 블랙박스 환경에서 간접 신호 탐지
- OWASP WSTG-INPV-19 표준 준수
- 버그바운티 실전 활용

## 🏗️ 기본 아키텍처
```
ssrf-modules/
├── input/                    # 크롤러 JSON 연동
├── fuzzer/                   # 기본 퍼징 엔진
│   ├── payloads/            # OWASP WSTG 표준 페이로드
│   └── engine.py            # 퍼징 로직
├── detector/                 # OWASP 표준 탐지 방법
│   ├── timing_analysis.py   # 타이밍 기반 분석
│   ├── pattern_matcher.py   # 응답 패턴 분석
│   └── error_analyzer.py    # 에러 메시지 분석
├── test/                     # 테스트 환경
│   └── real_world_test.py   # 실제 환경 테스트
└── config/                   # 기본 설정
    └── payloads.json        # 페이로드 DB
```

## 🧠 핵심 기능 (OWASP WSTG 기반)
- **표준 SSRF 탐지**: 타이밍 + 응답 패턴 + 에러 분석
- **기본 페이로드 세트**: localhost, 127.0.0.1, file://, 내부망 스캔
- **Playwright 연동**: 실제 브라우저 환경 테스트
- **취약한 앱 테스트**: DVWA, WebGoat, bWAPP 지원

## 📋 개발 명령어
| 명령 | 설명 |
|------|------|
| `python -m venv venv && venv\Scripts\activate` | 가상환경 생성/활성화 |
| `pip install -r requirements.txt` | 의존성 설치 |
| `python fuzzer/main.py --input crawler_results.json` | SSRF 퍼징 실행 |
| `python collaborator/server.py --domain ssrf-test.local` | OOB 서버 실행 |

## 🔧 MCP 서버 활용
- **context7**: 최신 우회 기법 연구
- **playwright**: 동적 테스트 수행
- **notion**: 프로젝트 진행 추적


# Add to memory.
- Use Context7 to check up-to-data docs when needed for implementing new libraries or framworks, or adding features using them.
- When you answer, answer in Korean.
- The reason I make a black box SRF fuzzer is that I'm trying to find a cve by writing it in a bugbounty.
- Don't use an emoji when commenting on the code.
- Claude must never truncate or summarize code outputs. If the response is cut off, it must internally remember the last generated section and resume seamlessly when the user types "continue", "go on", or "more".
- Claude must treat any long code output as a multi-part sequence. If the code exceeds 700 lines, do NOT summarize or stop. Instead, automatically continue generating until the entire program is complete.
- Never summarize long code or omit sections for brevity.

