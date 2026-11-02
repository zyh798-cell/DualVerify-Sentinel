<div align="center">

# DualVerify-Sentinel

**결정론적·인가 게이트 기반 보안 검증 엔진.**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 Stable · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — 픽셀 스타일 애니메이션 배너. 타이틀이 한 글자씩 나타나고 스캔라인과 데이터 플로우 효과가 흐릅니다" width="720">

**DualVerify-Sentinel — Deterministic Security Validation Engine**
⚠️ **AUTHORIZED SECURITY TESTING ONLY**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](#4-요구-사항)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](#10-알려진-제한-사항)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#11-프로젝트-현황)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#11-프로젝트-현황)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · **한국어** · [Español](README.es.md) · [Français](README.fr.md)

</div>

---

## 1. 이것은 무엇인가?

DualVerify-Sentinel은 **규칙 기반(rule-based) 보안 검증 엔진**입니다
(명시적으로 **모델 기반이 아님**). 모든 실행 단계는 기계 판독 가능한 인가 스코프에
대해 정책 검사를 거치고, 변조 탐지 가능한 해시 체인 감사 저널에 기록되며,
**페일 클로즈드(fail-closed)**로 동작합니다 — 인가가 없거나, 손상되었거나,
만료되었다면 *거부*될 뿐, 검사가 생략되는 일은 없습니다.

Gen-1은 결정론적·정책 기반 보안 검증 엔진이며, **자율 LLM 에이전트가 아닙니다**.
계획/의사결정 계층은 의도적으로 결정론적으로 유지됩니다. 차세대 검증 아키텍처
(인가 게이트 + 신뢰성 높은 실행 엔진)의 보안 엔지니어링 기반 계층입니다.

## 2. 무엇을 할 수 있나?

| 기능 | 동작 방식 |
|---|---|
| 인가 게이트 | 기계 판독 가능한 scope JSON을 **격리된 서브프로세스**에서 검증. 누락/손상/만료 → REFUSED (종료 코드 2). 우회 경로는 존재하지 않습니다. |
| 실행 티켓 (RunTicket) | 어댑터는 정책 엔진이 발급한 티켓만 수용. 스코프 해시·모드·대상·윈도우를 **실행 시점에 재차 독립 검증**. |
| 안전한 실행 | 단계별 12항목 검사 체인. 파괴적 기법 없음, 지속화(persistence) 없음, 페이로드 제작 없음, 발견된 데이터의 외부 전송 없음. |
| 감사 저널 | 추가 전용 해시 체인 (`seq`/`prev`/`h`, SHA-256). 변조/재정렬 탐지. 감사 장애는 종료 코드 3으로 종료되며 정상 결과로 위장하지 않습니다. |
| 결정론적 의사결정 루프 | 명시적 규칙 P0–P8: 거부/중단/실패가 하나라도 있으면 루프를 중지. 대상은 **절대** 확장되지 않습니다. |
| 태스크 그래프 | 하드 예산이 적용된 상태 머신 (최대 32노드, 스폰 깊이 2, 스폰 8회). 동적 스폰은 부모 COMPLETED를 전제로 합니다. |
| 선택적 도구 어댑터 | `nuclei` (템플릿 스캔)와 `bandit` (정적 분석) — 미설치 시 preflight 리포트와 함께 정상적으로 SKIPPED. |
| 정직한 리포팅 | 발견 사항은 그대로 기록. 검증되지 않은 출력은 확인된 취약점으로 표시되지 않음. 알려진 제한 사항은 모든 리포트에 나열. |

## 3. 사용 사례

- 자신이 소유하거나 운영하는 랩 대상, 명시적으로 인가된 호스트의 검증.
- 완전한 감사 추적을 갖춘, 재현 가능하고 증거를 산출하는 보안 검사 실행.
- 상위 수준 검증 파이프라인을 구축하기 위한 기반 계층.

## 4. 요구 사항

| 요구 사항 | 상세 |
|---|---|
| Python | >= 3.10 (3.13.14에서만 테스트됨) |
| 서드파티 의존성 | **없음** — 표준 라이브러리만 사용 |
| 운영체제 | Windows **검증됨**; Linux/macOS **아직 미검증** |
| 외부 도구 (선택) | `nuclei`, `bandit` — 없으면 정상적으로 건너뜀 |

## 5. 설치

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

pip install .
```

개발용 편집 설치(editable install) `pip install -e .`도 지원됩니다.

## 6. 기본 사용법

**1단계 — scope 파일 검증 (반드시 먼저 수행):**

```bash
dvs gate-check scripts/example-scope.json
# 종료 코드 0 = 스코프 유효 · 1 = 거부
```

**2단계 — 검증 실행:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# 또는: python -m vuln_hunter run --scope ... --mode ... --target ...
```

모드 (위험 상한 증가 순): `passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk` (R0–R4). `nuclei`는 R2 이상에서만 호출됩니다.

종료 코드: `0` 모든 단계 COMPLETED · `1` 실패/거부와 함께 완료 ·
`2` 게이트/정책 수준 거부 (아무것도 실행되지 않음) · `3` **감사 장애**
(저널 기록 불가/검증 불가 — 결과는 인증되지 않음).

`scripts/example-scope.json`은 가상의 예시이며 **실제 인가 기록이 아닙니다**.

## 7. 스코프 의미론

- 항목은 **파싱된 호스트명 일치**로 판별됩니다 (포트 없는 항목은 해당 호스트의
  임의 포트와 일치). **CIDR 범위는 지원되지 않습니다** — `host` 또는
  `host:port` 항목을 사용하세요.
- 인가 윈도우는 **모든 실행 단계마다** 재검사되며, 실행 중 만료 시 이후 단계를
  중단합니다.
- 스코프 내용의 해시는 각 실행 티켓에 바인딩되며, 스코프 변경 시 미완료 티켓은
  무효화됩니다.
- 파일시스템 스코프 단계는 네트워크 스코프 검사만 건너뛰고, 나머지 정책 검사는
  그대로 적용됩니다.

## 8. 인가와 안전

> ⚠️ **이 도구는 자신이 소유하거나 운영하는 시스템, 로컬 랩 대상, 또는 소유자의
> 명시적인 서면 인가를 보유한 호스트에만 사용하세요.** 무단, 범위 외, 윈도우
> 만료, 손상된 구성은 거부됩니다 (페일 클로즈드). 인가를 건너뛰는 코드 경로는
> 존재하지 않습니다.

번들된 예시 스코프는 가상의 것입니다. 실제 업무에는 실제의, 기계 판독 가능한
인가 기록이 필요합니다 — 이 저장소 외부에 보관하세요.

## 9. API 강화는 샌드박스가 아닙니다

RunTicket의 frozen dataclass와 프라이빗 레지스트리는 **API 강화**이지 샌드박스가
아닙니다 — 악의적인 프로세스 내 코드는 모든 Python 수준 검사를 우회할 수
있습니다. 강한 격리에는 프로세스 수준 조치가 필요합니다 (미구현). CLI가 유일하게
지원되는 진입점입니다.

## 10. 알려진 제한 사항

1. **프로세스 내 샌드박스 없음** — 섹션 9 참조.
2. **Windows 우선** — Windows의 타임아웃 경로는 필드화된 프로세스 트리 정리를
   수행합니다 (루트 kill 전에 `taskkill /T /F`를 먼저 실행하고 모든 결과를
   기록). 관리된 3계층 프로세스 트리 훈련에서 검증되었으나 **절대적 보장은
   아닙니다** (런타임 잔존 확인 없음; taskkill의 rc=0은 트리 전체 정리 완료를
   의미하지 않음; 실제 Nuclei 자손 프로세스 형태는 미검증). 비 Windows
   플랫폼에서는 트리 kill이 건너뛰어집니다 (루트만 kill). nuclei 경로 폴백은
   특정 로컬 `~/Tools/nuclei/` 레이아웃을 가정합니다.
3. **탐지 정확성 미보장** — 도구 출력은 그대로 기록되며, 검증되지 않은 결과는
   확인된 취약점으로 표시되지 않습니다.
4. **Linux/macOS 미검증** — CI는 비 Windows 플랫폼을 다루지 않습니다.
5. **저널 말단(truncation) 잘림** — 외부에 head 앵커를 저장한 경우에만 탐지
   가능. 리포트 내 앵커는 일관성 확인용입니다.
6. **Gen-1 플래너는 정적 템플릿** — 계획은 결정론적이며, 모델 기반이나 적응적이지
   않습니다.

## 11. 프로젝트 현황

- **Gen-1은 안정(stable)**: 18개 오프라인 테스트 스위트, 427개 이상 검사가
  로컬에서 통과 (Windows, Python 3.13.14). wheel/sdist 빌드로 패키징 스모크
  테스트 완료.
- **Gen-2 아키텍처**(별도의 미래 저장소)가 제안/판정 분리와 함께 계획되어
  있습니다. Gen-2 작업은 이 저장소에서 진행되지 않습니다.
- 전체 테스트 명령은 `tests/` 아래의 스위트에 나열되어 있습니다 — 실행하고 실제
  결과를 신뢰하세요. 이 저장소는 사전에 "전부 통과"라고 주장하지 않습니다.

## 12. 라이선스 및 피드백

- **라이선스**: MIT — [LICENSE](../../LICENSE) 참조.
- **보안 정책**: [SECURITY.md](../../SECURITY.md) 참조.
- **기여 가이드**: [CONTRIBUTING.md](../../CONTRIBUTING.md) 참조.
- Issue와 Pull Request를 환영합니다. 보안 관련 제보는 공개 issue를 열지 말고
  SECURITY.md의 안내를 따라주세요.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
