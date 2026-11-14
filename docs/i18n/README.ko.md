<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel logo — deep navy shield with dual verification check, cyan orbit nodes and the DVS wordmark" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**명시적 인가, 결정적 실행, 검증 가능한 증거를 중심으로 설계된 정책 기반 보안 검증 엔진.**

결정적 실행 · 명시적 인가 경계 · 감사 가능한 보안 증거.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel banner — shield mark, project name, one-line description and authorized-testing-only notice" width="720">

[![Star on GitHub](https://img.shields.io/badge/Star_on-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Star](https://img.shields.io/badge/Star-grey?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#sec-7)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#sec-3)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#sec-5)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#sec-8)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · **한국어** · [Español](README.es.md) · [Français](README.fr.md)

[개요](#sec-1) · [구현 기능](#sec-2) · [빠른 시작](#sec-4) · [인가와 안전](#sec-5) · [플랫폼 테스트](#sec-7) · [기여](#sec-9) · [Security](../../SECURITY.md)

> ⭐ **프로젝트가 도움이 된다면 Star를 눌러 주세요. 커뮤니티 테스트와 기여도 환영합니다.**

> ⚠️ **인가된 보안 테스트 전용**

</div>

---

<a id="sec-1"></a>
## 1. DualVerify-Sentinel이란?

DualVerify-Sentinel(DVS)는 **정책 기반 보안 검증 엔진**입니다. 모든 실행 단계는 기계가 읽을 수 있는 인가 범위에 대해 검사되고, 변조를 탐지할 수 있는 증거 저널에 기록되며, **실패 시 거부(fail-closed)** 방식으로 동작합니다. 인가가 없거나 손상되었거나 만료된 경우 검사를 건너뛰지 않고 거부합니다.

이는 보안 엔지니어링의 기반 계층, 즉 인가 게이트와 결정적 실행 엔진입니다. Gen-1의 계획 계층은 **정적 규칙 기반 템플릿**이며, 모델 기반 또는 적응형 플래너가 아닙니다.

**현재 DVS가 아닌 것**: 범용 에이전트 플랫폼, LLM 에이전트 런타임, 모델 기반 자율 의사결정 시스템, OS 수준 샌드박스. 이들은 장기 방향이며 현재 기능이 아닙니다.

<a id="sec-2"></a>
## 2. 현재 구현된 기능

아래 기능은 모델 판단이 아니라 명시적 코드 경로로 강제됩니다.

| 기능 | 구현 내용 |
|---|---|
| **명시적 인가** | 범위 JSON을 **독립 서브프로세스**에서 검증합니다. 실행 시 범위 해시, 모드, 대상, 시간 창을 다시 독립적으로 확인합니다. 누락·손상·만료 → 거부하며 우회 경로가 없습니다. |
| **정책 기반 실행** | 위험 상한이 점증하는 5개 모드: `passive`(R0), `safe_scan`(R1), `vuln_validation`(R2), `attack_simulation`(R3), `high_risk`(R4). 명시적 결정 규칙은 거부·중단·실패 시 루프를 멈추며, 대상 범위를 확장하지 않습니다. |
| **위험 인지 제어** | TaskGraph 상태 머신에 하드 예산(최대 32 노드, 파생 깊이 2, 파생 8회), 부모 COMPLETED 상태를 조건으로 하는 동적 파생, 단계별 12단계 검사 체인. 파괴적 기법, 지속성, 페이로드 생성, 발견 데이터 유출을 사용하지 않습니다. |
| **보안 도구 연동** | 핵심 어댑터 `nuclei` / `bandit`, 그리고 `vuln_hunter/adapters_ext/`의 선택적 `gitleaks` / `semgrep` 어댑터(로컬 규칙 파일만 사용, 네트워크에서 규칙을 가져오지 않음). 모든 출력은 통합 Finding Schema(`findings.py`)로 정규화됩니다. 바이너리가 없으면 사전 보고와 함께 안전하게 건너뜁니다. |
| **검증 가능한 감사 증거** | 추가 전용 SHA-256 해시 체인(`seq` / `prev` / `h`)으로 변조와 순서 변경을 탐지합니다. 감사 실패는 종료 코드 3으로 명시되며, 인증되지 않은 결과를 정상 결과로 위장하지 않습니다. |
| **정직하고 구조화된 보고** | 발견 항목은 있는 그대로 기록하고, 검증되지 않은 도구 출력을 확인된 취약점으로 표시하지 않으며, 모든 보고서에 알려진 제한을 기재합니다. 탐지 정확도나 정답률을 주장하지 않습니다. |

> 어댑터는 **코드로 구현되어 있습니다**. 코드의 존재는 실제 도구 실행 검증의 증거가 아닙니다. 실제 도구 종단 간 검증은 아직 완료되지 않았습니다(8절 참조).

<a id="sec-3"></a>
## 3. 요구 사항

| 항목 | 내용 |
|---|---|
| Python | >= 3.10 (3.13.14에서 검증) |
| 의존성 | **표준 라이브러리만** — 서드파티 런타임 의존성 없음 |
| OS | Windows **검증됨**; Linux / macOS **미검증** — 7절 참조 |
| 선택적 외부 도구 | `nuclei`, `bandit`, `gitleaks`, `semgrep` — 없으면 안전하게 건너뜀 |

<a id="sec-4"></a>
## 4. 설치 및 빠른 시작

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# Windows (CMD):        .venv\Scripts\activate.bat
# Linux/macOS:          source .venv/bin/activate

pip install .
```

개발용으로 `pip install -e .`도 지원합니다.

**1단계 — 항상 먼저 범위 파일을 검증하세요:**

```bash
dvs gate-check scripts/example-scope.json
# 0 = 유효 · 1 = 거부 · 2 = 사용법 오류
```

**2단계 — 검증 실행:**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# 또는: python -m vuln_hunter run --scope ... --mode ... --target ...
```

모드(위험 상한 순): `passive` → `safe_scan` → `vuln_validation` → `attack_simulation` → `high_risk`(R0–R4). `nuclei`는 R2 이상에서만 호출됩니다.

종료 코드: `0` 모든 단계 완료 · `1` 실패/거부가 있는 종료 · `2` 게이트/정책 수준 거부(아무 것도 실행하지 않음) · `3` **감사 실패**(저널을 쓰거나 검증할 수 없어 결과가 인증되지 않음).

`scripts/example-scope.json`은 가상의 예시이며 **실제 인가가 아닙니다**.

<a id="sec-5"></a>
## 5. 인가와 안전

> ⚠️ **DVS는 직접 소유·운영하는 시스템, 로컬 실험 대상, 또는 소유자로부터 명시적인 서면 인가를 받은 호스트에만 사용하세요.**

인가되지 않았거나 범위를 벗어나거나 만료되었거나 손상된 설정은 거부됩니다. 인가를 건너뛰는 코드 경로는 없습니다.

- 항목은 **파싱된 호스트명 일치**로 비교됩니다. 포트가 없는 항목은 해당 호스트의 모든 포트에 일치합니다. **CIDR 범위는 지원하지 않습니다** — `host` 또는 `host:port`를 사용하세요.
- 인가 시간 창은 **모든 실행 단계**에서 재확인되며, 실행 중 만료되면 이후 단계가 중단됩니다.
- 범위 내용은 해시로 각 실행 티켓에 묶이며, 범위를 변경하면 미사용 티켓이 무효화됩니다.
- 파일 시스템 범위 단계는 네트워크 범위 검사만 건너뛰고, 다른 정책 검사는 모두 적용됩니다.

실제 인가 기록은 이 저장소 밖에 보관하세요. 포함된 예시는 가상입니다.

**API 강화는 OS 수준 샌드박스가 아닙니다.** `RunTicket`의 frozen dataclass와 비공개 레지스트리는 Python 수준 강화이며, 프로세스 내 악성 코드는 우회할 수 있습니다. 강력한 격리에는 프로세스 수준 조치가 필요하며 현재 구현되어 있지 않습니다. 지원되는 진입점은 CLI뿐입니다.

<a id="sec-6"></a>
## 6. 증거와 정직한 보고

감사 저널은 추가 전용이며 해시 체인으로 연결되어 변조와 순서 변경을 탐지합니다. 감사 실패는 숨기지 않고 명시됩니다. 실행 보고서는 완전·부분·불완전 결과를 구분하며, 불완전한 결과는 실패 시 거부되어 수집된 발견 항목에 포함되지 않습니다.

두 가지 경계를 분명히 합니다. 도구 출력은 있는 그대로 기록되며 검증되지 않은 출력이 확인된 취약점으로 승격되지 않습니다. 또한 저널 꼬리 잘림은 외부에 head 앵커가 저장되어 있을 때만 탐지할 수 있습니다.

<a id="sec-7"></a>
## 7. 플랫폼 호환성과 커뮤니티 테스트

**커뮤니티 테스트를 환영합니다. 플랫폼 호환성 확장에 도움을 주세요.**

DVS는 현재 **Windows 우선**입니다. Windows의 타임아웃 경로는 기록이 남는 프로세스 트리 정리를 수행합니다(루트 종료 전 `taskkill /T /F`를 실행하고 모든 결과를 기록). 통제된 훈련에서 확인했지만 잔여 프로세스가 전혀 없음을 절대적으로 보장하지는 않습니다. 비 Windows 플랫폼에서는 트리 종료가 생략되고 루트 프로세스만 종료됩니다. `nuclei` 경로 폴백 또한 특정 로컬 설치 구조를 가정합니다.

Linux와 macOS는 **검증되지 않았고** CI도 아직 다루지 않습니다. 다른 플랫폼에서 실행해 보셨다면 동작한 부분과 그렇지 않은 부분을 issue로 공유해 주세요. 어댑터 동작, 프로세스 정리, 패키징이 특히 유용합니다. 실제 대상 데이터, 자격 증명, 인가 없는 스캔 출력은 첨부하지 마세요.

<a id="sec-8"></a>
## 8. 프로젝트 현황과 방향

| | |
|---|---|
| **구현 완료(Gen-1)** | 인가 게이트, 정책 엔진(R0–R4), TaskGraph, 감사 저널, 구조화된 보고서, 통합 Finding Schema, 그리고 `nuclei` / `bandit` / `gitleaks` / `semgrep` 어댑터 코드 경로. |
| **구축·검증 중** | 실제 도구 종단 간 검증, 비 Windows 검증 및 CI, 현재 버전의 패키징 검증. 테스트 스위트는 `tests/`에 있습니다. 직접 실행하고 실제 출력을 근거로 삼으세요. 이 저장소는 "전체 통과"를 미리 주장하지 않습니다. |
| **장기 방향** | 모델 기반 계획, 더 강한 프로세스 수준 격리, 더 넓은 플랫폼 지원. 모두 방향일 뿐이며 Gen-1에 **구현되어 있지 않습니다**. |

현재 계획 계층은 결정적 정적 템플릿입니다. 어댑터 코드의 존재는 도구 실행 검증을 뜻하지 않으며, API 강화는 OS 수준 샌드박스가 아닙니다. 패키징은 현재 버전을 실제로 빌드해 판단해야 하며, 오래된 빌드 산출물은 현재 버전의 증거가 되지 않습니다. 이는 엔지니어링 기반 계층이며 상용 수준의 평가 제품이 아닙니다.

<a id="sec-9"></a>
## 9. 기여와 참여

Star는 다른 사람들이 프로젝트를 발견하는 데 도움이 됩니다. 자신의 실험 환경에서 사용해 보고, 관찰한 내용을 알려주고, Pull Request를 보내는 것 모두 환영합니다. 자세한 내용은 [CONTRIBUTING.md](../../CONTRIBUTING.md)를 참조하세요.

참여할 수 있는 영역:

- **플랫폼 적응 및 호환성 테스트** — Linux/macOS 동작, 프로세스 트리 정리, 패키징.
- **보안 도구 Provider / Adapter 통합** — 인가 게이트와 fail-closed 설계를 지키는 새 연동.
- **테스트 케이스와 회귀 기준선** — 재현 가능하고 증거를 남기는 검사.
- **문서와 다국어** — 6개 언어 README, 예시, 가독성.
- **버그 수정과 코드 품질** — 실행 가능한 증거를 담은 작고 집중된 변경.
- **보안 연구** — [SECURITY.md](../../SECURITY.md)를 따르세요. 공개되지 않은 취약점을 공개 issue로 올리지 마세요.
- **사용 경험과 기능 제안** — 먼저 issue로 범위를 합의하세요.

버그·플랫폼 결과·제안에는 **Issues**, 코드 및 문서 변경에는 **Pull Requests**를 사용하세요. 실제 대상 데이터, 자격 증명, 사적 인가 기록, 인가 없는 스캔 출력을 issue나 PR에 첨부하지 마세요.

<a id="sec-10"></a>
## 10. 라이선스와 링크

- **라이선스**: MIT — [LICENSE](../../LICENSE) 참조.
- **보안 정책**: [SECURITY.md](../../SECURITY.md).
- **기여 가이드**: [CONTRIBUTING.md](../../CONTRIBUTING.md).
- **Issues / PR**: [issue 열기](https://github.com/zyh798-cell/DualVerify-Sentinel/issues) · [PR 열기](https://github.com/zyh798-cell/DualVerify-Sentinel/pulls).
- **번역**: 中文 · 日本語 · 한국어 · Español · Français(상단 언어 전환 참조).

---

<div align="center"><sub>DualVerify-Sentinel · Engineered for Trust. Built for Control. · MIT © 2026 zyh798-cell</sub></div>
