# bob15th-after-ad-sast

BoB 15기 공방전 이후의 소스 코드 분석을 재현 가능한 연구 절차로 정리하기 위한 **증거 기반 AI 보조 SAST 프로토타입**입니다.

이 저장소의 도구는 공방전 당시 사용한 도구가 아닙니다. 공방전이 끝난 뒤 확보한 분석 경험을 바탕으로 만든 **후속 연구용 MVP**입니다. 현재 구현은 Semgrep·CodeQL·Trivy의 SARIF를 정규화하고, 같은 위치의 후보를 보수적으로 그룹화한 뒤, 스캐너 요약·SARIF 데이터 흐름·선택적 소스 조각을 증거 묶음으로 저장합니다. 설정·패치·동적 실행 증거의 가져오기와 자동 상태 전이는 아직 로드맵입니다. AI의 답변만으로 취약점을 확정하거나 패치를 자동 적용하지 않습니다.

## 공개 범위와 주의사항

- BoB 15기 A&D의 원본 문제 소스, 실제 공격 payload, flag, 계정정보 및 운영 인프라 정보는 포함하지 않습니다.
- `fixtures/`에는 공개 데모를 위해 새로 작성한 synthetic 코드와 예시 SARIF만 포함합니다.
- 분석 결과의 수치는 모두 자동 탐지 항목 또는 검토 후보를 뜻합니다. 별도의 수동·동적 검증 없이 이를 모두 확정 취약점으로 표현하지 않습니다.
- 이 도구는 소유하거나 명시적으로 허가받은 코드 및 격리된 실험 환경에서만 사용해야 합니다.

## 연구 배경

BoB 15기 A&D는 EDU, Fintech, Healthcare, Manufacturer의 네 서비스로 구성되었습니다. 작성자는 Manufacturer 서비스의 방어를 담당했습니다. 공방전 전에는 Gamebox를 임의로 설치하거나 문제 코드를 미리 분석하지 않는 운영 원칙을 지켰으며, 실제 진행 중에는 Semgrep을 빠른 탐색 도구로 주로 사용했습니다. CodeQL은 고사양 교실 데스크톱에서 지정 팀원이 보조적으로 실행했습니다.

당시에는 제한된 시간 안에 자동 탐지 결과를 검토하고, 실제 요청 경로와 패치 우선순위를 연결하는 일이 가장 큰 병목이었습니다. 공방전 이후에는 배포 호스트 소스와 자체 검증 환경을 이용해 분석 범위를 확장했습니다. 사후 1차 분석에서 197개 항목을 정리했고, 개인 서버에서 수행한 동적 검증 및 패치 우회 관점의 분석으로 44개 항목을 추가하여 총 241개 후보를 분류했습니다.

| 심각도 | 후보 수 |
| --- | ---: |
| Critical | 24 |
| High | 89 |
| Medium | 109 |
| Low | 19 |
| 합계 | 241 |

이 수치는 연구 데이터셋의 분류 결과이며, 241개 모두가 독립적이고 악용 가능한 취약점이라는 뜻은 아닙니다. 중복 근본 원인, 구성 오류, 방어 계층에 의해 도달 불가능한 경로와 추가 검증이 필요한 항목이 포함될 수 있습니다.

241건의 발생 위치와 취약점명만 빠르게 확인하려면 [취약점 발생 위치 요약](docs/vulnerability-locations.md)을 참고하십시오.

## 보고서 서사

보고서에서는 다음 순서로 사실과 후속 연구를 구분합니다.

1. **개요** — 네 서비스, 팀 역할, 공방전의 시간·환경 제약을 설명합니다.
2. **공방전 전 전략 수립** — Gamebox 사전 미설치 원칙, Semgrep 중심의 빠른 탐색 전략, CodeQL 보조 계획을 기록합니다.
3. **공방전 실제 진행**
   - **3-1. 취약점 탐색** — 당시 실제로 확인한 사례와 실패·불확정 시도를 구분합니다. 서비스별 세부 내용은 공개 허가가 확인된 자료에서만 다룹니다.
   - **3-2. 패치로부터 취약점 추론** — 다른 팀의 패치 diff와 방어 변경을 단서로 입력점, sink, 누락된 보안 조건을 역추적한 과정을 설명합니다.
4. **공방전 후 분석 및 검증**
   - **4-1. 배포 호스트 소스 분석** — 사후 확보한 범위 안에서 소스와 설정을 다시 검토합니다.
   - **4-2. 기존 SAST 활용** — Semgrep과 CodeQL 결과를 수집·정규화하고 사람이 triage합니다.
   - **4-3. 사용자 정의 분석 도구** — 본 저장소의 통합·상관분석 프로토타입을 후속 연구로 구현합니다.
   - **4-4. 생성 payload 검증** — AI가 제안한 테스트 입력은 자체 격리 서버에서만 검증하고, 성공·실패·불확정을 그대로 기록합니다.

이 순서는 “공방전 때 AI SAST를 사용했다”는 식의 사후적 각색을 피합니다. 공방전 당시의 도구와 결과, 공방전 후의 재분석, 앞으로 개발하는 AI 보조 도구를 시간 순서대로 분리합니다.

## 도구가 하는 일

`bob15-sast`는 다음 네 가지 경로를 제공합니다.

- `doctor`: 로컬 실행 환경과 선택 분석기의 사용 가능 여부를 점검합니다.
- `demo`: synthetic fixture만 사용해 전체 파이프라인을 안전하게 시연합니다.
- `analyze`: 허가된 로컬 경로를 분석하고 결과를 공통 finding 형식으로 정리합니다.
- `ingest`: Semgrep·CodeQL 등이 만든 SARIF를 읽어 공통 스키마로 정규화합니다.

정적 분석기 결과는 먼저 기계적으로 수집됩니다. 현재 증거 묶음에는 항상 스캐너·rule·심각도·CWE·sink 요약이 들어가고, SARIF에 데이터 흐름이 있으면 첫 번째 흐름을 추가합니다. `--include-source`를 지정한 경우에만 경로 이탈 검사를 통과하고 마스킹된 관련 소스 조각을 추가합니다. 설정, patch diff, 로그와 동적 실행 결과를 별도 증거로 가져오는 기능은 아직 구현되지 않았습니다.

AI가 활성화된 경우에도 위 증거를 바탕으로 설명과 검증 계획을 제안할 뿐입니다. 현재 AI 호출은 **root-cause group당 1회**이며, 기본 상한은 한 실행당 20개 group입니다. `--max-ai-groups`로 더 낮게 제한할 수 있고, 상한을 넘으면 첫 API 호출 전에 실행을 중단합니다. 이 값은 호출 수 상한이지 token 또는 원화 비용 보장은 아니므로, 제공자 측 예산 제한도 함께 설정해야 합니다. `confirmed` 판정은 반드시 사람이 검토한 증거를 요구합니다.

`demo`와 `analyze`의 pipeline 작업량 기본 상한은 finding 5,000개와 root-cause group 500개입니다. 초과하면 output 디렉터리를 만들거나 artifact를 쓰기 전에 실패합니다. 필요하면 `--max-findings`와 `--max-groups`로 명시적으로 늘릴 수 있지만, 메모리·디스크·검토량을 먼저 산정해야 합니다.

## 빠른 시작

Python 3.11 이상을 권장합니다.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Windows PowerShell에서는 가상환경 활성화 명령으로 `.venv\Scripts\Activate.ps1`을 사용합니다. `doctor`, `demo`, `ingest`는 사용할 수 있지만, 로컬 분석기 프로세스 전체를 안전하게 종료하기 위해 현재 `analyze`는 POSIX 환경에서만 실행됩니다. Windows에서는 외부 격리 환경에서 만든 SARIF를 `ingest`하십시오.

```bash
bob15-sast doctor
bob15-sast demo
bob15-sast ingest fixtures/sarif/sample.sarif
```

데모와 ingest는 별도 분석기 없이 동작하며 synthetic fixture만 처리합니다. 실제 분석은 Semgrep, CodeQL 또는 Trivy를 사용자가 별도로 설치한 뒤 실행합니다. 예를 들어 Semgrep 설치 후 `bob15-sast analyze fixtures/synthetic`을 실행할 수 있습니다. 실제 소스를 분석하기 전에는 해당 코드에 대한 권한과 실행 격리를 먼저 확인하십시오. 기본 `analyze`는 프로젝트에 포함된 Python 명령 주입 예시 규칙 하나를 사용하는 MVP이며, 범용 취약점 커버리지를 주장하지 않습니다.

scanner 실행 파일은 분석 대상 밖에 설치하십시오. PATH에서 찾은 Semgrep·CodeQL·Trivy 실행 파일이 대상 내부로 resolve되면 실행을 거부하므로, 대상 저장소 안의 가상환경도 scanner 설치 위치로 사용하지 않아야 합니다. `--scanner trivy`에는 대상 밖에 미리 채운 `--trivy-cache-dir`가 필수입니다.

OpenAI triage는 선택 기능입니다. `python -m pip install -e ".[openai]"` 후 `--ai openai`로 활성화할 수 있습니다. 기본적으로 소스 본문은 외부 모델에 보내지 않으며, `--include-source`를 함께 지정할 때만 민감정보 마스킹을 거친 관련 소스 조각이 전송됩니다. 이 옵션을 사용하기 전 제공자의 데이터 처리 조건을 확인하십시오.

`analyze`의 기본 결과 위치는 분석 대상 밖에 매 실행 새로 만드는 비공개 운영체제 임시 디렉터리 `bob15-sast-artifacts-*`입니다. `--output`을 직접 지정하더라도 대상 디렉터리 자체나 그 하위 경로는 거부합니다. 이는 분석 산출물이 다시 스캔되거나 대상 저장소를 오염시키는 일을 막기 위한 경계입니다.

## 결과 상태

아래 상태는 연구 보고서에서 사용할 **목표 상태 모델**입니다. 현재 MVP의 group 상태는 기본 `candidate`이며, 모든 구성 finding에 accepted suppression이 있으면 `suppressed_candidate`, 그렇지 않으면서 모든 구성 finding의 SARIF `baselineState`가 `absent`이면 `baseline_absent`로 표시합니다. 사람 검토 상태는 `pending_review`입니다. 이 표시는 원본 SARIF 상태를 보존하기 위한 것이며 취약점 기각이나 사람 검토 완료를 뜻하지 않습니다. 설정·patch·runtime 증거 가져오기와 나머지 상태 전이는 아직 자동화되지 않았습니다.

| 상태 | 의미 | 전환 권한 |
| --- | --- | --- |
| `candidate` | 분석기가 탐지한 미검토 후보 | 분석기 |
| `evidence_supported` | 코드 경로·설정·로그 등 보조 증거가 연결됨 | 규칙 기반 파이프라인 |
| `sandbox_reproduced` | 허가된 격리 환경에서 재현됨 | 검증 실행기 |
| `reviewed_confirmed` | 사람이 근본 원인과 영향까지 검토함 | 사람 검토자 |
| `rejected` | 오탐, 중복 또는 비도달 경로로 판정됨 | 사람 검토자 |

AI는 상태 전환에 필요한 설명이나 검증 계획을 제안할 수 있지만, 스스로 `reviewed_confirmed`를 부여할 수 없습니다. 현재 CLI는 AI 제안만으로 어떤 상태도 승격하지 않습니다.

## CodeQL 관련 주의

CodeQL은 이 저장소에 포함하거나 재배포하지 않습니다. CodeQL의 소스 구성요소와 CLI 배포물은 적용되는 라이선스 및 이용 조건이 서로 다를 수 있으므로, 사용 전 현재의 GitHub CodeQL 약관과 자신의 연구·교육·상업적 사용 범위를 직접 확인해야 합니다. 이 프로젝트에서는 CodeQL이 설치되어 있을 때 생성된 SARIF를 선택적으로 수집하는 어댑터만 가정합니다. CodeQL이 없어도 synthetic 데모와 SARIF ingest는 동작해야 합니다.

안전 경계를 위해 현재 CodeQL 어댑터는 CodeQL CLI 2.16.4 이상의 `--build-mode=none` 경로만 사용하며 저장소 제공 빌드 명령을 실행하지 않습니다. 어댑터가 설치 버전을 자동 검증하지 않으므로 사용자가 호환 버전을 확인해야 합니다. 특히 `--codeql-language java-kotlin`에서 no-build 추출은 **Java만 대상으로 하며 Kotlin은 분석하지 않습니다**. Kotlin 또는 실제 빌드가 필요한 프로젝트는 네트워크·파일시스템·권한을 제한한 외부 격리 단계에서 CodeQL 데이터베이스와 SARIF를 만든 뒤, 이 도구의 `ingest`로 가져와야 합니다.

## SARIF suppression과 baseline

현재 parser는 SARIF `kind`가 `pass` 또는 `notApplicable`인 결과를 건너뜁니다. suppression이 있는 finding은 삭제하지 않습니다. 공개 정규화 JSON의 `suppressed`는 suppression 중 `status=accepted`가 하나라도 있을 때만 `true`이고, `baseline_state`는 허용된 SARIF `baselineState`를 노출합니다. group의 `suppressed_candidate`와 `baseline_absent`도 이 metadata를 보존하는 보조 상태일 뿐 자동 기각이나 baseline delta 계산이 아닙니다. 따라서 baseline 비교가 필요하면 입력 SARIF를 별도로 관리하고 사람의 검토 정책에 따라 처리해야 합니다.

스캔 단계의 파일 제외 정책도 이 parser 동작과 별개입니다. Semgrep 어댑터는 ignore 동작을 덮어쓰지 않으므로 설치 버전이 인식하는 대상 저장소의 ignore 정책을 따릅니다. Trivy는 대상 밖의 격리된 작업 디렉터리에서 신뢰된 빈 `trivy.yaml`과 빈 ignorefile을 명시적으로 사용하므로 대상의 `trivy.yaml`·`.trivyignore`가 분석을 바꾸거나 finding을 숨기지 못하며, `.git`은 명시적으로 건너뜁니다. CLI의 Trivy offline scan에는 대상 밖에 미리 채운 `--trivy-cache-dir`가 필수입니다. 재현 실험에서는 분석기 버전, cache 준비 상태와 최종 스캔 파일 목록을 별도로 기록해야 합니다.

## 저장소 구성

```text
docs/                  아키텍처와 연구 방법
fixtures/sarif/        공개 가능한 SARIF 예시
fixtures/synthetic/    의도적으로 작성한 취약/안전 코드
rules/semgrep/         사용자 정의 Semgrep 규칙과 rule test
src/                   CLI 및 분석 파이프라인
tests/                 자동화 테스트
```

자세한 설계는 [docs/architecture.md](docs/architecture.md), 평가·보고 방법은 [docs/research-method.md](docs/research-method.md)를 참고하십시오.

## 라이선스

이 저장소 자체 코드는 [Apache License 2.0](LICENSE)으로 배포합니다. Semgrep, CodeQL 및 기타 외부 분석기는 각 프로젝트의 별도 라이선스와 이용 조건을 따릅니다.
