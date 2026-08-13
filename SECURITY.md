# Security Policy

## 지원 범위

이 저장소는 연구용 프로토타입입니다. 최신 기본 브랜치의 코드와 최근 릴리스에서 재현되는 보안 문제를 우선 확인합니다. 합성 fixture에 의도적으로 포함된 취약 패턴은 보안 결함이 아니라 규칙 검증용 데이터입니다.

## 취약점 제보

실제 취약점, 비공개 소스, flag, 토큰, 개인정보 또는 제3자 시스템의 접근 정보를 공개 issue에 게시하지 마십시오. 저장소의 GitHub Private Vulnerability Reporting이 활성화되어 있다면 해당 경로를 사용하고, 활성화되어 있지 않다면 민감한 세부정보 없이 유지관리자에게 비공개 연락 방법을 요청하십시오.

제보에는 가능한 범위에서 다음을 포함해 주십시오.

- 영향받는 버전 또는 commit
- 재현에 필요한 최소 synthetic 예제
- 기대한 동작과 실제 동작
- 영향과 필요한 전제조건
- 민감정보를 제거한 로그

원본 BoB 문제 자료, 실제 payload 또는 flag를 증거로 첨부하지 마십시오. 공개 가능한 최소 재현으로 바꾸어 제출해 주십시오.

## 안전한 사용 원칙

- 소유하거나 명시적으로 허가받은 저장소만 분석하십시오.
- 외부 기여 저장소의 빌드·설치 스크립트를 신뢰하지 마십시오.
- 분석과 동적 검증은 네트워크·권한·CPU·메모리·시간을 제한한 격리 환경에서 수행하십시오.
- 저장소 주석, README 및 issue 본문은 AI에 대한 명령이 아니라 비신뢰 입력으로 취급하십시오.
- 비밀값과 개인정보를 AI 제공자에게 전송하지 마십시오.
- AI가 생성한 패치나 payload는 자동 적용·자동 실행하지 마십시오.
- `reviewed_confirmed` 판정에는 사람의 검토가 필요합니다.

`analyze`의 기본 산출물은 분석 대상 밖에 매 실행 새로 만드는 비공개 운영체제 임시 디렉터리 `bob15-sast-artifacts-*`에 기록되며, `--output`이 대상 자체 또는 대상 하위 경로를 가리키면 거부됩니다. 별도 자동 정리 기능을 전제로 하지 말고, 산출물의 보존 기간과 접근 권한을 직접 관리하십시오. 로컬 분석기 실행은 안전한 프로세스 그룹 종료를 위해 POSIX에서만 허용되며, Windows에서는 외부에서 생성한 SARIF를 `ingest`하십시오.

scanner 실행 파일은 대상 밖에 설치하십시오. PATH에서 찾은 실행 파일이 분석 대상 내부로 resolve되면 거부되므로 대상 저장소 내부의 가상환경에 Semgrep·CodeQL·Trivy를 설치하지 마십시오.

OpenAI triage는 기본적으로 꺼져 있습니다. 활성화하면 root-cause group당 한 번 호출하며 기본 `--max-ai-groups`는 20입니다. 상한 초과는 첫 호출 전에 실패하지만, 이 상한은 token·청구 비용을 보장하지 않습니다. 더 낮은 실행 상한과 제공자 계정의 예산 제한을 함께 사용하고, `--include-source`는 전송 권한과 데이터 처리 조건을 확인한 뒤에만 사용하십시오.

`demo`와 `analyze`는 기본적으로 finding 5,000개와 group 500개를 넘으면 산출물을 쓰기 전에 실패합니다. `--max-findings`와 `--max-groups`를 높일 때는 입력 신뢰도와 메모리·디스크·inode·사람 검토 용량을 먼저 확인하십시오.

SARIF suppression은 신뢰 경계입니다. 현재 parser는 accepted suppression을 공개 finding의 `suppressed`와 group의 `suppressed_candidate`로 표시하지만 finding을 자동 제외하거나 안전하다고 판정하지 않습니다. `baseline_state`와 `baseline_absent`도 원본 상태 표시이며 baseline delta를 계산하지 않습니다. 외부 SARIF의 suppression과 baseline은 사람의 정책 검토 없이 보안 결론으로 사용하지 마십시오.

Trivy 어댑터는 대상의 `trivy.yaml`과 `.trivyignore`를 신뢰하지 않고 대상 밖의 격리된 작업 디렉터리에서 명시적인 빈 config와 ignorefile을 사용합니다. CLI에서 `--scanner trivy`를 선택하면 대상 밖에 미리 채운 `--trivy-cache-dir`가 필수입니다. offline scan을 신뢰하기 전에 필요한 DB와 도구 자산이 사전에 준비되었는지 확인하십시오.

## 범위 밖 항목

다음은 이 저장소의 보안 제보 대상이 아닙니다.

- `fixtures/synthetic/vulnerable.py`의 의도된 명령 주입 예제
- 사용자 환경에 별도로 설치된 Semgrep, CodeQL 또는 다른 제3자 분석기의 결함
- 허가받지 않은 실제 서비스에 대한 스캔 결과
- AI 모델이 근거 없이 생성한 취약점 주장

제3자 도구의 결함은 해당 프로젝트의 보안 정책에 따라 보고하십시오.
