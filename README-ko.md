# GX RE Toolkit

[English](README.md) | [한국어](README-ko.md)

> 영어본의 한글 번역이다. 내용이 다르면 영어본을 기준으로 한다.

명시된 Mitsubishi 프로젝트 형식을 오프라인에서 분석하는 독립 연구 도구다.
Mitsubishi Electric과 제휴하거나 승인을 받은 도구가 아니다.
분석 성공은 GX 재빌드, 공식 export 일치, PLC 적용 승인 또는 현장 안전성을 뜻하지 않는다.
소스는 오프라인 연구용으로 공개되어 있으며 현장 적용 승인본이 아니다.

## 구성

| 배포 패키지 | 버전 | 용도 |
| --- | --- | --- |
| gx3-fx5-parser-toolkit | 0.4.0 | GX3 FX5 구조와 Neutral IR 분석 |
| gx3-r-parser-toolkit | 0.2.0 | 명시된 R04CPU GX3 분석 |
| gxw-parser-toolkit | 0.1.0 | GXW 분석, Reference IR, 후보 파일 작성 |
| gx-re-lab | 0.1.0 | 제한된 비교, census, 계획, 축소 연구 도구 |

Python 3.12 이상이 필요하다. 전체 작성 기능은 Windows와 pywin32를 사용한다.
지원 CPU와 보장 범위는 [호환성 표](docs/compatibility-matrix-ko.md)를 확인한다.
비공개 원본, 고객 데이터, 공식 export, vendor 자료는 포함하지 않는다.
기본 테스트와 런타임은 GX 프로그램이나 PLC를 실행 또는 연결하지 않는다.

## 빌드와 설치

검토 후 커밋한 깨끗한 독립 checkout에서 빌드한다. 결과 디렉터리는
checkout 밖의 새 경로여야 한다. 다음은 PowerShell 예시다.

```powershell
python -m venv C:\Temp\gx-build-env
C:\Temp\gx-build-env\Scripts\python.exe -m pip install build==1.3.0 setuptools==84.0.0
C:\Temp\gx-build-env\Scripts\python.exe tools/build_artifacts.py --output C:\Temp\gx-build-01
$wheels = Get-ChildItem C:\Temp\gx-build-01\artifacts -Recurse -Filter *.whl
C:\Temp\gx-build-env\Scripts\python.exe -m pip install $wheels.FullName
C:\Temp\gx-build-env\Scripts\python.exe -m pip check
$commit = git rev-parse HEAD
$tree = git rev-parse 'HEAD^{tree}'
C:\Temp\gx-build-env\Scripts\python.exe tools/verify_install.py --commit $commit --tree $tree --output C:\Temp\gx-install-report.json
```

편집 가능 설치는 배포 검증 근거로 사용하지 않는다. 빌드 시 루트 LICENSE,
NOTICE와 의존성 고지가 각 배포물에 들어간다. FX5/R의 source commit/tree는
커밋한 소스가 아닌 배포물의 provenance resource에 기록한다.
원본 checkout에서 resource가 없을 때의 0 값은 확인된 배포 identity가 아니다.
`build-manifest.json`은 실제 도구 버전, 소스 commit/tree와 배포물 SHA-256을 기록한다.

## 실행

```powershell
gx3-fx5-inspect --help
gx3-r-inspect --help
gxw-reference-ir --help
gxw-write --help
gxw-encode --help
python -m gx_re_lab.lab --help
python -m gx_re_lab.census --help
python -m gx_re_lab.planner --help
```

`gx3-r-inspect --summary`는 계산된 `FULL`, `PARTIAL`, `FATAL` 상태, R 프로필 지원
판정, coverage 합계, finding 개수만 출력한다. 프로젝트 이름, record, operand,
comment, label, archive 경로 및 그 밖의 프로젝트 문자열은 출력하지 않는다.
완전한 익명화 보증은 아니므로 공유 전에 출력을 검토한다. 일반 출력은 완전한 R 분석을 포함한다.
`--output`과 함께 사용하면 stdout은 summary를 유지하고 새 디렉터리에는 완전한 artifact가
생성된다.

Lab 모듈 CLI는 `explorer_diff`, `reference_query`, `census`, `r04_census`,
`gxw_census`, `planner`, `coverage_ledger`, `external_compare`, `final_scope`,
`lab`, `experiment`, `relation_audit`, `campaign_coverage`다.
`gxw-inspect`와 `python -m gxw_pou_devmap`은 입력이 없으면 사용법과 종료 코드 1을 반환한다.
작성 도구에는 원본 대신 폐기 가능한 복사본과 새 출력 경로만 전달한다.
입출력 전체에 대한 원자적 hostile-filesystem 방어를 보장하지 않는다.

GXW 단일명령의 `--all` 없는 `--apply`는 길이가 같은 완전한 03 계열의 비수식자
피연산자 frame 명령 또는 공개 encoder allowlist의 `(marker, A, opcode)`와 정확히
일치하는 고정-arity 05 dispatch/XFER 명령만 허용한다. XML의 한 POU
`.res`/`.Program.pou` 역할을 해석하고 bounded 명령, line statement, Note grammar로
payload의 모든 바이트를 소비한다. line statement는 정확한
`<L> 80 <ceil(L/2)> <printable text (L-4)> <L>` 형식이며 Note는 같은 길이 관계 또는
공개 raw subtype `01`만 허용한다. K/H와 부동소수 constant frame도 encoder 근거 폭으로
제한한다. 둘째 `.res` payload가 비어 있으면 2개 복제본,
비어 있지 않으면 3개가 완전히 같아야 한다. `_hdb`의 모든 OLD hit는 해석된 slice여야
하며 container 전체 OLD count도 추가 fail-closed 모호성 검사에 사용한다. 이는 물리
sector offset 매핑을 주장하는 검사는 아니다. 미지원 grammar, metadata 없는 입력,
복제본 불일치, embedded OLD, 헤더/trailer 이상 또는 모호성은 후보를 만들지 않고
종료 코드 10으로 거부한다. dry-run과 명시적 전역 `--all` 교체는 기존 계약을 유지한다.
writer, fill, transpose는 임시 후보를 검증한 뒤 새 출력 경로에 발행한다.
기존 출력은 거부하며 reader 실패, 예외 또는 30초 검증 timeout이면 발행하지 않는다.
명시적 `--in-place`는 폐기 가능한 사본 전용이고 기존 `.bak`가 있으면 거부한다.
후보 검증 후에만 백업을 만들고 입력 사본을 교체한다.
`--in-place`와 `--out`은 함께 쓸 수 없다. 준비 중과 발행 직전의 입력 변경을
해시로 검사하지만 파일시스템 잠금을 제공하는 것은 아니다.
숫자 검사는 frame 범위 초과를 거부하고 유효한 음수의 2의 보수 표현을 보존한다.
frame 폭이 CPU의 디바이스 또는 피연산자 지원 범위를 의미하지는 않는다.

## 검증과 공개 경계

`tools/audit_public_tree.py`는 작업 트리, 로컬 전체 refs의 파일과 지정한
`--artifact` 배포물의 경로, 형식, 일부 민감 패턴을 검사한다.
이 검사는 완전한 비밀정보 탐지나 독립적인 법률 검토가 아니다.
별도 비공개 비교 결과와 공개 synthetic 테스트를 합쳐 현장 승인으로 표시하지 않는다.

- [검증 방법](docs/validation-methodology-ko.md)
- [안전 경계](docs/safety-boundaries-ko.md)
- [역공학 및 권리 정책](docs/reverse-engineering-policy-ko.md)
- [의존성 고지](THIRD_PARTY_NOTICES-ko.md)
- [외부 연구 경계](THIRD_PARTY_RESEARCH-ko.md)
- [보안 보고](SECURITY-ko.md)
- [기여 기준](CONTRIBUTING-ko.md)

## 문서 언어

기본 문서 언어는 영어다. 한글 번역에는 `-ko.md` 접미사를 붙이고 영어 원문으로
돌아가는 링크를 둔다. 의미, 명령 또는 안전 경계를 바꾸면 두 언어를 함께 갱신한다.
번역이 다르면 영어본을 정본으로 삼는다. LICENSE와 NOTICE의 법적 원문은 유지한다.

## 복구

다른 PC에서는 이 저장소를 독립적으로 복원한 다음 빌드 전에 소비자가 요구하는
검수된 commit을 선택한다. 승인 artifact pin을 최신 브랜치 tip으로 대체하지 않는다.

```powershell
git clone https://github.com/plcmanjp/gx-re-toolkit.git C:\Work\gx-re-toolkit
git -C C:\Work\gx-re-toolkit rev-parse --show-toplevel
git -C C:\Work\gx-re-toolkit remote get-url origin
git -C C:\Work\gx-re-toolkit switch --detach <reviewed-commit>
```

이 checkout은 자체 Git 데이터베이스를 사용한다. 다른 저장소는 이 파일과
커밋을 자동 백업하지 않는다. 작업 트리 밖에 명시적 ref Git bundle을 만들고
별도 복원으로 commit/tree를 확인한다. 로컬 백업은 장치 외부 재해 복구가 아니다.
상위 디렉터리의 재귀 정리는 중첩 저장소까지 삭제할 수 있으므로 사용하지 않는다.
