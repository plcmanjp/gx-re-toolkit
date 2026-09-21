# GX RE Toolkit

명시된 Mitsubishi 프로젝트 형식을 오프라인에서 분석하는 독립 연구 도구다.
Mitsubishi Electric과 제휴하거나 승인을 받은 도구가 아니다.
분석 성공은 GX 재빌드, 공식 export 일치, PLC 적용 승인 또는 현장 안전성을 뜻하지 않는다.
현재는 공개 전 로컬 후보이며 배포 승인이 필요하다.

## 구성

| 배포 패키지 | 버전 | 용도 |
| --- | --- | --- |
| gx3-fx5-parser-toolkit | 0.4.0 | GX3 FX5 구조와 Neutral IR 분석 |
| gx3-r-parser-toolkit | 0.2.0 | 명시된 R04CPU GX3 분석 |
| gxw-parser-toolkit | 0.1.0 | GXW 분석, Reference IR, 후보 파일 작성 |
| gx-re-lab | 0.1.0 | 제한된 비교, census, 계획, 축소 연구 도구 |

Python 3.12 이상이 필요하다. 전체 작성 기능은 Windows와 pywin32를 사용한다.
지원 CPU와 보장 범위는 [호환성 표](docs/compatibility-matrix.md)를 확인한다.
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

Lab 모듈 CLI는 `explorer_diff`, `reference_query`, `census`, `r04_census`,
`gxw_census`, `planner`, `coverage_ledger`, `external_compare`, `final_scope`,
`lab`, `experiment`, `relation_audit`, `campaign_coverage`다.
`gxw-inspect`와 `python -m gxw_pou_devmap`은 입력이 없으면 사용법과 종료 코드 1을 반환한다.
작성 도구에는 원본 대신 폐기 가능한 복사본과 새 출력 경로만 전달한다.
입출력 전체에 대한 원자적 hostile-filesystem 방어를 보장하지 않는다.

## 검증과 공개 경계

`tools/audit_public_tree.py`는 작업 트리, 로컬 전체 refs의 파일과 지정한
`--artifact` 배포물의 경로, 형식, 일부 민감 패턴을 검사한다.
이 검사는 완전한 비밀정보 탐지나 독립적인 법률 검토가 아니다.
별도 비공개 비교 결과와 공개 synthetic 테스트를 합쳐 현장 승인으로 표시하지 않는다.

- [검증 방법](docs/validation-methodology.md)
- [안전 경계](docs/safety-boundaries.md)
- [역공학 및 권리 정책](docs/reverse-engineering-policy.md)
- [의존성 고지](THIRD_PARTY_NOTICES.md)
- [보안 보고](SECURITY.md)

## 복구

이 checkout은 자체 Git 데이터베이스를 사용한다. 다른 저장소는 이 파일과
커밋을 자동 백업하지 않는다. 작업 트리 밖에 명시적 ref Git bundle을 만들고
별도 복원으로 commit/tree를 확인한다. 로컬 백업은 장치 외부 재해 복구가 아니다.
상위 디렉터리의 재귀 정리는 중첩 저장소까지 삭제할 수 있으므로 사용하지 않는다.
