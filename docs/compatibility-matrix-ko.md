# 호환성 경계

[English](compatibility-matrix.md) | [한국어](compatibility-matrix-ko.md)

> 영어본의 한글 번역입니다. 내용이 다르면 영어본을 기준으로 합니다.

| 패키지 | 명시한 범위 | 범위 밖 |
|---|---|---|
| gx3-fx5-parser-toolkit 0.4.0 | 검증된 FX5-family GX3 carrier와 Neutral IR 1.0.0 | 모든 FX 명령이나 언어 지원 주장 |
| gx3-r-parser-toolkit 0.2.0 | 현재 명시적 지원 프로필: `R04/4097`의 R04CPU Ladder | 다른 iQ-R CPU 또는 미검증 프로젝트 형식의 현재 지원 주장 |
| gxw-parser-toolkit 0.1.0 | 기존 Q 계열 GXW 판독과 제한된 후보 writer/encoder | 모든 CPU/명령의 공식 저장 및 실행 보증 |
| gx-re-lab 0.1.0 | 고정 입력의 연구 조회, 비교, census, 계획 | 공식 lifecycle 수집과 제품 수락 |

R 도구의 프로젝트 대상은 MELSEC iQ-R 계열 전반의 읽기 전용 분석이며,
현재 구현은 위에 명시한 R04CPU Ladder 프로필만 지원합니다. 판별기는 다른
Unit/UnitId 조합이 명시되면 `UNSUPPORTED`, 기종 식별 근거가 없거나 모호하면
`AMBIGUOUS`로 판정합니다. 현재 프로필 식별자는
`mitsubishi.gx3.r04cpu.ladder`로 유지됩니다. iQ-R 전반으로의 확대는 개발 방향이며
현재 호환성 보장이 아닙니다. [프로젝트 방향](../README-ko.md#프로젝트-방향)을
참고하세요.

FX5 detector의 정확한 tuple은 `(FX5U, 528)`, `(FX5UJ, 529)`, `(FX5S, 530)`입니다.
FX5UC는 별도 identity를 추측하지 않고 검증된 FX5U tuple을 공유하는 범위로 제한합니다.
tuple 일치만으로 전체 프로젝트의 완전 해독이나 target 변환을 승인하지 않습니다.

FX5와 R schema는 버전과 embedded identifier가 같더라도 서로 다른 resource입니다.
각 owning package에서 명시한 profile로 선택하며 교차 fallback하지 않습니다.
FX5의 `SOURCE_GLOBAL_ORDER_NOT_SERIALIZED` finding을 R에 허용하지 않습니다.

GXW 판독은 `olefile`, Windows 파일 writer/encoder는 `pywin32`를 사용합니다.
GXW reference IR은 직접 `K1`~`K8` 묶음 비트 디바이스를 식별하고 `4n`개 비트 주소를 열거합니다.
인덱스/간접 operand와 묶음 블록 범위는 미확정으로 남깁니다. 이 연구용 projection은 대상
CPU 주소 범위나 제품 변환을 승인하지 않습니다.
Windows storage API 사용은 GX GUI 또는 PLC 접속 권한을 뜻하지 않습니다.
일부 원래 CLI의 도움말은 성공 코드 0이 아닌 사용법 코드 1을 반환할 수 있습니다.

## GXW 판독 경계

판독 대상 counted COMMENT 형식에서 `device_comment_pairs`는 명시된 디바이스
범위를 길이 정보가 있는 UTF-16 텍스트에 결합하며, 대문자·숫자·빈 문자열·여러 줄
코멘트도 보존합니다. 타입 정보가 있는 워드 비트 영역은 명시된 디바이스 종류,
모듈, 워드 주소와 비트 번호를 유지합니다. 알 수 없는 디바이스 타입, 중복 주소,
불완전한 counted 레코드는 거부합니다. `device_comment_map`과 `COMMENT.csv`에서는
빈 코멘트를 제외하므로, 해당 항목이 필요하면 `device_comment_pairs`를 사용하세요.

판독기는 관찰된 비펄스 `DFMOV` 헤더 `05 4c 05 0e 05` 뒤에 완전한 피연산자
프레임이 정확히 세 개 오는 형식을 인식합니다. 손상되거나 잘린 형식, 피연산자가
추가된 형식은 `DFMOV`로 출력하지 않고 미확인 명령 표식 `<i:05:4c:0e>`를 유지합니다.
이는 원본 판독기의 프레임 경계를 설명하며, 작성기나 CPU 호환 범위를 확장하지 않습니다.
