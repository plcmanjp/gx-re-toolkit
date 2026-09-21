# 호환성 경계

[English](compatibility-matrix.md) | [한국어](compatibility-matrix-ko.md)

> 영어본의 한글 번역이다. 내용이 다르면 영어본을 기준으로 한다.

| 패키지 | 명시한 범위 | 범위 밖 |
|---|---|---|
| gx3-fx5-parser-toolkit 0.4.0 | 검증된 FX5-family GX3 carrier와 Neutral IR 1.0.0 | 모든 FX 명령이나 언어 지원 주장 |
| gx3-r-parser-toolkit 0.2.0 | `R04/4097`의 R04CPU Ladder profile | 다른 R CPU 전체로의 일반화 |
| gxw-parser-toolkit 0.1.0 | 기존 Q 계열 GXW 판독과 제한된 후보 writer/encoder | 모든 CPU/명령의 공식 저장 및 실행 보증 |
| gx-re-lab 0.1.0 | 고정 입력의 연구 조회, 비교, census, 계획 | 공식 lifecycle 수집과 제품 수락 |

FX5 detector의 정확한 tuple은 `(FX5U, 528)`, `(FX5UJ, 529)`, `(FX5S, 530)`이다.
FX5UC는 별도 identity를 추측하지 않고 검증된 FX5U tuple을 공유하는 범위로 제한한다.
tuple 일치만으로 전체 프로젝트의 완전 해독이나 target 변환을 승인하지 않는다.

FX5와 R schema는 버전과 embedded identifier가 같더라도 서로 다른 resource다.
각 owning package에서 명시한 profile로 선택하며 교차 fallback하지 않는다.
FX5의 `SOURCE_GLOBAL_ORDER_NOT_SERIALIZED` finding을 R에 허용하지 않는다.

GXW 판독은 `olefile`, Windows 파일 writer/encoder는 `pywin32`를 사용한다.
Windows storage API 사용은 GX GUI 또는 PLC 접속 권한을 뜻하지 않는다.
일부 원래 CLI의 도움말은 성공 코드 0이 아닌 사용법 코드 1을 반환할 수 있다.
