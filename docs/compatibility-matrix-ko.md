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

R 객체 읽기는 관측된 디바이스 코멘트의 식별자/문자열과 local label의 이름/Comment를
기존 IR로 출력합니다. carrier 소유 관계, 라벨 자료형/주소와 POU 연결은 미해독이므로
PARTIAL을 유지합니다. 미지원 행은 opaque 식별자와 finding으로 보존합니다.
자세한 범위는 [R 객체 읽기 경계](r-object-reading.md)를 따릅니다.

FX5 detector의 정확한 tuple은 `(FX5U, 528)`, `(FX5UJ, 529)`, `(FX5S, 530)`입니다.
FX5UC는 별도 identity를 추측하지 않고 검증된 FX5U tuple을 공유하는 범위로 제한합니다.
tuple 일치만으로 전체 프로젝트의 완전 해독이나 target 변환을 승인하지 않습니다.

별도 `gx3_fx5_profile.hsc_observed.decode_hsc_observed_settings` API는 문맥을
검증한 Normal/전체 채널 Not Use 관측형만 반환합니다. 호출자는 UNIT 항목과
순서가 있는 record 가드의 버전별 profile을 제공하고 그 출처를 독립 검증해야
합니다. profile은 의미 이름이나 mapping을 지정할 수 없습니다. 고정 코드는
record envelope, attribute, nested key를 검사한 뒤 `NORMAL`과
`ALL_NOT_USE_OBSERVED_VECTOR`를 반환합니다. 다른 값, 손상 바이트와 문맥
불일치는 위치를 포함한 미지원으로 남깁니다. counter-device encoding은 UNKNOWN이며
프로젝트 완료나 공식 authority를 선언하지 않습니다. Neutral IR과 프로젝트
reading-scope 판정은 변경하지 않고 일반 HSC schema 지원도 제공하지 않습니다.

별도 `gx3_fx5_profile.cpu_observed.decode_cpu_observed_settings` API는 opaque
문맥 가드 안에서 관측된 두 CPU 프로그램 이름 형식과 w3pa mirror를 읽습니다.
제공된 모든 QPG carrier를 목록화하고 유일한 정규 POU link 및 관련 항목을
검사하며 제한된 POU 이름을 반환합니다. `OBSERVED_SINGLETON_CONTEXT`는 독립
관측으로 확인한 프로그램/POU 문맥이며 CPU의 숫자 foreign key 해독이 아닙니다.
unlinked QPG는 위치와 UNKNOWN 사유를 보존합니다. 호출자는 전체 member 목록을
제공하고 가드 profile과 공식 증거의 출처를 독립 검증해야 합니다. 일반 실행유형
enum, 실행순서 규칙과 QPG record 크기 의미는 UNKNOWN입니다. Neutral IR을
변경하거나 프로젝트 판독 완료를 선언하지 않습니다.

CPU identity는 XML 루트 또는 wrapper의 직계 자식 위치에 Config 노드가 정확히
하나 있어야 합니다. 다중 노드, 동일 중복과 중첩 후보는 탐색 순서와 무관하게
`AMBIGUOUS`입니다. R은 `Config.xml`과 `!!Config.xml`의 바이트 일치를 요구하고,
FX5는 mirror가 있을 때 일치를 검사합니다. 파일 간 불일치와 한 XML 안의 다중
노드는 별도 진단입니다. 이 규칙은 지원 CPU 조합을 확장하지 않습니다.

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

첫 프로그램 영역은 길이로 구분된 완전한 프레임 밖의 END trailer 전체에서
끝납니다. 피연산자나 텍스트에 포함된 유사 마커는 경계로 사용하지 않습니다.
프레임 밖의 불완전한 마커나 마커를 포함한 손상 프레임은 모호한 경계로 거부합니다.
EOF에서 잘린 접점 헤더는 인덱스 예외 대신 미확인 명령 진단을 유지합니다.
이 진단은 Reference IR의 COMPLETE 판정도 막습니다.

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
