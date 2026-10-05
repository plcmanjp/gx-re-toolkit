# 검증 방법

[English](validation-methodology.md) | [한국어](validation-methodology-ko.md)

> 영어본의 한글 번역입니다. 내용이 다르면 영어본을 기준으로 합니다.

검증 계층은 합산하지 않고 구분합니다.

1. 공개 synthetic: 직접 생성한 작은 입력과 오류 조건의 회귀입니다.
2. 비공개 conformance: 공개 wheel의 고정 hash와 원래 authority 입력을 결속합니다.
3. GUI lifecycle: 별도 승인한 프로젝트 사본의 저장, 재오픈, rebuild, export 증거입니다.
4. 현장 수락: 설비별 안전 및 운전 검증이며 이 저장소의 테스트 결과가 아닙니다.

원래 테스트 분모, byte oracle, 실패와 SKIP 사유를 보존합니다. 현재 구현의 출력을
새 expected로 덮어써 통과시키지 않습니다. packaging metadata 차이는 별도 목록으로
기록하고, opcode, operand, radix, 순서, unknown 및 finding 차이는 회귀로 차단합니다.

일반 wheel 설치를 사용하고 source checkout 밖에서 import origin, CLI 및 resource를
확인합니다. editable install이나 PYTHONPATH로 설치 누락을 숨기지 않습니다.
`tools/build_artifacts.py`는 clean commit만 읽어 새 외부 staging에서 wheel/sdist를
만듭니다. parser 출처는 빌드된 resource에만 고정하며 runtime에서 상위 Git을 찾지 않습니다.
같은 환경의 반복 빌드는 원본 artifact hash와 archive member hash를 모두 비교합니다.
압축 timestamp 등 metadata 차이가 있으면 bit-identical이라고 보고하지 않습니다.

CI 빌드 환경은 전이 도구와 플랫폼 조건을 포함하여 버전과 해시를 고정한
`requirements-build.txt`를 사용합니다. 제품 런타임 의존성은 패키지 메타데이터에
별도로 선언합니다. Windows는 Python 3.12/3.13에서 설치된 전체 도구를,
Linux는 같은 버전에서 설치된 FX5/R 읽기 전용 패키지와 CLI를 검증합니다.
Linux에서 Windows COM 쓰기는 검증하지 않습니다. Python Action 고정 버전은
Node 24를 사용하므로 호환되는 호스팅 실행기가 필요합니다.

메타데이터 XML은 1 MiB, 노드 10,000개, 깊이 64로 제한하고 DTD 및 entity
선언을 거부합니다. GXW OLE은 외부 컨테이너 512 MiB, 스트림 10,000개,
스트림당 256 MiB, 선언된 전체 스트림 512 MiB로 제한합니다. 실제 읽은 길이가
선언 길이와 같은지도 확인합니다. 제한 초과는 입력 거부이며 부분 수락이
아닙니다. 향후 스키마와 증명 결정은 [계약 진화](contract-evolution-ko.md)를
참고합니다.
