# Corpus census

[English](corpus-census.md) | [한국어](corpus-census-ko.md)

`python -m gx_re_lab.corpus_census --manifest manifest.json --manifest-sha256
<sha256> --source-root <폐기 가능한 복사본> --output <새 보고서.json>`은
기존 GX3-FX5와 GXW-Q census를 고정 SHA의 retained 복사본에서 실행한다.
manifest는 다음 키만 포함하는 UTF-8 JSON이다.

```json
{"format":"plcman.gx-re-lab.corpus-manifest","version":1,"cases":[
  {"case_id":"C001","path":"C001.gx3","adapter":"GX3-FX5",
   "byte_count":123,"sha256":"<소문자 16진수 64자리>"}
]}
```

adapter는 `GX3-FX5`, `GXW-Q`다. 경로는 입력 root 기준 상대 경로이며 링크,
상위 경로 탈출, alternate stream, 절대 경로를 거부한다. 최대 256개 파일,
GX3-FX5 파일당 32 MiB, GXW-Q 파일당 16 MiB, 전체 512 MiB, 보고서 4 MiB로
제한한다. FX5 압축 해제 한도는 2,000 entry, entry당 16 MiB, 전체 64 MiB로
유지한다. 컨테이너 크기 확대는 DB·압축·의미 검사를 완화하지 않는다. 같은 SHA의 중복 파일도
각각 검사해 집계한다. SHA 불일치, 검사 중 원본 변경, census 실패는 BLOCKED로
남기고 다른 파일을 계속 검사한다. BLOCKED가 있으면 CLI 종료 코드는 1이며
기존 보고서는 덮어쓰지 않는다.

통합 보고서는 case ID, 입력 SHA, 개수와 해시 처리한 내부 키를 담는다. 같은
키에 서로 다른 내용이 있으면 adapter와 내용 SHA별로 기록한다. 내부 이름이나
GUID의 재사용만으로 프로젝트 간 의미가 같다고 판정할 수 없다. 원본 이름과
예외 메시지는 출력하지 않는다. 의미 커버리지는 `NOT_MEASURED`, lifecycle과
대상 수용 검증은 `NOT_RUN`, 지원 주장은 `NOT_CLAIMED`다. 구조 개수는 변환
정확도를 측정하지 않으며 공식 export 비교를 대체하지 않는다. R 계열은
별도 `r04_census` adapter를 사용한다.

manifest, 입력 사본과 검사 보고서는 공개 저장소 밖에 보관한다. 공개 저장소에는
합성 테스트와 범용 구현만 추가한다.
