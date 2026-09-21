# 실행과 입력 안전 경계

[English](safety-boundaries.md) | [한국어](safety-boundaries-ko.md)

> 영어본의 한글 번역이다. 내용이 다르면 영어본을 기준으로 한다.

기본 import와 help는 GUI, 네트워크 및 PLC 동작을 실행하지 않는다.
parser와 Lab은 로컬 파일을 검사하며 일부 출력에 POU 이름과 사용자가 넣은 문자열이
포함될 수 있다. 연구 결과를 외부에 공유하기 전에 내용 검토가 필요하다.

snapshot은 크기 제한, regular file, 링크 조상, 열린 핸들 identity, 최종 경로와
경로 교체를 검사한다. 이는 신뢰할 수 있는 로컬 환경의 오류 검출이며 적대적
파일시스템에 대한 원자적 sandbox 보장은 아니다.

writer/encoder는 명시적인 사본 입력과 출력을 사용한다. 라이브 설비 파일이나
유일한 원본에 적용하지 않는다. 지원되지 않은 형식은 추측으로 보완하지 않는다.

제조사 affiliation, 공식 certification, 보증 또는 현장 적용 승인을 주장하지 않는다.
