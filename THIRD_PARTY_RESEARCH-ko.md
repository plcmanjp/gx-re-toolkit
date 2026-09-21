# 외부 연구와 코드 편입 경계

[English](THIRD_PARTY_RESEARCH.md) | [한국어](THIRD_PARTY_RESEARCH-ko.md)

> 영어본의 한글 번역이다. 내용이 다르면 영어본을 기준으로 한다.

외부 parser와 구조화된 ladder 연구는 실패 조건 및 시험 축을 비교하는 참고에 한정한다.
source-available 또는 proprietary 구현과 fixture를 복사하거나 번역해 편입하지 않는다.
외부 프로그램을 runtime fallback으로 실행하지 않는다.

외부 결과를 입력받는 adapter는 사용자 제공 결과의 상태와 출처를 구분한다.
그 결과를 공식 정답, 지원 범위, 제품 수락 또는 현장 승인으로 승격하지 않는다.
새 제3자 코드를 도입하려면 정확한 버전, 라이선스, 직접 의존성과 고지 검토가 필요하다.
