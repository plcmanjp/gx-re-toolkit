# 의존성과 제3자 고지

[English](THIRD_PARTY_NOTICES.md) | [한국어](THIRD_PARTY_NOTICES-ko.md)

> 영어본의 한글 번역이다. 내용이 다르면 영어본을 기준으로 한다.

이 저장소의 자작 구현은 Apache-2.0으로 제공한다. 정본 조건은 `LICENSE`다.
제3자 dependency는 각 배포물의 라이선스를 유지하며 이 저장소에 vendor하지 않는다.

| 구성 | 용도 | 확인한 배포판의 고지 |
|---|---|---|
| Python | 실행 환경 | PSF 라이선스와 포함 구성별 고지 |
| olefile 0.47 | OLE Compound File 판독 | BSD 계열 라이선스. 설치 배포물의 LICENSE 참조 |
| pywin32 312 | Windows 파일 storage API | 설치 배포물의 PSF 및 제3자 고지 참조 |
| setuptools 84.0.0 | 빌드 backend | MIT. 실행 패키지에 vendor하지 않음 |
| build 1.3.0 | 빌드 frontend | MIT. 실행 패키지에 vendor하지 않음 |

원본 프로젝트, 공식 export, 고객 데이터, 제조사 프로그램과 매뉴얼은 포함하지 않는다.
dependency를 묶어 재배포할 때는 해당 배포물의 전체 고지와 조건을 별도로 확인해야 한다.
이 문서는 법률 의견이나 제3자 권리의 포괄적 보증이 아니다.
