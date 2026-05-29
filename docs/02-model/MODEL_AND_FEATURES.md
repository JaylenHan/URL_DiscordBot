# 모델 & 피처 (Model & Features)

> 피처 목록은 `Tonkatsu_bot.py`의 `feature_extract` 구현을 근거로 한다.

## 모델

- **배포 모델**: Random Forest (`rf_final.pickle`, scikit-learn 1.2.2, `joblib` 직렬화)
- **탐색한 모델군**: Decision Tree, SVM, XGBoost, LightGBM, Random Forest
  - 담당자(한승헌)는 그 중 **Decision Tree 모델 학습**을 맡았고, 최종 배포는 Random Forest 채택
- **학습 자산**: `모델 학습/` 폴더
  - `즐추 (1).ipynb` — 학습/실험 노트북
  - `urldata1011.csv` — URL 데이터셋
  - `cloudflare-radar-domains-top-100000-...csv` — 상위 도메인 랭킹(정상 신호용)
  - `rf_final.pickle` — 최종 Random Forest 모델

## 피처 엔지니어링

URL을 다음 피처로 변환한다(`urllib`로 파싱 후 파생):

### 구조 파싱
- `scheme`, `netloc`, `params`, `query`, `fragment`, `tld`

### 길이 (Length)
- `url_length` — 전체 URL 길이
- `path_length` — path 길이

### 카운트 (Count)
- 특수문자 빈도: `-`, `?`, `.`, `=`, `/` 각각의 등장 횟수
- `count_dir` — path 내 `/` 개수

### 보안 신호
- `use_of_ip` — 도메인에 IP 주소 직접 사용 여부 (IPv4 / 16진수 IPv4 / IPv6 정규식 매칭)
- `url_has_file` — URL에 파일 확장자 포함 여부 (포함 1 / 미포함 -1)
- `dom_alexa_rank` — 상위 도메인 랭킹(예: Alexa/Cloudflare top list) 내 존재/순위 신호
- URL **엔트로피** — 문자 분포 기반 무작위성 척도(난독화·DGA 도메인 탐지에 유효)

## WHOIS / IPWHOIS 보강

ML 예측과 별개로 도메인/IP 등록 정보를 조회해 신뢰도 신호로 결합한다.

- `whois.whois(domain)` — 도메인 등록 정보(등록자, 생성일 등)
- `IPWhois(...).lookup_whois()` — IP 소유/등록 정보
- 조회 실패 시 `PywhoisError` 예외 처리

## 데이터 / 한계

- 깨끗하고 방대한 URL 데이터 확보가 어려움 → 피처 품질이 성능을 좌우
- 현실의 URL은 정상/악성 패턴이 매우 다양 → **오탐(FP)·미탐(FN)은 필연** → 지속적 재학습 필요

## 관련 문서

- [시스템 아키텍처](../01-architecture/SYSTEM_ARCHITECTURE.md)
- [회고 & 로드맵](../04-devlog/RETROSPECTIVE.md)
