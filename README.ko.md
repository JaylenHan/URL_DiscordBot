<div align="center">

# 🛡️ 악성 URL 탐지 디스코드 봇

**머신러닝 모델과 WHOIS 도메인 정보를 결합해, 채팅 속 악성 URL을 실시간으로 탐지하는 Discord 봇.**

[![Language](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![discord.py](https://img.shields.io/badge/discord.py-2.3.2-5865F2?logo=discord&logoColor=white)](https://discordpy.readthedocs.io/)
[![ML](https://img.shields.io/badge/ML-scikit--learn-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Award](https://img.shields.io/badge/🏆_KISIA-장려상_(전체_4위)-success)](https://www.kisia.or.kr/)

🇺🇸 [English README](./README.md) · 📚 [문서](./docs)

</div>

---

## 소개

이 디스코드 봇은 **채팅에 올라오는 모든 URL을 분석해 실시간으로 경고**함으로써, 피싱·악성코드
링크로부터 서버를 보호합니다. 각 URL은 2단계 검증을 거칩니다:

1. **ML 모델** — URL에서 추출한 피처(길이, 특수문자 수, IP 사용, 엔트로피, Alexa 랭크, 파일 확장자 등)로
   악성 여부를 분류
2. **WHOIS / IPWHOIS** — 도메인 등록 정보·IP 소유 정보를 조회해 모델 판정에 신뢰도 신호를 더함

악성으로 판단되면 봇이 채널에 경고 메시지와 도메인 WHOIS 정보를 함께 출력합니다.

> **KISIA AI보안 기술개발 교육과정**(팀 "제돈햄칼", 네트워크보안반 1팀)에서 개발했으며,
> **장려상 — 전체 4위**를 수상했습니다.

## 핵심 특징

- 🔍 **실시간 URL 탐지** — 모든 채팅 메시지에 대해 동작 (`on_message`)
- 🧠 **ML 분류기**(Random Forest) — 엔지니어링된 URL 피처 기반
- 🌐 **WHOIS + IPWHOIS** — 도메인/IP 정보를 2차 검증 레이어로 활용
- 🧩 **난독화 해제 파싱** — 삽입된 공백/한글/특수문자를 제거 후 분석
- ☁️ **Heroku worker 배포 가능** (`Procfile`, `runtime.txt` 포함)
- 🧪 **재현 가능한 학습 자산** — `모델 학습/`에 노트북 + 데이터셋

## 기술 스택

| 분류 | 도구 |
|---|---|
| 언어 | Python 3.11 |
| 봇 | `discord.py` 2.3.2 |
| ML | scikit-learn (Random Forest) — 탐색: Decision Tree, SVM, XGBoost, LightGBM |
| 도메인 정보 | `python-whois`, `ipwhois` |
| URL 파싱 | `tld`, `tldextract`, `urllib` |
| 데이터 | `pandas`, `numpy`, `joblib` |
| 배포 | Heroku (worker dyno) |

## 동작 방식

```
Discord 메시지
   │
   ▼
parsing_message()   ── 삽입된 공백/한글/특수문자 제거 (난독화 해제)
   │
   ▼
check_url()         ── 실제 URL인지 판별
   │
   ├──► feature_extract()  ── url_length, path_length, 특수문자 카운트,
   │                          count_dir, use_of_ip, url_has_file, alexa rank, 엔트로피 ...
   │         ▼
   │      predict()        ── Random Forest 모델 (rf_final.pickle)
   │
   └──► whois_api_info()   ── WHOIS + IPWHOIS 도메인/IP 조회
   │
   ▼
채널에 경고 메시지 + 도메인 정보 출력
```

상세: [docs/01-architecture/SYSTEM_ARCHITECTURE.md](./docs/01-architecture/SYSTEM_ARCHITECTURE.md),
[docs/02-model/MODEL_AND_FEATURES.md](./docs/02-model/MODEL_AND_FEATURES.md).

## 프로젝트 구조

```
URL_DiscordBot/
├── Tonkatsu_bot.py        # 메인 봇 (탐지 파이프라인 + Discord 이벤트) — 진입점
├── main.py                # (플레이스홀더)
├── requirements.txt       # Python 의존성
├── Procfile               # Heroku: worker: python Tonkatsu_bot.py
├── runtime.txt            # python-3.11.6
├── 디코봇 실험체들/         # 봇 실험 코드 (WHOIS / IPWHOIS / scratch)
└── 모델 학습/              # 모델 학습: 노트북, 데이터셋, rf_final.pickle
```

## 시작하기

```bash
pip install -r requirements.txt

# Discord 봇 토큰은 환경변수로 주입 (절대 하드코딩 금지)
export TOKEN="your-discord-bot-token"

python Tonkatsu_bot.py
```

> ⚠️ **보안 주의:** 현재 소스에는 모델 파일을 다른 레포에서 받아오기 위한 자격증명이 하드코딩되어 있습니다.
> **즉시 폐기하고 환경변수로 옮겨야** 합니다. [docs/03-guides/GETTING_STARTED.md](./docs/03-guides/GETTING_STARTED.md#보안-주의) 참고.

## 문서

| 문서 | 내용 |
|---|---|
| [00 · 프로젝트 개요](./docs/00-overview/PROJECT_BRIEF.md) | 문제 정의, 수상, 팀, 역할 |
| [01 · 시스템 아키텍처](./docs/01-architecture/SYSTEM_ARCHITECTURE.md) | 탐지 파이프라인, Discord 이벤트, 배포 |
| [02 · 모델 & 피처](./docs/02-model/MODEL_AND_FEATURES.md) | 피처 엔지니어링, 모델, 데이터셋, 학습 |
| [03 · 시작 가이드](./docs/03-guides/GETTING_STARTED.md) | 설치, 설정, 실행, 배포, 보안 |
| [04 · 회고 & 로드맵](./docs/04-devlog/RETROSPECTIVE.md) | 깨달은 점, 향후 방향 |

## 로드맵

- URL 외 위협 탐지 확장(악성 파일, 위장 Nitro 생성기 등)
- 보안 커뮤니티와 위협 정보 공유 + 모델 지속 재학습
- 봇 내 사용자 보안 교육·안내

## 크레딧

**팀 제육돈까스햄버거칼국수 (제돈햄칼)** — KISIA AI보안 교육, 네트워크보안반 1팀.
팀장: 남정운 · 팀원: 강승구, 김용범, 정민성, 한승헌.

**한승헌 (Jaylen Han)** — 기획 · 데이터 수집/레이블링/전처리 · Feature Engineering ·
학습 모델 분류 및 데이터셋 관리 · Decision Tree 모델 학습.

- 🏆 KISIA AI보안 기술개발 교육과정 — **장려상 (전체 4위)** · 2023.07~2023.11

## 라이선스

교육용 프로젝트. 현재 별도 라이선스가 부착돼 있지 않으며, 재사용 전 작성자에게 문의 바랍니다.
