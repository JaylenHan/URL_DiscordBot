# 시작 가이드 (Getting Started)

## 요구 사항

- Python 3.11 (`runtime.txt` 기준 3.11.6)
- Discord 봇 토큰 ([Discord Developer Portal](https://discord.com/developers/applications)에서 발급)

## 설치

```bash
pip install -r requirements.txt
```

주요 의존성: `discord.py==2.3.2`, `scikit-learn==1.2.2`, `python-whois`, `ipwhois`, `tld`,
`tldextract`, `pandas`, `joblib`.

## 설정 & 실행

봇 토큰은 **환경변수**로 주입한다(코드에 하드코딩 금지):

```bash
export TOKEN="your-discord-bot-token"   # Windows(PowerShell): $env:TOKEN="..."
python Tonkatsu_bot.py
```

- 봇은 `discord.Intents`의 **Message Content Intent**가 필요하다. Developer Portal에서
  해당 인텐트를 활성화해야 메시지 본문을 읽을 수 있다.
- 봇을 서버에 초대한 뒤, 채널에 URL을 입력하면 탐지/경고가 동작한다.

## 배포 (Heroku worker)

이 프로젝트는 worker dyno로 상시 구동되도록 구성돼 있다.

- `Procfile`: `worker: python Tonkatsu_bot.py`
- `runtime.txt`: `python-3.11.6`

```bash
# 예시
heroku create
heroku config:set TOKEN="your-discord-bot-token"
git push heroku main
heroku ps:scale worker=1
```

## 보안 주의

> 🔴 **하드코딩된 자격증명 제거 필요**

현재 `Tonkatsu_bot.py`에는 모델 파일(`rf_final.pickle`)을 다른 저장소에서 받아오기 위한
**자격증명이 하드코딩**되어 있다. 이는 다음과 같이 조치해야 한다:

1. 노출된 토큰을 **즉시 폐기(revoke)** — [github.com/settings/tokens](https://github.com/settings/tokens)
2. 코드의 하드코딩 값을 제거하고 **환경변수**로 전환 (예: `os.environ.get('GITHUB_TOKEN')`)
3. 모델이 **공개 저장소**에 있다면 토큰 없이 받도록 변경, 비공개라면 배포 환경의 시크릿으로 주입
4. (선택) 커밋 히스토리에서 토큰 흔적 정리

봇 토큰(`TOKEN`)은 이미 환경변수로 처리되어 있으므로 동일 원칙을 모든 자격증명에 적용한다.

## 트러블슈팅

| 증상 | 원인 | 해결 |
|---|---|---|
| 봇이 메시지를 못 읽음 | Message Content Intent 비활성 | Developer Portal에서 인텐트 활성화 |
| `Improper token` | `TOKEN` 미설정/오류 | 환경변수 재확인 |
| 모델 로드 실패 | 원격 fetch 실패/권한 | 모델 경로·접근 권한 확인(보안 주의 참고) |
| WHOIS 조회 실패 | 도메인 미등록/속도 제한 | 예외 처리됨, 일시적이면 재시도 |

## 관련 문서

- [시스템 아키텍처](../01-architecture/SYSTEM_ARCHITECTURE.md)
- [모델 & 피처](../02-model/MODEL_AND_FEATURES.md)
