<div align="center">

# 🛡️ Malicious URL Detection Discord Bot (악성 URL 탐지 디스코드 봇)

**A Discord bot that detects malicious URLs in chat in real time, combining a machine-learning model with WHOIS domain intelligence.**

[![Language](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![discord.py](https://img.shields.io/badge/discord.py-2.3.2-5865F2?logo=discord&logoColor=white)](https://discordpy.readthedocs.io/)
[![ML](https://img.shields.io/badge/ML-scikit--learn-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Award](https://img.shields.io/badge/🏆_KISIA-장려상_(전체_4위)-success)](https://www.kisia.or.kr/)

🇰🇷 [한국어 README](./README.ko.md) · 📚 [Documentation](./docs)

</div>

---

## Overview

This Discord bot protects servers from phishing and malware links by **analyzing every URL posted in
chat and warning users in real time**. Each URL is run through a two-layer check:

1. **ML model** — a trained classifier scores the URL from engineered features (length, special-char
   counts, IP usage, entropy, Alexa-rank, file extension, etc.).
2. **WHOIS / IPWHOIS** — domain registration & IP ownership lookups add a trust signal on top of the
   model's verdict.

If a URL looks malicious, the bot replies in-channel with a warning and the domain's WHOIS info.

> Built during the **KISIA AI Security Technology Development training program** (team "제돈햄칼", Net-Sec class team 1)
> and awarded **장려상 — 4th place overall**.

## Highlights

- 🔍 **Real-time URL detection** on every chat message (`on_message`)
- 🧠 **ML classifier** (Random Forest) over engineered URL features
- 🌐 **WHOIS + IPWHOIS** domain/IP intelligence as a second layer
- 🧩 **De-obfuscation parsing** — strips injected spaces / Korean / special chars before analysis
- ☁️ **Deployable as a Heroku worker** (`Procfile`, `runtime.txt` included)
- 🧪 **Reproducible training assets** — notebook + datasets under `모델 학습/`

## Tech Stack

| Category | Tools |
|---|---|
| Language | Python 3.11 |
| Bot | `discord.py` 2.3.2 |
| ML | scikit-learn (Random Forest) — explored: Decision Tree, SVM, XGBoost, LightGBM |
| Domain intel | `python-whois`, `ipwhois` |
| URL parsing | `tld`, `tldextract`, `urllib` |
| Data | `pandas`, `numpy`, `joblib` |
| Deploy | Heroku (worker dyno) |

## How It Works

```
Discord message
   │
   ▼
parsing_message()   ── strip injected spaces / Korean / special chars (de-obfuscation)
   │
   ▼
check_url()         ── is this actually a URL?
   │
   ├──► feature_extract()  ── url_length, path_length, special-char counts,
   │                          count_dir, use_of_ip, url_has_file, alexa rank, entropy ...
   │         ▼
   │      predict()        ── Random Forest model (rf_final.pickle)
   │
   └──► whois_api_info()   ── WHOIS + IPWHOIS domain/IP lookup
   │
   ▼
Warning message + domain info posted to the channel
```

See [docs/01-architecture/SYSTEM_ARCHITECTURE.md](./docs/01-architecture/SYSTEM_ARCHITECTURE.md) and
[docs/02-model/MODEL_AND_FEATURES.md](./docs/02-model/MODEL_AND_FEATURES.md).

## Project Structure

```
URL_DiscordBot/
├── Tonkatsu_bot.py        # Main bot (detection pipeline + Discord events) — entry point
├── main.py                # (placeholder)
├── requirements.txt       # Python dependencies
├── Procfile               # Heroku: worker: python Tonkatsu_bot.py
├── runtime.txt            # python-3.11.6
├── 디코봇 실험체들/         # Bot experiments (WHOIS / IPWHOIS / scratch)
└── 모델 학습/              # Model training: notebook, datasets, rf_final.pickle
```

## Getting Started

```bash
pip install -r requirements.txt

# Provide your Discord bot token via environment variable (never hardcode it)
export TOKEN="your-discord-bot-token"

python Tonkatsu_bot.py
```

> ⚠️ **Security note:** the source currently contains a hardcoded credential used to fetch the model
> file from another repo. It must be **revoked and moved to an environment variable**. See
> [docs/03-guides/GETTING_STARTED.md](./docs/03-guides/GETTING_STARTED.md#보안-주의).

## Documentation

| Doc | What's inside |
|---|---|
| [00 · Project Brief](./docs/00-overview/PROJECT_BRIEF.md) | Problem, award, team, role |
| [01 · System Architecture](./docs/01-architecture/SYSTEM_ARCHITECTURE.md) | Detection pipeline, Discord events, deployment |
| [02 · Model & Features](./docs/02-model/MODEL_AND_FEATURES.md) | Feature engineering, models, dataset, training |
| [03 · Getting Started](./docs/03-guides/GETTING_STARTED.md) | Install, config, run, deploy, security |
| [04 · Retrospective & Roadmap](./docs/04-devlog/RETROSPECTIVE.md) | Lessons learned, future direction |

## Roadmap

- Detect more threats beyond URLs (malicious files, fake Nitro generators, etc.)
- Share threat intel with security communities; continuously retrain the model
- In-bot security education & guidance for users

## Credits

**Team 제육돈까스햄버거칼국수 (제돈햄칼)** — KISIA AI Security training, Net-Sec class team 1.
Lead: 남정운 · Members: 강승구, 김용범, 정민성, 한승헌.

**한승헌 (Jaylen Han)** — planning · data collection/labeling/preprocessing · feature engineering ·
model selection & dataset management · Decision Tree model training.

- 🏆 KISIA AI Security Technology Development program — **장려상 (4th place overall)** · 2023.07–2023.11

## License

Educational project. No formal license is currently attached; please contact the author before reuse.
