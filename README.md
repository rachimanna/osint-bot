# OSINT Telegram-бот

Один файл: `bot.py`. Пробивает по бесплатным/открытым источникам.

## Что умеет
- Телефон → страна, оператор, таймзона (phonenumbers + опц. Numverify)
- Email → Gravatar, MX, GitHub-поиск, утечки HIBP (с ключом)
- Username → 17 площадок (GitHub, X, IG, Reddit, TikTok, Telegram и т.д.)
- IP → гео, ISP, PTR, флаги proxy/hosting (ip-api.com)
- Домен → whois, DNS, поддомены (crt.sh)
- Авто/лицо → заглушки (бесплатных открытых баз нет)

## Env
- `BOT_TOKEN` — обязательный, от @BotFather
- `HIBP_KEY` — опционально
- `NUMVERIFY_KEY` — опционально

## Деплой на Render
Worker-сервис, `render.yaml` готов. Переменные вбить в дашборде.
