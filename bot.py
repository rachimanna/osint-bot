"""
OSINT Telegram-бот. Один файл.
Пробивает: телефон, email, username, IP, домен. Авто и лицо — заглушки.
Запуск: BOT_TOKEN=xxx python bot.py
Опционально: HIBP_KEY, NUMVERIFY_KEY
Для Render free (web): параллельно поднимается HTTP на $PORT.
"""
import asyncio, os, re, ipaddress, hashlib, logging, socket
import aiohttp, phonenumbers, whois, dns.resolver
from aiohttp import web
from phonenumbers import geocoder, carrier, timezone as pn_tz
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message


logging.basicConfig(level=logging.INFO)


BOT_TOKEN        = os.environ["BOT_TOKEN"]
HIBP_KEY         = os.getenv("HIBP_KEY", "")
NUMVERIFY_KEY    = os.getenv("NUMVERIFY_KEY", "")
PORT             = int(os.getenv("PORT", "10000"))
UA               = {"User-Agent": "Mozilla/5.0 (osint-bot)"}


HELP = (
    "Отправь:\n"
    "• телефон: +79991234567\n"
    "• email: user@mail.com\n"
    "• @username или ник\n"
    "• IP: 1.2.3.4\n"
    "• домен: example.com\n"
    "• госномер: A123BC77 (ограничено)\n"
    "• фото лица ответом (ограничено)"
)


PHONE_RE  = re.compile(r"^\+?\d[\d\-\s()]{6,}$")
EMAIL_RE  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PLATE_RE  = re.compile(r"^[АВЕКМНОРСТУХA-Z]\d{3}[АВЕКМНОРСТУХA-Z]{2}\d{2,3}$", re.I)
DOMAIN_RE = re.compile(r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
NICK_RE   = re.compile(r"^[\w.\-]{3,32}$")


def classify(text: str) -> str:
    t = text.strip()
    if EMAIL_RE.match(t): return "email"
    if PHONE_RE.match(t): return "phone"
    try:
        ipaddress.ip_address(t); return "ip"
    except ValueError:
        pass
    if PLATE_RE.match(t.replace(" ", "")): return "plate"
    if DOMAIN_RE.match(t): return "domain"
    if t.startswith("@") or NICK_RE.match(t): return "username"
    return "unknown"


# ---------- PHONE ----------
async def lookup_phone(num: str) -> str:
    try:
        p = phonenumbers.parse(num, None)
    except Exception as e:
        return f"Не парсится: {e}"
    out = [
        f"{phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}",
        f"Валидный: {phonenumbers.is_valid_number(p)}",
        f"Регион: {geocoder.description_for_number(p, 'ru') or '—'}",
        f"Оператор: {carrier.name_for_number(p, 'ru') or '—'}",
        f"TZ: {', '.join(pn_tz.time_zones_for_number(p)) or '—'}",
    ]
    if NUMVERIFY_KEY:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get("http://apilayer.net/api/validate",
                                 params={"access_key": NUMVERIFY_KEY, "number": num},
                                 timeout=10) as r:
                    j = await r.json()
                    out.append(f"Numverify line_type: {j.get('line_type','—')}")
        except Exception as e:
            out.append(f"Numverify: {e}")
    return "\n".join(out)


# ---------- EMAIL ----------
async def lookup_email(email: str) -> str:
    out = [f"{email}"]
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    out.append(f"Gravatar: https://www.gravatar.com/avatar/{md5}")
    domain = email.split("@", 1)[1]
    try:
        mx = dns.resolver.resolve(domain, "MX", lifetime=5)
        out.append("MX: " + ", ".join(str(r.exchange).rstrip(".") for r in mx))
    except Exception:
        out.append("MX: не найдено")
    async with aiohttp.ClientSession(headers=UA) as s:
        try:
            async with s.get(f"https://api.github.com/search/users?q={email}+in:email",
                             timeout=10) as r:
                if r.status == 200:
                    j = await r.json()
                    if j.get("items"):
                        out.append("GitHub: " + ", ".join(i["login"] for i in j["items"][:5]))
                    else:
                        out.append("GitHub: пусто")
        except Exception as e:
            out.append(f"GitHub: {e}")
        if HIBP_KEY:
            try:
                async with s.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                                 headers={**UA, "hibp-api-key": HIBP_KEY},
                                 timeout=10) as r:
                    if r.status == 200:
                        j = await r.json()
                        out.append("Утечки HIBP: " + ", ".join(b["Name"] for b in j))
                    elif r.status == 404:
                        out.append("Утечки HIBP: не найдено")
                    else:
                        out.append(f"HIBP: HTTP {r.status}")
            except Exception as e:
                out.append(f"HIBP: {e}")
        else:
            out.append("HIBP: ключ не задан (HIBP_KEY)")
    return "\n".join(out)


# ---------- USERNAME ----------
SITES = {
    "GitHub":    "https://github.com/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit":    "https://www.reddit.com/user/{}",
    "TikTok":    "https://www.tiktok.com/@{}",
    "Telegram":  "https://t.me/{}",
    "GitLab":    "https://gitlab.com/{}",
    "Steam":     "https://steamcommunity.com/id/{}",
    "YouTube":   "https://www.youtube.com/@{}",
    "Twitch":    "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium":    "https://medium.com/@{}",
    "HN":        "https://news.ycombinator.com/user?id={}",
    "Keybase":   "https://keybase.io/{}",
    "DevTo":     "https://dev.to/{}",
    "Lichess":   "https://lichess.org/@/{}",
    "VK":        "https://vk.com/{}",
}


async def _check(session, name, url):
    try:
        async with session.get(url, allow_redirects=True, timeout=8) as r:
            text = await r.text(errors="ignore")
            ok = r.status == 200 and "not found" not in text.lower()[:2000]
            return name, url, ok
    except Exception:
        return name, url, False


async def lookup_username(nick: str) -> str:
    async with aiohttp.ClientSession(headers=UA) as s:
        res = await asyncio.gather(*[_check(s, n, u.format(nick)) for n, u in SITES.items()])
    found = [f"{n}: {u}" for n, u, ok in res if ok]
    miss  = [n for n, _, ok in res if not ok]
    body  = "\n".join(found) if found else "ничего не нашлось"
    return f"{nick}\n\n{body}\n\nПусто: {', '.join(miss) or '—'}"


# ---------- IP ----------
async def lookup_ip(ip: str) -> str:
    out = [f"{ip}"]
    async with aiohttp.ClientSession(headers=UA) as s:
        try:
            async with s.get(f"http://ip-api.com/json/{ip}"
                             "?fields=status,country,regionName,city,isp,org,as,query,reverse,mobile,proxy,hosting",
                             timeout=10) as r:
                j = await r.json()
                if j.get("status") == "success":
                    for k in ("country", "regionName", "city", "isp", "org", "as",
                              "reverse", "mobile", "proxy", "hosting"):
                        out.append(f"{k}: {j.get(k,'—')}")
        except Exception as e:
            out.append(f"ip-api: {e}")
    try:
        host = socket.gethostbyaddr(ip)[0]
        out.append(f"PTR: {host}")
    except Exception:
        pass
    return "\n".join(out)


# ---------- DOMAIN ----------
async def lookup_domain(dom: str) -> str:
    out = [f"{dom}"]
    try:
        w = whois.whois(dom)
        for k in ("registrar", "creation_date", "expiration_date", "name_servers",
                  "emails", "country"):
            v = w.get(k)
            if v: out.append(f"{k}: {v}")
    except Exception as e:
        out.append(f"whois: {e}")
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            ans = dns.resolver.resolve(dom, rtype, lifetime=5)
            out.append(f"{rtype}: " + ", ".join(str(r).strip('"')[:120] for r in ans))
        except Exception:
            pass
    async with aiohttp.ClientSession(headers=UA) as s:
        try:
            async with s.get(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=15) as r:
                if r.status == 200 and r.content_type == "application/json":
                    j = await r.json()
                    subs = sorted({row["name_value"] for row in j})[:25]
                    out.append("Поддомены (crt.sh):\n" + "\n".join(subs))
        except Exception as e:
            out.append(f"crt.sh: {e}")
    return "\n".join(out)


# ---------- PLATE ----------
async def lookup_plate(plate: str) -> str:
    return (f"{plate}\nБесплатных открытых баз ГИБДД нет. "
            "Проверка штрафов/ОСАГО требует СТС/VIN на госуслугах или РСА.")


# ---------- FACE ----------
async def lookup_face(_bot: Bot, _file_id: str) -> str:
    return ("Поиск по лицу бесплатно и легально не делается. "
            "PimEyes/FaceCheck — платные. Для своей базы — DeepFace локально.")


# ---------- ROUTER ----------
bot = Bot(BOT_TOKEN)
dp  = Dispatcher()


@dp.message(CommandStart())
@dp.message(Command("help"))
async def start(m: Message):
    await m.answer(HELP)


@dp.message(F.photo)
async def on_photo(m: Message):
    await m.answer(await lookup_face(bot, m.photo[-1].file_id))


@dp.message(F.text)
async def on_text(m: Message):
    kind = classify(m.text)
    await m.answer("Ищу…")
    try:
        if   kind == "phone":    out = await lookup_phone(m.text.strip())
        elif kind == "email":    out = await lookup_email(m.text.strip())
        elif kind == "username": out = await lookup_username(m.text.strip().lstrip("@"))
        elif kind == "ip":       out = await lookup_ip(m.text.strip())
        elif kind == "domain":   out = await lookup_domain(m.text.strip())
        elif kind == "plate":    out = await lookup_plate(m.text.strip())
        else:                    out = "Не понял тип.\n\n" + HELP
    except Exception as e:
        out = f"Ошибка: {e}"
    for i in range(0, len(out), 3800):
        await m.answer(out[i:i+3800], disable_web_page_preview=True)


# ---------- HEALTHCHECK (Render free web) ----------
async def _health(_): return web.Response(text="ok")


async def _run_http():
    app = web.Application()
    app.router.add_get("/", _health)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    logging.info(f"HTTP healthcheck on :{PORT}")


async def main():
    await _run_http()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
