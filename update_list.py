from __future__ import annotations

import http.client
import ipaddress
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
#  ИСТОЧНИКИ
# ─────────────────────────────────────────────

SOURCE_URLS = [
    # ── blackmatrix7 ──────────────────────────────────────────────────────────
    # Реклама (полный список)
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising.list",
    # Реклама (только домены, DOMAIN-SET формат)
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising_Domain.list",
    # Трекеры и слежка
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Privacy/Privacy.list",
    # Угон трафика провайдерами
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Hijacking/Hijacking.list",

    # ── OISD Big (глобальный мировой список) ──────────────────────────────────
    # Блокирует рекламу, трекеры, фишинг, malware, spyware, cryptojacking
    "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_big.txt",

    # ── anti-AD ───────────────────────────────────────────────────────────────
    # Независимый проект, синхронизируется с несколькими источниками
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",

    # ── AWAvenue (秋风) ────────────────────────────────────────────────────────
    # Блокирует 90%+ рекламных SDK, входит в официальный список AdGuard DNS
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge.list",

    # ── Loyalsoldier ──────────────────────────────────────────────────────────
    # Глобальный reject-список (v2ray community + GFWList + AdGuard)
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/reject.txt",

    # ── 1Hosts Lite ───────────────────────────────────────────────────────────
    # Лёгкий мировой список без агрессивной блокировки
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",

    # ── HaGeZi Ultimate ───────────────────────────────────────────────────────
    # Самый полный мировой список: реклама, трекеры, malware, phishing
    # Источники: EasyList, EasyPrivacy, AdGuard, Peter Lowe, OISD и др.
    "https://raw.githubusercontent.com/hagezi/dns-blocklists-legacy/main/domains/ultimate.txt",

    # ── StevenBlack hosts ─────────────────────────────────────────────────────
    # Классический объединённый hosts-файл: AdAway + hpHosts + Peter Lowe + MVP
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

    # ── misha-tgshv ───────────────────────────────────────────────────────────
    # GeoIP-детект домены для RU региона
    "https://cdn.jsdelivr.net/gh/Lexanewmsk/shadowrocket-configuration-file@Shadowrocket/ru_adblock_shadowrocket.conf",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/refs/heads/main/rules/domains_geo_detect.list",

    # ── notrack-blocklists (GitLab) ───────────────────────────────────────────
    # Malware-домены: вредоносные сайты, фишинг, ботнеты
    "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/malware.hosts?ref_type=heads",
    # Трекеры: сбор данных, аналитика, слежка
    "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/trackers.hosts?ref_type=heads",

    # ── hBlock ────────────────────────────────────────────────────────────────
    # Объединяет 100+ источников: реклама, трекеры, malware. Обновляется ежедневно.
    "https://hblock.molinero.dev/hosts",
]


# ─────────────────────────────────────────────
#  РУЧНЫЕ ПРАВИЛА
# ─────────────────────────────────────────────

MANUAL_RULES = {
    # Аналитика / трекеры
    "DOMAIN-SUFFIX,rudderstack.com",
    "DOMAIN-SUFFIX,pendo.io",
    "DOMAIN-SUFFIX,cryptoloot.org",
    "DOMAIN-SUFFIX,redditmedia.com",
    "DOMAIN-SUFFIX,launchdarkly.com",
    "DOMAIN-SUFFIX,split.io",
    "DOMAIN-SUFFIX,configcat.com",
    "DOMAIN-SUFFIX,flagsmith.com",
    "DOMAIN-SUFFIX,jwplayer.com",
    "DOMAIN-SUFFIX,bcovlive.io",
    "DOMAIN-SUFFIX,ngfts.lge.com",
    "DOMAIN-SUFFIX,cdn.privacy-mgmt.com",

    "DOMAIN-SUFFIX,f.vimeocdn.com",
    "DOMAIN-SUFFIX,st-widget.s3.amazonaws.com",
    "DOMAIN-SUFFIX,f.vimeocdn.com",
    "DOMAIN-SUFFIX,cdn.ravenjs.com",
    "DOMAIN-SUFFIX,tagmanager.google.com",
    "DOMAIN-SUFFIX,plus.google.com",

    "DOMAIN-SUFFIX,cookies-data.onetrust.io",
    "DOMAIN-SUFFIX,gepush.com",

    # Реклама
    "DOMAIN-SUFFIX,kaspersky-labs.com",
    "DOMAIN-SUFFIX,widgets.pinterest.com",
    "DOMAIN-SUFFIX,qevents.quora.com",

    # Email-маркетинг / спам
    "DOMAIN-SUFFIX,click.mailchimp.com",
    "DOMAIN-SUFFIX,mailchimp.com",
    "DOMAIN-SUFFIX,open.convertkit.com",
    "DOMAIN-SUFFIX,app.convertkit.com",
    "DOMAIN-SUFFIX,email.mailgun.net",
    "DOMAIN-SUFFIX,clicks.aweber.com",
    "DOMAIN-SUFFIX,pi.pardot.com",
    "DOMAIN-SUFFIX,mandrill.net",
    "DOMAIN-SUFFIX,sendgrid.net",

    # Майнинг
    "DOMAIN-SUFFIX,cpu.js.org",
    "DOMAIN-SUFFIX,fastpool.xyz",
}


# ─────────────────────────────────────────────
#  ИСКЛЮЧЕНИЯ (не блокировать включая поддомены)
# ─────────────────────────────────────────────

EXCLUSIONS = {
    "keysforgamers.com",
    "updates.maxmind.com",
    "browserleaks.com",
    "browserleaks.org",
    "browserleaks.net",
    "addr.tools",
    "dnscheck.tools",
    "graph.whatsapp.com",
    "antibot.wildberries.ru",
    "strm.yandex.ru",
}


# ─────────────────────────────────────────────
#  НАСТРОЙКИ
# ─────────────────────────────────────────────

OUTPUT_FILENAME = "my_custom_blocklist.list"

USER_AGENT = "Mozilla/5.0 (compatible; ShadowrocketBlocklistBuilder/1.0)"

DOMAIN_RULE_PREFIXES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "GEOIP",
}


# ─────────────────────────────────────────────
#  УТИЛИТЫ
# ─────────────────────────────────────────────

def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_to_cidr_rule(value: str) -> Optional[str]:
    """
    Превращает голый IP-адрес в IP-CIDR правило.

    Некоторые источники (например, blackmatrix7 Advertising Domain)
    содержат строки с голыми публичными IP-адресами без префикса.
    Раньше такие строки просто отбрасывались как нераспарсенные.

    Приватные, loopback и прочие не-глобальные адреса НЕ добавляются:
    блокировать локальную сеть через IP-CIDR нельзя.
    """

    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if not ip.is_global:
        return None

    if ip.version == 4:
        return f"IP-CIDR,{ip}/32"

    return f"IP-CIDR6,{ip}/128"


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.strip(".")
    value = value.lstrip("*.")
    value = value.lstrip(".")
    value = value.replace(" ", "")
    return value


def is_excluded_domain(domain: str) -> bool:
    """
    Проверяет, должен ли домен быть исключён из blocklist.

    Исключение работает в обе стороны.

    Например:

        EXCLUSION:
            updates.maxmind.com

        RULE:
            DOMAIN-SUFFIX,maxmind.com

    Такое правило тоже удаляется, потому что
    DOMAIN-SUFFIX,maxmind.com блокирует updates.maxmind.com.

    Также исключаются:
        updates.maxmind.com
        foo.updates.maxmind.com

    При этом обычная блокировка остальных доменов
    остаётся без изменений.
    """

    domain = normalize_domain(domain)

    if not domain:
        return False

    for exclusion in EXCLUSIONS:
        exclusion = normalize_domain(exclusion)

        if not exclusion:
            continue

        # 1. Сам домен является исключением
        if domain == exclusion:
            return True

        # 2. Домен является поддоменом исключения
        if domain.endswith("." + exclusion):
            return True

        # 3. Правило является родительским доменом
        #
        # EXCLUSION:
        #   updates.maxmind.com
        #
        # RULE:
        #   maxmind.com
        #
        # DOMAIN-SUFFIX,maxmind.com
        # всё равно заблокирует updates.maxmind.com.
        #
        # Поэтому такое правило тоже исключаем.
        if exclusion.endswith("." + domain):
            return True

    return False


def is_excluded_rule(prefix: str, value: str) -> bool:
    """
    Проверяет исключения с учётом типа Shadowrocket/Surge rule.

    DOMAIN / DOMAIN-SUFFIX:
        проверяется сам домен и родительские правила.

    DOMAIN-KEYWORD:
        keyword проверяется как подстрока.

    IP-CIDR, GEOIP, PROCESS-NAME, USER-AGENT,
    URL-REGEX остаются без изменений.
    """

    prefix = prefix.strip().upper()

    if prefix == "DOMAIN":
        domain = extract_domain_token(value)
        return bool(domain and is_excluded_domain(domain))

    if prefix == "DOMAIN-SUFFIX":
        domain = extract_domain_token(value)
        return bool(domain and is_excluded_domain(domain))

    if prefix == "DOMAIN-KEYWORD":
        # ВАЖНО:
        # DOMAIN-KEYWORD не обязан содержать точку.
        #
        # Например:
        #   adsense
        #   admob
        #   crashlytics
        #   googleads
        #   inmobi
        #
        # Поэтому require_dot=False.
        keyword = extract_domain_token(
            value,
            require_dot=False
        )

        if not keyword:
            return False

        keyword = normalize_domain(keyword)

        # DOMAIN-KEYWORD работает как поиск подстроки.
        #
        # Например:
        #   DOMAIN-KEYWORD,maxmind
        #
        # совпадёт с:
        #   updates.maxmind.com
        #
        # Поэтому такой keyword тоже нельзя оставлять,
        # если он встречается в одном из исключений.
        for exclusion in EXCLUSIONS:
            exclusion = normalize_domain(exclusion)

            if keyword in exclusion:
                return True

        return is_excluded_domain(keyword)

    return False


def strip_inline_noise(text: str) -> str:
    return text.lstrip("\ufeff").strip()


def extract_host_from_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return normalize_domain(host)


def extract_domain_token(
    text: str,
    require_dot: bool = True
) -> str:
    """
    Извлекает домен или keyword.

    require_dot=True:
        обычный домен должен содержать точку.

    require_dot=False:
        используется для DOMAIN-KEYWORD,
        где значение может быть:
            adsense
            admob
            inmobi
            crashlytics
            и т.д.
    """

    text = strip_inline_noise(text)

    if not text:
        return ""

    if text.startswith("||"):
        text = text[2:]

    if text.startswith("|"):
        text = text.lstrip("|")

    text = text.strip().strip("^").strip()
    text = text.replace("\\", "/")

    if "://" in text:
        return extract_host_from_url(text)

    text = text.split("/", 1)[0]
    text = text.split("?", 1)[0]
    text = text.split("#", 1)[0]

    if ":" in text and not text.startswith("["):
        maybe_host, maybe_port = text.rsplit(":", 1)

        if maybe_port.isdigit():
            text = maybe_host

    text = normalize_domain(text)

    if is_ip_address(text):
        return ""

    # Для обычных доменов точка обязательна.
    # Для DOMAIN-KEYWORD require_dot=False.
    if require_dot and "." not in text:
        return ""

    return text


def normalize_rule(line: str) -> Optional[str]:
    line = strip_inline_noise(line)

    if not line:
        return None

    if line.startswith(("#", "//", "!", ";")):
        return None

    # HOSTS-формат:
    # 0.0.0.0 example.com
    parts = line.split()

    if len(parts) >= 2 and is_ip_address(parts[0]):
        # HOSTS-строка вида "0.0.0.0 1.2.3.4":
        # второй токен сам является IP — блокируем его как IP-CIDR.
        if is_ip_address(parts[1]):
            return ip_to_cidr_rule(parts[1])

        host = extract_domain_token(parts[1])

        if host and not is_excluded_domain(host):
            return f"DOMAIN-SUFFIX,{host}"

        return None

    # Shadowrocket/Surge формат с префиксом
    if "," in line:
        prefix, value = line.split(",", 1)
        prefix = prefix.strip().upper()
        value = value.strip()

        if prefix in {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD"
        }:
            # Сначала проверяем исключения.
            if is_excluded_rule(prefix, value):
                return None

            # DOMAIN-KEYWORD может не содержать точки.
            domain = extract_domain_token(
                value,
                require_dot=(prefix != "DOMAIN-KEYWORD")
            )

            if not domain:
                return None

            return f"{prefix},{domain}"

        if prefix in {
            "IP-CIDR",
            "IP-CIDR6",
            "GEOIP",
            "PROCESS-NAME",
            "USER-AGENT",
            "URL-REGEX",
        }:
            return f"{prefix},{value}"

        domain = extract_domain_token(value)

        if domain and not is_excluded_domain(domain):
            return f"DOMAIN-SUFFIX,{domain}"

        return None

    # Голый IP-адрес отдельной строкой
    # (blackmatrix7 Advertising Domain и подобные списки).
    if is_ip_address(line):
        return ip_to_cidr_rule(line)

    # Adblock / raw домен
    domain = extract_domain_token(line)

    if domain and not is_excluded_domain(domain):
        return f"DOMAIN-SUFFIX,{domain}"

    return None


# ─────────────────────────────────────────────
#  ЗАГРУЗКА
# ─────────────────────────────────────────────

def _read_with_resume(
    url: str,
    timeout: int,
    context: ssl.SSLContext,
) -> tuple[bytes, str]:
    """
    Скачивает тело ответа; при обрыве на середине (IncompleteRead)
    докачивает недостающее через HTTP Range, а не начинает заново.

    Большие источники (hBlock ~14 МБ) на нестабильных соединениях
    иначе регулярно умирают, не добрав файл до конца.
    """

    buffer = bytearray()
    expected: Optional[int] = None
    content_type = ""
    max_resumes = 8

    for resume in range(max_resumes + 1):
        headers = {"User-Agent": USER_AGENT}

        if buffer:
            headers["Range"] = f"bytes={len(buffer)}-"

        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(
                req,
                timeout=timeout,
                context=context,
            ) as response:
                status = getattr(response, "status", 200)

                # Сервер проигнорировал Range и прислал файл сначала:
                # начинаем буфер заново, иначе данные задублируются.
                if buffer and status == 200:
                    buffer = bytearray()
                    expected = None

                if not content_type:
                    try:
                        content_type = response.headers.get(
                            "Content-Type", ""
                        ) or ""
                    except Exception:
                        pass

                length = response.headers.get("Content-Length")

                if length and length.isdigit():
                    total = int(length)

                    if status == 206 and buffer:
                        expected = len(buffer) + total
                    elif expected is None:
                        expected = total

                buffer += response.read()

            break

        except http.client.IncompleteRead as e:
            if e.partial:
                buffer += e.partial

            if e.expected:
                expected = (
                    len(buffer) + e.expected
                    if expected is None
                    else expected
                )

            if resume >= max_resumes:
                raise

        except urllib.error.HTTPError as e:
            # 416 на Range-запросе: сервер/прокси не согласен
            # с нашей позицией в файле. Не спорим — один раз
            # начинаем файл заново с чистого буфера.
            if e.code == 416 and buffer and resume < max_resumes:
                buffer = bytearray()
                expected = None
                continue

            raise

    if expected is not None and len(buffer) < expected:
        raise http.client.IncompleteRead(bytes(buffer), expected)

    return bytes(buffer), content_type


def fetch_text(url: str, timeout: int = 60, retries: int = 2) -> str:
    context = ssl.create_default_context()

    last_error: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            raw, content_type = _read_with_resume(
                url,
                timeout,
                context,
            )

            encoding = "utf-8"

            match = re.search(
                r"charset=([^\s;]+)",
                content_type,
                re.IGNORECASE
            )

            if match:
                encoding = match.group(1).strip(
                    '"'
                ).strip("'")

            return raw.decode(
                encoding,
                errors="replace"
            )

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError
        ) as e:
            last_error = e

            if attempt < retries:
                continue

            raise last_error


# ─────────────────────────────────────────────
#  СЖАТИЕ ПОДДОМЕНОВ
# ─────────────────────────────────────────────

def domain_ancestors(domain: str) -> list[str]:
    """Все родительские домены: a.b.example.com -> [b.example.com, example.com]."""

    parts = domain.split(".")

    return [
        ".".join(parts[i:])
        for i in range(1, len(parts))
    ]


def is_covered_by_suffixes(domain: str, suffixes: set[str]) -> bool:
    """True, если domain накрывается набором DOMAIN-SUFFIX доменов."""

    if domain in suffixes:
        return True

    return any(
        ancestor in suffixes
        for ancestor in domain_ancestors(domain)
    )


def collapse_suffix_domains(domains: set[str]) -> set[str]:
    """
    Удаляет дочерние поддомены, если родительский домен уже есть
    в наборе как DOMAIN-SUFFIX.

    ВАЖНО: это НЕ расширение блокировки. Родитель, который уже стоит
    в списке как DOMAIN-SUFFIX, и так блокирует все свои поддомены.
    Дочерние строки рядом с ним — мёртвый груз. Домены, чьего родителя
    в списке НЕТ, не трогаются вообще: aaa.bbb.cc никогда не
    превращается в блокировку всего bbb.cc.
    """

    # Сортировка по перевёрнутым меткам гарантирует,
    # что родитель всегда обрабатывается раньше потомка:
    # перевёрнутый список родителя — префикс перевёрнутого списка ребёнка.
    sorted_domains = sorted(
        domains,
        key=lambda d: d.split(".")[::-1],
    )

    optimized: set[str] = set()

    for domain in sorted_domains:
        if is_covered_by_suffixes(domain, optimized):
            continue

        optimized.add(domain)

    return optimized


def collapse_rules(rules: set[str]) -> set[str]:
    """
    Применяет сжатие поддоменов к полному набору правил.

    - DOMAIN-SUFFIX: дочерние поддомены удаляются под живым родителем.
    - DOMAIN: точное правило удаляется, если оно накрыто
      surviving DOMAIN-SUFFIX правилом.
    - Все остальные типы правил не изменяются.

    Самопроверки (сборка падает, а не пишет плохой файл):
    - каждый удалённый поддомен обязан накрываться surviving-родителем;
    - ни одно исключение из EXCLUSIONS не должно накрываться итогом.
    """

    suffix_domains: set[str] = set()
    exact_domains: set[str] = set()
    other_rules: set[str] = set()

    for rule in rules:
        prefix, _, value = rule.partition(",")

        if prefix == "DOMAIN-SUFFIX":
            suffix_domains.add(value)
        elif prefix == "DOMAIN":
            exact_domains.add(value)
        else:
            other_rules.add(rule)

    optimized = collapse_suffix_domains(suffix_domains)

    # Самопроверка покрытия: удалённое обязано накрываться.
    for removed in suffix_domains - optimized:
        if not is_covered_by_suffixes(removed, optimized):
            raise RuntimeError(
                f"Сжатие сломало покрытие домена: {removed}"
            )

    # Канарейка: исключения не должны накрываться результатом.
    for exclusion in EXCLUSIONS:
        normalized = normalize_domain(exclusion)

        if normalized and is_covered_by_suffixes(normalized, optimized):
            raise RuntimeError(
                f"Исключение накрыто итоговым списком: {normalized}"
            )

    kept_exact = {
        domain
        for domain in exact_domains
        if not is_covered_by_suffixes(domain, optimized)
    }

    result = set(other_rules)
    result.update(f"DOMAIN-SUFFIX,{d}" for d in optimized)
    result.update(f"DOMAIN,{d}" for d in kept_exact)

    return result


# ─────────────────────────────────────────────
#  СБОРКА
# ─────────────────────────────────────────────

def build_blocklist() -> list[str]:
    combined_rules: set[str] = set()

    for rule in MANUAL_RULES:
        normalized = normalize_rule(rule)

        if normalized:
            combined_rules.add(normalized)

    print(
        f"Ручных правил добавлено: {len(combined_rules)}"
    )

    print(
        "Начинаю загрузку и обработку списков...\n"
    )

    results = []
    failed = []

    for url in SOURCE_URLS:
        source_name = url.split("/")[-1]

        try:
            content = fetch_text(url)

            count_before = len(combined_rules)

            for raw_line in content.splitlines():
                normalized = normalize_rule(raw_line)

                if normalized:
                    combined_rules.add(normalized)

            added = len(combined_rules) - count_before

            results.append(
                (source_name, added, True)
            )

            print(
                f"✅ {source_name:<55} +{added}"
            )

        except Exception as e:
            results.append(
                (source_name, 0, False)
            )

            failed.append(
                (source_name, str(e))
            )

            print(
                f"❌ {source_name:<55} ОШИБКА: {e}"
            )

    if failed:
        print(
            f"\n⚠️  Не удалось загрузить "
            f"{len(failed)} источник(ов):"
        )

        for name, err in failed:
            print(
                f"   • {name}: {err}"
            )

    collapsed = collapse_rules(combined_rules)

    removed = len(combined_rules) - len(collapsed)
    percent = (
        removed / len(combined_rules) * 100
        if combined_rules
        else 0.0
    )

    print(
        f"\n🗜️  Сжатие поддоменов: "
        f"{len(combined_rules):,} -> {len(collapsed):,} "
        f"правил (удалено {removed:,}, {percent:.1f}%)"
    )

    return sorted(collapsed)


# ─────────────────────────────────────────────
#  ЗАПИСЬ
# ─────────────────────────────────────────────

def write_atomically(
    path: str,
    lines: list[str]
) -> None:

    target = Path(path)

    target.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    now = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    header = [
        "# ══════════════════════════════════════════════════════════════",
        "# Auto-generated Shadowrocket / Surge Blocklist",
        f"# Generated: {now}",
        f"# Total rules: {len(lines)}",
        "# Compression: subdomain collapse applied to DOMAIN-SUFFIX rules",
        "#",
        "# Sources:",
        *[
            f"#   {url}"
            for url in SOURCE_URLS
        ],
        "# ══════════════════════════════════════════════════════════════",
        "",
    ]

    temp_dir = str(target.parent)

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        delete=False,
        dir=temp_dir,
        prefix=target.name + ".",
        suffix=".tmp",
    ) as tmp:

        tmp_path = tmp.name

        for line in header:
            tmp.write(
                line + "\n"
            )

        for line in lines:
            tmp.write(
                line + "\n"
            )

    os.replace(
        tmp_path,
        target
    )


# ─────────────────────────────────────────────
#  ТОЧКА ВХОДА
# ─────────────────────────────────────────────

def main() -> None:
    rules = build_blocklist()

    if not rules:
        print(
            "\nНе удалось собрать ни одного правила. "
            "Файл не перезаписан."
        )
        return

    write_atomically(
        OUTPUT_FILENAME,
        rules
    )

    print(
        f"\n{'─' * 60}"
    )

    print(
        f"✅ Готово! Всего уникальных правил: "
        f"{len(rules)}"
    )

    print(
        f"📄 Файл сохранён: "
        f"{OUTPUT_FILENAME}"
    )


if __name__ == "__main__":
    main()
