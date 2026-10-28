"""
Сборка бинарных rule-set файлов из итогового списка.

Выходы:
  dist/domainset.txt            — "+.domain" строки для компилятора mihomo
  dist/blocklist_singbox.json   — исходник rule-set для sing-box
  dist/my_custom_blocklist.mrs  — Mihomo/OpenClash (если есть bin/mihomo)
  dist/my_custom_blocklist.srs  — sing-box (если есть bin/sing-box)
  my_custom_blocklist.domainset — Shadowrocket DOMAIN-SET: все DOMAIN-SUFFIX
                                  домены голым списком без типов (быстрый путь SR)
  my_custom_blocklist_extras.list — Shadowrocket RULE-SET: все остальные правила
                                  (DOMAIN-KEYWORD, URL-REGEX, IP-CIDR, DOMAIN)
  reports/build_stats.json      — счётчики и размеры для контроля здоровья

DOMAIN-SET + extras в сумме дают ровно my_custom_blocklist.list:
домены уходят в domainset, всё остальное — в extras, объединение тождественно
исходному списку (проверяется assert'ом при каждой сборке).

Отдельный белый список НЕ публикуется (решение владельца 28.10.2026):
домены из EXCLUSIONS (update_list.py) вырезаются из итогового списка при
сборке — из любого источника, включая добавленные позже.

Бинарники .mrs/.srs содержат только DOMAIN-SUFFIX домены:
DOMAIN-KEYWORD и URL-REGEX в доменные бинарные форматы не переводятся,
они остаются только в текстовом my_custom_blocklist.list для Shadowrocket/Surge.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LIST_FILENAME = BASE_DIR / "my_custom_blocklist.list"
DOMAINSET_FILENAME = BASE_DIR / "my_custom_blocklist.domainset"
EXTRAS_FILENAME = BASE_DIR / "my_custom_blocklist_extras.list"
DIST_DIR = BASE_DIR / "dist"
STATS_FILENAME = BASE_DIR / "reports" / "build_stats.json"
MIHOMO_BIN = BASE_DIR / "bin" / "mihomo"
SINGBOX_BIN = BASE_DIR / "bin" / "sing-box"


def read_suffix_domains() -> list[str]:
    domains: list[str] = []

    for raw in LIST_FILENAME.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.strip()

        if line.startswith("DOMAIN-SUFFIX,"):
            domains.append(line.split(",", 1)[1].strip())

    return sorted(set(domains))


def write_domainset(path: Path, domains: list[str]) -> None:
    path.write_text(
        "".join(f"+.{d}\n" for d in domains),
        encoding="utf-8",
    )


def read_list_extras() -> tuple[list[str], list[str]]:
    """DOMAIN-KEYWORD значения и IP-CIDR сети из итогового списка."""

    keywords: list[str] = []
    cidrs: list[str] = []

    for raw in LIST_FILENAME.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.strip()

        if line.startswith("DOMAIN-KEYWORD,"):
            keywords.append(line.split(",", 1)[1].strip())
        elif line.startswith(("IP-CIDR,", "IP-CIDR6,")):
            cidrs.append(line.split(",", 1)[1].split(",", 1)[0].strip())

    return sorted(set(keywords)), sorted(set(cidrs))


def subsume_by_keywords(
    domains: list[str], keywords: list[str]
) -> list[str]:
    """
    Убрать домены, содержащие выживший keyword как подстроку.

    Применяется ТОЛЬКО там, где keyword-правила живут в том же файле,
    что и домены (.srs): покрытие при этом не меняется. Для .mrs и
    DOMAIN-SET применять нельзя — в тех форматах ключевых слов нет,
    и домены там обязаны остаться полными.

    Keyword-ы с ведущим дефисом не участвуют: их семантика позиционная.
    """

    drivers = sorted(
        (k for k in keywords if not k.startswith("-")), key=len
    )

    if not drivers:
        return domains

    return [d for d in domains if not any(k in d for k in drivers)]


def write_singbox_json(
    path: Path,
    domains: list[str],
    keywords: list[str],
    cidrs: list[str],
) -> int:
    """
    JSON для компилятора sing-box rule-set.

    Отдельный объект правила на каждый тип: поля внутри одного
    объекта объединяются по И, поэтому смешивать типы нельзя.
    URL-REGEX сюда не переносится: это паттерны полных URL, а не хостов.

    Возвращает число domain_suffix после keyword-поглощения.
    """

    srs_domains = subsume_by_keywords(domains, keywords)

    rules: list[dict] = []

    if srs_domains:
        rules.append({"domain_suffix": srs_domains})
    if keywords:
        rules.append({"domain_keyword": keywords})
    if cidrs:
        rules.append({"ip_cidr": cidrs})

    payload = {"version": 1, "rules": rules}
    path.write_text(
        json.dumps(payload, separators=(",", ":")),
        encoding="utf-8",
    )

    return len(srs_domains)


def split_sr_sets() -> tuple[int, int, int]:
    """Разделить итоговый список на DOMAIN-SET и extras для Shadowrocket.

    Возвращает (доменов в domainset, правил в extras, всего правил).
    Объединение двух файлов обязано быть тождественно исходному списку.
    """
    suffix_domains: list[str] = []
    extras: list[str] = []
    total = 0

    for raw in LIST_FILENAME.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if line.startswith("DOMAIN-SUFFIX,"):
            suffix_domains.append(line.split(",", 1)[1].strip())
        else:
            extras.append(line)

    suffix_domains = sorted(set(suffix_domains))
    assert len(suffix_domains) + len(extras) == total, (
        "DOMAIN-SET + extras не равны исходному списку: "
        f"{len(suffix_domains)} + {len(extras)} != {total}"
    )

    # DOMAIN-SET: домены с ведущей точкой (".example.com" = домен и все
    # поддомены, конвенция Surge/Shadowrocket). До 28.10.2026 писались
    # голые домены: на тесте владельца (489 хостов) пара DOMAIN-SET+extras
    # дала 454/489 против 486/489 у одиночного RULE-SET; при этом часть
    # голых родителей поддомены покрывала (bugsnag), а часть — нет
    # (rollbar и др.). Точка — проверяемое исправление формата,
    # результат определит повторный тест владельца.
    DOMAINSET_FILENAME.write_text(
        "".join(f".{d}\n" for d in suffix_domains),
        encoding="utf-8",
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# ══════════════════════════════════════════════════════════════",
        "# Auto-generated extras rule-set for Shadowrocket (RULE-SET)",
        "# Все правила my_custom_blocklist.list, кроме DOMAIN-SUFFIX:",
        "# DOMAIN-KEYWORD, URL-REGEX, IP-CIDR и DOMAIN.",
        f"# Generated: {now}",
        f"# Total rules: {len(extras)}",
        "# ══════════════════════════════════════════════════════════════",
        "",
    ]
    EXTRAS_FILENAME.write_text(
        "\n".join(header) + "".join(f"{l}\n" for l in extras),
        encoding="utf-8",
    )

    return len(suffix_domains), len(extras), total


def run(cmd: list[str]) -> None:
    print("  $", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True)


def tool_version(binary: Path, *args: str) -> str:
    try:
        out = subprocess.run(
            [str(binary), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0].strip() if text else ""
    except Exception:
        return ""


def file_size(path: Path) -> int | None:
    return path.stat().st_size if path.exists() else None


def main_build() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    STATS_FILENAME.parent.mkdir(parents=True, exist_ok=True)

    previous_stats = {}
    if STATS_FILENAME.exists():
        try:
            previous_stats = json.loads(
                STATS_FILENAME.read_text(encoding="utf-8")
            )
        except Exception:
            previous_stats = {}

    suffix_domains = read_suffix_domains()

    print(f"DOMAIN-SUFFIX доменов: {len(suffix_domains):,}")

    domainset = DIST_DIR / "domainset.txt"
    blocklist_json = DIST_DIR / "blocklist_singbox.json"

    write_domainset(domainset, suffix_domains)

    keywords, cidrs = read_list_extras()
    srs_domains = write_singbox_json(
        blocklist_json, suffix_domains, keywords, cidrs
    )
    print(f"sing-box JSON: domain_suffix {srs_domains:,} "
          f"(keyword-поглощение −{len(suffix_domains) - srs_domains:,}), "
          f"domain_keyword {len(keywords):,}, ip_cidr {len(cidrs):,}")

    ds_count, ex_count, total_rules = split_sr_sets()
    print(f"DOMAIN-SET для SR: {ds_count:,} доменов; "
          f"extras: {ex_count:,} правил; всего в списке: {total_rules:,}")

    stats: dict = {
        "generated": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),
        "suffix_domains": len(suffix_domains),
        "previous_suffix_domains": previous_stats.get("suffix_domains"),
        "domainset_domains": ds_count,
        "extras_rules": ex_count,
        "list_total_rules": total_rules,
        "srs_suffix_domains": srs_domains,
        "keyword_rules": len(keywords),
        "cidr_rules": len(cidrs),
        "sizes": {},
        "tools": {},
    }

    if MIHOMO_BIN.exists():
        stats["tools"]["mihomo"] = tool_version(MIHOMO_BIN, "-v")
        run([
            str(MIHOMO_BIN), "convert-ruleset", "domain", "text",
            str(domainset), str(DIST_DIR / "my_custom_blocklist.mrs"),
        ])
    else:
        print("⚠️  bin/mihomo не найден — .mrs не собраны")

    if SINGBOX_BIN.exists():
        stats["tools"]["sing-box"] = tool_version(
            SINGBOX_BIN, "version"
        )
        run([
            str(SINGBOX_BIN), "rule-set", "compile",
            "--output", str(DIST_DIR / "my_custom_blocklist.srs"),
            str(blocklist_json),
        ])
    else:
        print("⚠️  bin/sing-box не найден — .srs не собраны")

    for name in (
        "my_custom_blocklist.list",
        "my_custom_blocklist.domainset",
        "my_custom_blocklist_extras.list",
        "my_custom_blocklist.mrs",
        "my_custom_blocklist.srs",
    ):
        path = (DIST_DIR / name) if name.endswith((".mrs", ".srs")) else (
            BASE_DIR / name
        )
        stats["sizes"][name] = file_size(path)

    STATS_FILENAME.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n📊 Статистика сборки:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main_build()
