"""
Канареечные проверки итогового списка.

Сборка ПАДАЕТ (exit 1), если:
  - хоть одно исключение из EXCLUSIONS накрывается итоговым списком
    (само, родительским правилом или правилом-поддоменом);
  - контрольный рекламный домен перестал блокироваться;
  - в списке есть правило без точки (уровень TLD) —
    такие правила блокируют пол-интернета.

Только ПРЕДУПРЕЖДЕНИЕ, если:
  - число доменов изменилось больше чем на 35% к прошлой сборке
    (похоже на умерший или сломавшийся источник — смотреть отчёт парсера);
  - в списке есть правила, равные публичным суффиксам. По ICANN-секции
    Public Suffix List это блокировка уровня целых национальных зон
    (типа net.ar), по PRIVATE-секции — DynDNS/хостинг-домены, под которыми
    живут чужие поддомены. Такие правила приходят из самих источников
    и действуют в списке и без сжатия, поэтому сборку они не роняют,
    а выносятся в reports/public_suffix_warnings.txt для ручного решения.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LIST_FILENAME = BASE_DIR / "my_custom_blocklist.list"
STATS_FILENAME = BASE_DIR / "reports" / "build_stats.json"
PSL_FILENAME = BASE_DIR / "bin" / "public_suffix_list.dat"

# Контрольные домены: обязаны блокироваться всегда.
MUST_BLOCK = [
    "doubleclick.net",
    "googlesyndication.com",
    "appsflyersdk.com",
    "sentry.io",
    "2mdn.net",
]


def load_main_module():
    spec = importlib.util.spec_from_file_location(
        "main_blocklist",
        BASE_DIR / "update_list.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["main_blocklist"] = module
    spec.loader.exec_module(module)
    return module


main = load_main_module()


def read_suffix_domains() -> set[str]:
    domains: set[str] = set()

    for raw in LIST_FILENAME.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.strip()

        if line.startswith("DOMAIN-SUFFIX,"):
            domains.add(line.split(",", 1)[1].strip())

    return domains


def load_public_suffixes() -> dict[str, set[str]] | None:
    if not PSL_FILENAME.exists():
        return None

    sections: dict[str, set[str]] = {"icann": set(), "private": set()}
    current = "icann"

    for raw in PSL_FILENAME.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.strip()

        if "BEGIN PRIVATE DOMAINS" in line:
            current = "private"
            continue

        if "BEGIN ICANN DOMAINS" in line:
            current = "icann"
            continue

        if not line or line.startswith("//"):
            continue

        # Wildcard (*.bd) и исключения (!www.ck) пропускаем:
        # точное совпадение с обычной записью — то, что нам нужно.
        if line.startswith(("*.", "!")):
            continue

        sections[current].add(line)

    return sections


def main_verify() -> int:
    failures: list[str] = []
    suffixes = read_suffix_domains()

    print(f"DOMAIN-SUFFIX правил в итоге: {len(suffixes):,}")

    # 1. Исключения не должны накрываться.
    for exclusion in main.EXCLUSIONS:
        ex = main.normalize_domain(exclusion)

        if not ex:
            continue

        if main.is_covered_by_suffixes(ex, suffixes):
            failures.append(
                f"Исключение накрыто блоклистом: {ex}"
            )

        children = [
            d for d in suffixes
            if d == ex or d.endswith("." + ex)
        ]
        if children:
            failures.append(
                f"В блоклисте есть правила внутри исключения "
                f"{ex}: {children[:3]}"
            )

    # 2. Контрольные домены обязаны блокироваться.
    for domain in MUST_BLOCK:
        if not main.is_covered_by_suffixes(domain, suffixes):
            failures.append(
                f"Контрольный домен НЕ блокируется: {domain}"
            )

    # 3. Аудит публичных суффиксов.
    for domain in suffixes:
        if "." not in domain:
            failures.append(
                f"Правило без точки (уровень TLD): {domain}"
            )

    psl = load_public_suffixes()

    if psl is None:
        print(
            "⚠️  bin/public_suffix_list.dat не найден — "
            "аудит публичных суффиксов пропущен"
        )
    else:
        icann_hits = sorted(suffixes & psl["icann"])
        private_hits = sorted(suffixes & psl["private"])

        print(
            f"Публичных суффиксов в списке: "
            f"ICANN {len(icann_hits)}, PRIVATE {len(private_hits)} "
            f"(предупреждение, не ошибка — см. "
            f"reports/public_suffix_warnings.txt)"
        )

        warnings_path = (
            BASE_DIR / "reports" / "public_suffix_warnings.txt"
        )
        warnings_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# Правила блоклиста, равные публичным суффиксам",
            "# DOMAIN-SUFFIX на таком домене блокирует ВСЕ его поддомены.",
            "# Эти правила приходят из источников и действуют в списке",
            "# и без сжатия поддоменов. Файл — для ручного решения:",
            "# убрать правило из источников нельзя, но можно добавить",
            "# точечную обработку в update_list.py по запросу владельца.",
            "",
            f"== ICANN (национальные зоны второго уровня): {len(icann_hits)} ==",
            *icann_hits,
            "",
            f"== PRIVATE (DynDNS и хостинг-платформы): {len(private_hits)} ==",
            *private_hits,
            "",
        ]

        warnings_path.write_text(
            "\n".join(lines), encoding="utf-8"
        )

    # 4. Здоровье источников (только предупреждение).
    if STATS_FILENAME.exists():
        try:
            stats = json.loads(
                STATS_FILENAME.read_text(encoding="utf-8")
            )
            current = stats.get("suffix_domains")
            previous = stats.get("previous_suffix_domains")

            if current and previous:
                delta = abs(current - previous) / previous * 100

                if delta > 35:
                    print(
                        f"⚠️  Число доменов изменилось на "
                        f"{delta:.1f}% ({previous:,} -> "
                        f"{current:,}) — проверь отчёт парсера, "
                        f"похоже на проблему с источником"
                    )
        except Exception:
            pass

    if failures:
        print("\n❌ ПРОВЕРКА ПРОВАЛЕНА:")
        for failure in failures:
            print(f"   • {failure}")
        return 1

    print("\n✅ Все канареечные проверки пройдены")
    return 0


if __name__ == "__main__":
    sys.exit(main_verify())
