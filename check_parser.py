from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────
# НАСТРОЙКИ / АБСОЛЮТНЫЕ ПУТИ
# ─────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent

MAIN_SCRIPT = BASE_DIR / "update_list.py"
REPORT_FILENAME = BASE_DIR / "reports" / "parser_report.md"
UNPARSED_FILENAME = BASE_DIR / "reports" / "unparsed_lines.txt"
OUTPUT_FILENAME = BASE_DIR / "my_custom_blocklist.list"


# ─────────────────────────────────────────────
# ЗАГРУЗКА ОСНОВНОГО СКРИПТА
# ─────────────────────────────────────────────

def load_main_module():
    script_path = Path(MAIN_SCRIPT)

    if not script_path.exists():
        raise FileNotFoundError(
            f"Не найден основной скрипт: {script_path}"
        )

    spec = importlib.util.spec_from_file_location(
        "main_blocklist",
        script_path,
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            f"Не удалось загрузить {script_path}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules["main_blocklist"] = module
    spec.loader.exec_module(module)

    return module


main = load_main_module()


# ─────────────────────────────────────────────
# ИМЯ ИСТОЧНИКА
# ─────────────────────────────────────────────

def source_name(url: str) -> str:
    u = url.lower()

    if "blackmatrix7" in u:
        if "advertising_domain" in u:
            return "blackmatrix7 — Advertising Domain"
        if "advertising" in u:
            return "blackmatrix7 — Advertising"
        if "privacy" in u:
            return "blackmatrix7 — Privacy"
        if "hijacking" in u:
            return "blackmatrix7 — Hijacking"

    if "oisd" in u:
        return "OISD Big"
    if "anti-ad" in u:
        return "anti-AD"
    if "awavenue" in u:
        return "AWAvenue Ads"
    if "loyalsoldier" in u:
        return "Loyalsoldier — reject"
    if "1hosts" in u:
        return "1Hosts Lite"
    if "hagezi" in u:
        return "HaGeZi Ultimate"
    if "stevenblack" in u:
        return "StevenBlack Hosts"
    if "lexanewmsk" in u:
        return "misha-tgshv — RU AdBlock"
    if "misha-tgshv" in u:
        return "misha-tgshv — Geo Detect"
    if "malware.hosts" in u:
        return "notrack — Malware"
    if "trackers.hosts" in u:
        return "notrack — Trackers"
    if "hblock" in u:
        return "hBlock"

    return url.split("/")[-1] or url


# ─────────────────────────────────────────────
# EXCLUSIONS
# ─────────────────────────────────────────────

def is_excluded_line(line: str) -> bool:
    line = main.strip_inline_noise(line)

    if not line:
        return False

    if "," in line:
        prefix, value = line.split(",", 1)
        prefix = prefix.strip().upper()
        value = value.strip()

        if prefix in {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
        }:
            return main.is_excluded_rule(prefix, value)

    parts = line.split()

    if len(parts) >= 2 and main.is_ip_address(parts[0]):
        host = main.extract_domain_token(parts[1])
        return bool(host and main.is_excluded_domain(host))

    domain = main.extract_domain_token(line)
    return bool(domain and main.is_excluded_domain(domain))


# ─────────────────────────────────────────────
# ПРОВЕРКА ИСТОЧНИКА
# ─────────────────────────────────────────────

def check_source(url: str, cumulative_rules: set[str]) -> dict:
    result = {
        "url": url,
        "name": source_name(url),
        "downloaded": False,
        "total_lines": 0,
        "empty_lines": 0,
        "comments": 0,
        "parsed": 0,
        "failed": 0,
        "excluded": 0,
        "duplicates": 0,
        "unique": 0,
        "new_to_total": 0,
        "unparsed_lines": [],
        "error": "",
    }

    try:
        content = main.fetch_text(url)
        result["downloaded"] = True

        source_rules: set[str] = set()

        for line_number, raw_line in enumerate(content.splitlines(), 1):
            result["total_lines"] += 1

            line = main.strip_inline_noise(raw_line)

            if not line:
                result["empty_lines"] += 1
                continue

            if line.startswith(("#", "//", "!", ";")):
                result["comments"] += 1
                continue

            normalized = main.normalize_rule(line)

            if normalized is None:
                if is_excluded_line(line):
                    result["excluded"] += 1
                else:
                    result["failed"] += 1
                    result["unparsed_lines"].append({
                        "line_number": line_number,
                        "line": line,
                    })
                continue

            result["parsed"] += 1

            if normalized in source_rules:
                result["duplicates"] += 1

            source_rules.add(normalized)

        result["unique"] = len(source_rules)

        before = len(cumulative_rules)
        cumulative_rules.update(source_rules)
        result["new_to_total"] = len(cumulative_rules) - before

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ─────────────────────────────────────────────
# СОХРАНЕНИЕ НЕРАСПАРСЕННЫХ СТРОК
# ─────────────────────────────────────────────

def write_unparsed_file(results: list[dict]) -> int:
    path = Path(UNPARSED_FILENAME).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total = sum(len(r["unparsed_lines"]) for r in results)

    sources_with_unparsed = sum(
        1 for r in results if r["unparsed_lines"]
    )

    lines: list[str] = [
        "# Unparsed Shadowrocket / Surge source lines",
        f"# Generated: {now}",
        f"# Total unparsed lines: {total}",
        f"# Sources with unparsed lines: {sources_with_unparsed}",
        "",
    ]

    for result in results:
        unparsed = result["unparsed_lines"]

        if not unparsed:
            continue

        lines.extend([
            "══════════════════════════════════════════════════════════════",
            f"SOURCE: {result['name']}",
            f"URL: {result['url']}",
            f"UNPARSED: {len(unparsed)}",
            "══════════════════════════════════════════════════════════════",
            "",
        ])

        for item in unparsed:
            lines.append(
                f"[line {item['line_number']}] {item['line']}"
            )

        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if not path.exists():
        raise RuntimeError(f"Не удалось создать файл: {path}")

    return total


# ─────────────────────────────────────────────
# ИТОГОВЫЙ ФАЙЛ
# ─────────────────────────────────────────────

def read_final_blocklist() -> set[str]:
    path = Path(OUTPUT_FILENAME)

    if not path.exists():
        return set()

    rules: set[str] = set()

    try:
        for raw_line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            rules.add(line)

    except Exception:
        return set()

    return rules


def compare_final_file(
    cumulative_rules: set[str],
    final_file_rules: set[str],
) -> dict:
    missing_rules = cumulative_rules - final_file_rules
    extra_rules = final_file_rules - cumulative_rules

    return {
        "exact_match": not missing_rules and not extra_rules,
        "missing": missing_rules,
        "extra": extra_rules,
    }


# ─────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────

def make_report(
    results: list[dict],
    cumulative_rules: set[str],
    manual_rules: set[str],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    successful = sum(1 for r in results if r["downloaded"])
    failed_sources = len(results) - successful
    total_lines = sum(r["total_lines"] for r in results)
    total_parsed = sum(r["parsed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_excluded = sum(r["excluded"] for r in results)
    total_duplicates = sum(r["duplicates"] for r in results)
    total_unique_per_source = sum(r["unique"] for r in results)
    total_new_to_total = sum(r["new_to_total"] for r in results)
    total_unparsed = sum(len(r["unparsed_lines"]) for r in results)

    final_file_rules = read_final_blocklist()

    # Итоговый файл собирается со сжатием поддоменов,
    # поэтому сравниваем не с сырым объединением источников,
    # а с тем же collapse_rules, что применяет update_list.py.
    expected_rules = main.collapse_rules(cumulative_rules)

    comparison = compare_final_file(
        expected_rules,
        final_file_rules,
    )

    missing_rules = comparison["missing"]
    extra_rules = comparison["extra"]

    lines: list[str] = [
        "# 🔍 Parser Report",
        "",
        f"Последняя проверка: **{now}**",
        "",
        "## 📊 Общий итог",
        "",
        f"- Источников: **{successful}/{len(results)}** успешно",
        f"- Ошибок загрузки: **{failed_sources}**",
        f"- Всего строк во всех источниках: **{total_lines:,}**",
        f"- Успешно распарсено строк: **{total_parsed:,}**",
        f"- Не удалось распарсить: **{total_failed:,}**",
        f"- Удалено через EXCLUSIONS: **{total_excluded:,}**",
        f"- Дубликатов внутри источников: **{total_duplicates:,}**",
        f"- Сумма уникальных правил по источникам: **{total_unique_per_source:,}**",
        f"- Новых правил, добавленных источниками: **{total_new_to_total:,}**",
        f"- Ручных правил: **{len(manual_rules):,}**",
        f"- Уникальных правил после объединения источников: **{len(cumulative_rules):,}**",
        f"- После сжатия поддоменов: **{len(expected_rules):,}** (удалено **{len(cumulative_rules) - len(expected_rules):,}**)",
        f"- Правил фактически в `{OUTPUT_FILENAME.name}`: **{len(final_file_rules):,}**",
        "",
        "## ❌ Нераспарсенные строки",
        "",
        f"- Всего нераспарсено: **{total_unparsed:,}**",
    ]

    if total_lines:
        percentage = total_unparsed / total_lines * 100
        lines.append(
            f"- Доля от всех строк: **{percentage:.4f}%**"
        )

    lines.extend([
        f"- Полный список: `{UNPARSED_FILENAME.relative_to(BASE_DIR)}`",
        f"- Абсолютный путь: `{UNPARSED_FILENAME}`",
        "",
        "| Источник | Нераспарсено | Статус |",
        "|---|---:|---|",
    ])

    for r in results:
        count = len(r["unparsed_lines"])
        status = "✅ 0" if count == 0 else "⚠️ проверить"

        lines.append(
            f"| {r['name']} | {count:,} | {status} |"
        )

    lines.extend([
        "",
        "> 💡 В `unparsed_lines.txt` сохранены сами строки и номера строк в исходной базе.",
        "> Пустые строки и комментарии туда не попадают.",
        "",
    ])

    if comparison["exact_match"]:
        lines.extend([
            "- Проверка итогового файла: **✅ точное совпадение**",
            "- Отсутствующих правил: **0**",
            "- Лишних правил: **0**",
        ])
    else:
        lines.extend([
            "- Проверка итогового файла: **❌ НЕ совпадает**",
            f"- Отсутствующих правил: **{len(missing_rules):,}**",
            f"- Лишних правил: **{len(extra_rules):,}**",
        ])

        if missing_rules:
            lines.extend([
                "",
                "### ❌ Примеры отсутствующих правил",
                "",
            ])
            for rule in sorted(missing_rules)[:20]:
                lines.append(f"- `{rule}`")

        if extra_rules:
            lines.extend([
                "",
                "### ⚠️ Примеры лишних правил",
                "",
            ])
            for rule in sorted(extra_rules)[:20]:
                lines.append(f"- `{rule}`")

    lines.extend([
        "",
        "## 📚 Источники",
        "",
        "| Источник | Строк | Распарсено | Отброшено | EXCLUSIONS | Дубли | Уникальных | Новых в итог | Статус |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ])

    for r in results:
        status = "✅ OK" if r["downloaded"] else f"❌ {r['error']}"

        lines.append(
            f"| {r['name']} "
            f"| {r['total_lines']:,} "
            f"| {r['parsed']:,} "
            f"| {r['failed']:,} "
            f"| {r['excluded']:,} "
            f"| {r['duplicates']:,} "
            f"| {r['unique']:,} "
            f"| {r['new_to_total']:,} "
            f"| {status} |"
        )

    lines.extend([
        "",
        "## ℹ️ Что означают столбцы",
        "",
        "- **Строк** — сколько строк получено от источника.",
        "- **Распарсено** — сколько строк превратилось в валидные Shadowrocket/Surge-правила.",
        "- **Отброшено** — строки, которые текущий парсер не смог преобразовать.",
        "- **EXCLUSIONS** — строки, которые намеренно удалены твоими исключениями.",
        "- **Дубли** — повторяющиеся правила внутри одной конкретной базы.",
        "- **Уникальных** — уникальные правила внутри конкретной базы.",
        "- **Новых в итог** — сколько уникальных правил эта база добавила сверх всех предыдущих баз.",
        "- **Нераспарсенные строки** — конкретные строки, которые `update_list.py` не смог преобразовать в правило.",
        "",
        "> 💡 Именно столбец **«Новых в итог»** показывает реальную пользу каждой базы.",
        "> Если база содержит 1 000 000 правил, но «Новых в итог» = 50 000, остальные уже были получены из других источников.",
        "",
        "## 🛡️ Проверяемая логика",
        "",
        "- `update_list.py` — основной парсер.",
        "- `DOMAIN-KEYWORD` разрешён без точки.",
        "- Дубли внутри каждой базы определяются отдельно.",
        "- Дубли между источниками удаляются через `set`.",
        "- Сжатие поддоменов (`collapse_rules`) применяется одинаково в `update_list.py` и здесь: удаляются только дети уже существующего DOMAIN-SUFFIX родителя, покрытие не меняется.",
        "- Голые публичные IP-адреса источников превращаются в IP-CIDR правила; приватные адреса не добавляются.",
        "- `EXCLUSIONS` учитываются.",
        "- Итоговый файл сравнивается по точному содержимому, а не только по количеству правил.",
        "- При несовпадении показываются примеры отсутствующих и лишних правил.",
        "- Все нераспарсенные строки сохраняются отдельно.",
        "- Пути привязаны к папке этого скрипта, поэтому запуск из другой директории не ломает сохранение файлов.",
        "",
        "## 📁 Файлы",
        "",
        f"- Основная база: `{OUTPUT_FILENAME}`",
        f"- Основной скрипт: `{MAIN_SCRIPT}`",
        f"- Этот отчёт: `{REPORT_FILENAME}`",
        f"- Нераспарсенные строки: `{UNPARSED_FILENAME}`",
    ])

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main_check() -> None:
    print("🔍 Запуск проверки всех источников...\n")

    print(f"📁 Папка скрипта: {BASE_DIR}")
    print(f"📄 Отчёт: {REPORT_FILENAME}")
    print(f"📄 Нераспарсенные строки: {UNPARSED_FILENAME}")
    print("")

    results: list[dict] = []
    cumulative_rules: set[str] = set()
    manual_rules: set[str] = set()

    for rule in main.MANUAL_RULES:
        normalized = main.normalize_rule(rule)
        if normalized:
            manual_rules.add(normalized)

    cumulative_rules.update(manual_rules)

    print(f"Ручных правил: {len(manual_rules):,}")
    print("")

    for index, url in enumerate(main.SOURCE_URLS, 1):
        print(
            f"[{index}/{len(main.SOURCE_URLS)}] "
            f"{source_name(url)}"
        )

        result = check_source(url, cumulative_rules)
        results.append(result)

        if result["downloaded"]:
            print(
                f"  ✅ строк: {result['total_lines']:,} | "
                f"parsed: {result['parsed']:,} | "
                f"failed: {result['failed']:,} | "
                f"duplicates: {result['duplicates']:,} | "
                f"new: {result['new_to_total']:,}"
            )
        else:
            print(f"  ❌ {result['error']}")

    unparsed_total = write_unparsed_file(results)

    report = make_report(
        results,
        cumulative_rules,
        manual_rules,
    )

    report_path = Path(REPORT_FILENAME)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")

    if not report_path.exists():
        raise RuntimeError(
            f"Не удалось создать отчёт: {report_path}"
        )

    print("")
    print("════════════════════════════════════════")
    print("✅ Отчёт создан:")
    print(f"   {report_path}")
    print(f"⚠️ Нераспарсенных строк: {unparsed_total:,}")
    print("📄 Полный список:")
    print(f"   {Path(UNPARSED_FILENAME).resolve()}")
    print(
        f"📊 Уникальных правил: "
        f"{len(cumulative_rules):,}"
    )
    print(
        f"🗜️  После сжатия поддоменов: "
        f"{len(main.collapse_rules(cumulative_rules)):,}"
    )
    print("════════════════════════════════════════")


if __name__ == "__main__":
    main_check()
