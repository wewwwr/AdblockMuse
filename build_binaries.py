"""
Сборка бинарных rule-set файлов из итогового списка.

Выходы:
  dist/domainset.txt            — "+.domain" строки для компилятора mihomo
  dist/direct_domainset.txt     — то же для белого списка (EXCLUSIONS)
  dist/blocklist_singbox.json   — исходник rule-set для sing-box
  dist/direct_singbox.json      — то же для белого списка
  dist/my_custom_blocklist.mrs  — Mihomo/OpenClash (если есть bin/mihomo)
  dist/my_custom_direct.mrs     — белый список для Mihomo/OpenClash
  dist/my_custom_blocklist.srs  — sing-box (если есть bin/sing-box)
  dist/my_custom_direct.srs     — белый список для sing-box
  my_custom_direct_list.list    — белый список в формате Shadowrocket (в корне)
  reports/build_stats.json      — счётчики и размеры для контроля здоровья

Бинарники .mrs/.srs содержат только DOMAIN-SUFFIX домены:
DOMAIN-KEYWORD и URL-REGEX в доменные бинарные форматы не переводятся,
они остаются только в текстовом my_custom_blocklist.list для Shadowrocket/Surge.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LIST_FILENAME = BASE_DIR / "my_custom_blocklist.list"
DIRECT_LIST_FILENAME = BASE_DIR / "my_custom_direct_list.list"
DIST_DIR = BASE_DIR / "dist"
STATS_FILENAME = BASE_DIR / "reports" / "build_stats.json"
MIHOMO_BIN = BASE_DIR / "bin" / "mihomo"
SINGBOX_BIN = BASE_DIR / "bin" / "sing-box"


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


def write_singbox_json(path: Path, domains: list[str]) -> None:
    payload = {
        "version": 1,
        "rules": [
            {"domain_suffix": domains},
        ],
    }
    path.write_text(
        json.dumps(payload, separators=(",", ":")),
        encoding="utf-8",
    )


def write_direct_list(domains: list[str]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header = [
        "# ══════════════════════════════════════════════════════════════",
        "# Auto-generated Direct (whitelist) list — from EXCLUSIONS",
        f"# Generated: {now}",
        f"# Total rules: {len(domains)}",
        "# ══════════════════════════════════════════════════════════════",
        "",
    ]

    DIRECT_LIST_FILENAME.write_text(
        "\n".join(header)
        + "".join(f"DOMAIN-SUFFIX,{d}\n" for d in domains),
        encoding="utf-8",
    )


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
    direct_domains = sorted(
        {
            main.normalize_domain(e)
            for e in main.EXCLUSIONS
            if main.normalize_domain(e)
        }
    )

    print(f"DOMAIN-SUFFIX доменов: {len(suffix_domains):,}")
    print(f"Доменов белого списка: {len(direct_domains):,}")

    domainset = DIST_DIR / "domainset.txt"
    direct_domainset = DIST_DIR / "direct_domainset.txt"
    blocklist_json = DIST_DIR / "blocklist_singbox.json"
    direct_json = DIST_DIR / "direct_singbox.json"

    write_domainset(domainset, suffix_domains)
    write_domainset(direct_domainset, direct_domains)
    write_singbox_json(blocklist_json, suffix_domains)
    write_singbox_json(direct_json, direct_domains)
    write_direct_list(direct_domains)

    stats: dict = {
        "generated": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),
        "suffix_domains": len(suffix_domains),
        "previous_suffix_domains": previous_stats.get("suffix_domains"),
        "direct_domains": len(direct_domains),
        "sizes": {},
        "tools": {},
    }

    if MIHOMO_BIN.exists():
        stats["tools"]["mihomo"] = tool_version(MIHOMO_BIN, "-v")
        run([
            str(MIHOMO_BIN), "convert-ruleset", "domain", "text",
            str(domainset), str(DIST_DIR / "my_custom_blocklist.mrs"),
        ])
        run([
            str(MIHOMO_BIN), "convert-ruleset", "domain", "text",
            str(direct_domainset), str(DIST_DIR / "my_custom_direct.mrs"),
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
        run([
            str(SINGBOX_BIN), "rule-set", "compile",
            "--output", str(DIST_DIR / "my_custom_direct.srs"),
            str(direct_json),
        ])
    else:
        print("⚠️  bin/sing-box не найден — .srs не собраны")

    for name in (
        "my_custom_blocklist.list",
        "my_custom_direct_list.list",
        "my_custom_blocklist.mrs",
        "my_custom_direct.mrs",
        "my_custom_blocklist.srs",
        "my_custom_direct.srs",
    ):
        path = (BASE_DIR / name) if name.endswith(".list") else (
            DIST_DIR / name
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
