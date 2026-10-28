# AdBlock — собственный блоклист рекламы и трекеров

Ежедневно собираемый из 16 открытых источников блоклист со сжатием поддоменов
и компиляцией в бинарные rule-set форматы. Один источник правды — три выхода:
Shadowrocket/Surge, Mihomo/OpenClash и sing-box.

## Файлы и стабильные ссылки

| Файл | Формат | Для кого |
|---|---|---|
| `my_custom_blocklist.list` | текст, правила Shadowrocket/Surge | Shadowrocket, Surge |
| `my_custom_blocklist.domainset` | текст, домены без типов (DOMAIN-SET) | Shadowrocket (быстрый вариант) |
| `my_custom_blocklist_extras.list` | текст, правила кроме DOMAIN-SUFFIX | Shadowrocket (пара к DOMAIN-SET) |
| `my_custom_blocklist.mrs` | бинарный rule-set | Mihomo, OpenClash |
| `my_custom_blocklist.srs` | бинарный rule-set | sing-box, Throne |

Ссылки (подставь свой логин и имя репозитория, если переименуешь):

- Список: `https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist.list`
- DOMAIN-SET: `https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist.domainset`
- Extras: `https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist_extras.list`
- .mrs: `https://github.com/wewwwr/AdblockMuse/releases/latest/download/my_custom_blocklist.mrs`
- .srs: `https://github.com/wewwwr/AdblockMuse/releases/latest/download/my_custom_blocklist.srs`

Бинарники лежат в rolling-релизе `latest` и перезаписываются каждую сборку,
поэтому ссылки на них не меняются никогда.

> **Важно про бинарники:** в .mrs/.srs попадают только домены (DOMAIN-SUFFIX).
> Правила DOMAIN-KEYWORD и URL-REGEX в доменные бинарные форматы не переводятся —
> они остаются только в текстовом `.list` для Shadowrocket/Surge.

## Подключение

Подключается только блоклист (REJECT). Отдельного белого списка нет:
исключения уже вырезаны из блоклиста при сборке (см. «Исключения» ниже).

### Shadowrocket

Классический вариант — один файл, секция `[Rule]`:

```ini
[Rule]
RULE-SET,https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist.list,REJECT,no-resolve
```

Экспериментальный вариант — тот же набор правил, разбитый на доменный сет
и остаток:

```ini
[Rule]
DOMAIN-SET,https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist.domainset,REJECT
RULE-SET,https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist_extras.list,REJECT,no-resolve
```

⚠️ **Не рекомендуется как основной.** Замер на тесте из 489 хостов
(28.10.2026): одиночный RULE-SET выше заблокировал 486/489 (99%),
а пара с DOMAIN-SET — только 454/489 (93%): матчинг DOMAIN-SET
в Shadowrocket на сете такого размера теряет часть поддоменов,
хотя содержимое файлов идентично. Файлы оставлены для экспериментов.

`no-resolve` на RULE-SET строках не даёт клиенту резолвить домены ради
сверки с IP-CIDR правилами внутри набора — лишних DNS-запросов нет;
на DOMAIN-SET флаг не нужен, он там игнорируется.

Оба варианта дают одинаковое покрытие: domainset + extras в сумме —
это ровно `my_custom_blocklist.list` (сверяется при каждой сборке).

### OpenClash / Mihomo

```yaml
rule-providers:
  my-block:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/wewwwr/AdblockMuse/releases/latest/download/my_custom_blocklist.mrs"
    path: ./ruleset/my-block.mrs
    interval: 86400

rules:
  - RULE-SET,my-block,REJECT
  # дальше — твои существующие правила и финальная политика
```

### sing-box / Throne

В кастомный конфиг (подставь свой тег прокси-аутбаунда вместо `proxy`):

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "my-block",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/wewwwr/AdblockMuse/releases/latest/download/my_custom_blocklist.srs",
        "download_detour": "proxy"
      }
    ],
    "rules": [
      { "rule_set": "my-block", "action": "reject" }
    ]
  }
}
```

## Как работает сборка

Ежедневно в 02:00 UTC GitHub Actions:

1. `update_list.py` — скачивает 16 источников, нормализует в правила
   Shadowrocket/Surge, применяет EXCLUSIONS и ручные правила.
2. **Сжатие поддоменов**: если домен уже стоит в списке как DOMAIN-SUFFIX,
   его дочерние поддомены удаляются — родитель и так накрывает их все.
   Это не расширяет блокировку: покрытие до и после сжатия одинаковое,
   что доказывается автоматической самопроверкой при каждой сборке.
   Домен, чьего родителя в списке нет, никогда не «расширяется» вверх.
3. Голые публичные IP-адреса источников превращаются в IP-CIDR правила
   (приватные адреса не блокируются).
4. `check_parser.py` — независимый пересчёт всех источников и точная
   сверка итогового файла; отчёт — в `reports/parser_report.md`,
   нераспарсенные строки — в `reports/unparsed_lines.txt`.
5. `build_binaries.py` — компиляция .mrs и .srs; версии mihomo и sing-box
   резолвятся через GitHub API (не зашиты в имя файла).
6. `verify_rules.py` — канарейки: исключения не накрыты блоклистом,
   контрольные рекламные домены блокируются, в списке нет правил
   уровня TLD. Провал = сборка не публикуется. Правила, равные публичным
   суффиксам (приходят из самих источников), не роняют сборку, а выносятся
   в `reports/public_suffix_warnings.txt` для ручного решения.
7. Текстовые списки и отчёты коммитятся в репозиторий,
   бинарники — в rolling-релиз `latest`.

## Исключения (EXCLUSIONS)

Список доменов, которые никогда не блокируются, задаётся в `update_list.py`.
Исключение снимает сам домен, все его поддомены **и** родительское правило,
которое его накрывало бы. Фильтр применяется к объединённому итогу всех
источников, поэтому любой новый источник, добавленный в сборку позже,
автоматически учитывает те же исключения. Отдельный белый список не
публикуется: исключённых доменов в блоклисте просто нет. Чтобы добавить
исключение — допиши домен в EXCLUSIONS в `update_list.py`.

## Отчёты

- `reports/parser_report.md` — статистика по каждому источнику:
  сколько строк, сколько распарсено, сколько база реально добавила новых правил.
- `reports/build_stats.json` — счётчики и размеры файлов последней сборки;
  резкое изменение числа доменов (>35%) подсвечивается в логе проверки
  как признак умершего источника.
