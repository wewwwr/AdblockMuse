#!/usr/bin/env python3
"""Convert my_custom_blocklist.list to AdGuard Home (AdGuard) syntax.

Reads  my_custom_blocklist.list   (DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / URL-REGEX)
Writes my_custom_blocklist_agh.txt:
  DOMAIN-SUFFIX,d  ->  ||d^          (domain + all subdomains)
  DOMAIN,d         ->  ||d^
  DOMAIN-KEYWORD,k ->  /k/           (regex, metacharacters escaped)
  IP-CIDR, IP-CIDR6, URL-REGEX       ->  dropped: not expressible in DNS filtering

Run by .github/workflows/update.yml after verify_rules.py, so a list that
fails the canary never gets an AGH twin published.
"""
import collections
import re
import sys

SRC = 'my_custom_blocklist.list'
OUT = 'my_custom_blocklist_agh.txt'

ESCAPE = set('.+*?()|[]{}^$/')


def esc(keyword: str) -> str:
    return ''.join('\\' + c if c in ESCAPE else c for c in keyword)


def main() -> int:
    suffix = set()
    regexes = set()
    dropped = collections.Counter()
    gen_date = None

    with open(SRC, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                m = re.search(r'Generated:\s*(.+)', line)
                if m:
                    gen_date = m.group(1).strip()
                continue
            rtype, _, rest = line.partition(',')
            rest = rest.strip()
            if rtype in ('DOMAIN-SUFFIX', 'DOMAIN'):
                d = rest.lower().lstrip('.')
                if d:
                    suffix.add(d)
            elif rtype == 'DOMAIN-KEYWORD':
                if rest:
                    regexes.add('/' + esc(rest) + '/')
            else:
                dropped[rtype] += 1

    header = [
        '! Title: AdblockMuse — AdGuard Home version',
        '! Description: The AdblockMuse blocklist converted to AdGuard syntax.',
        '!   ||domain^  = source DOMAIN-SUFFIX (domain + all subdomains)',
        '!   /regex/    = source DOMAIN-KEYWORD rules',
        '!   IP-CIDR and URL-REGEX rules of the source cannot be expressed in DNS filtering and are omitted.',
        '! Source: https://raw.githubusercontent.com/wewwwr/AdblockMuse/main/my_custom_blocklist.list',
        f'! Source generated: {gen_date}',
        '! Homepage: https://github.com/wewwwr/AdblockMuse',
        f'! Domain rules: {len(suffix)}; keyword regex rules: {len(regexes)}; total: {len(suffix) + len(regexes)}',
        '',
    ]
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header))
        for d in sorted(suffix):
            f.write(f'||{d}^\n')
        for r in sorted(regexes):
            f.write(r + '\n')

    print(f'AGH: {len(suffix)} domain rules + {len(regexes)} keyword regexes '
          f'= {len(suffix) + len(regexes)}; dropped: {dict(dropped)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
