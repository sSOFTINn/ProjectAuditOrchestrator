# Запуск PAO для різних проєктів

`pao audit --config FILE --profile NAME` використовує приватний JSON і завжди
відкриває preview. `--execute` додатково вимагає точне підтвердження поточного
плану. Це поточний контракт кандидата v0.2; датовані інструкції старих локальних
пакетів є історичними. Почніть із [посібника пакета](../public-start.uk.md)
і [меж публічного кандидата](../release/v0.2-public-scope.md).

## Приватна конфігурація

Для публічного пакета використовуйте `pao.dev/local-audit-config/v2`.
Скопіюйте його blank `audit.json`, `toolchain.catalog.json` і
`docker-provider.json` у власну приватну папку. Значення `UNAPPROVED`,
`REPLACE_...`, порожні required paths і прострочені дати навмисно не дають запуску.

`--config` приймає абсолютний шлях або лише коротке ім'я файла. Коротке ім'я
шукається в `PAO/config` під `os.UserConfigDir`: на Windows це
`%APPDATA%\PAO\config`, на Linux — `$XDG_CONFIG_HOME/PAO/config` або
`$HOME/.config/PAO/config`. Немає пошуку в target, поточній папці чи Git;
довільний відносний шлях із каталогами відхиляється.

У v2 задайте абсолютні `target`, `evidence_base`, `report_base`,
`toolchain_root`, `manifest_root` і `toolchain_catalog`. `manifest_root`
вказує на `adapters` цього пакета. Provider JSON потрібний лише для вибраного
профілем runtime; `rule_pack_root` — для адаптерів із rules. Windows JSON
подвоює backslashes. Докладний каталог, timestamps і дозволені environment maps:
[toolchain-catalog.md](../toolchain-catalog.md).

Файли конфігурації/каталогу/provider і writable evidence/report roots не можуть
перетинати untrusted target. Не зберігайте їх у Git. Потрібні локальні абсолютні
шляхи без symlinks/junction, device aliases чи мережевих папок. Конфігурація
UTF-8 має ліміт 64 KiB; duplicate/unknown/null/wrong-type/trailing input
відхиляється. Вона не може додати shell commands, arbitrary argv, network
permission або виконання target code.

Власник окремо перевіряє точні bytes/version/license/freshness інструментів,
образів, баз, стану й правил. Catalog approval діє максимум 90 днів і не
подовжує строки окремих prerequisites. Hash сам по собі не є схваленням.
Оновлення Docker CLI чи образу потребує нового точного provider review,
а зміна конфігурації/catalog/provider потребує нового preview та RUN.

## Preview і виконання

PowerShell 7, звичайні права, з папки розпакованого перевіреного пакета:

```powershell
.\pao.exe audit --config 'D:\PAO-private\my-project.json' --profile deep-sca
.\pao.exe audit --config 'D:\PAO-private\my-project.json' --profile deep-sca --execute
```

Linux AMD64, sh, з папки перевіреного пакета; real-host scanner acceptance
ще **NOT VERIFIED**, тому ці приклади не є доказом приймання:

```sh
./pao audit --config /home/USER/pao-private/my-project.json --profile deep-sca
./pao audit --config /home/USER/pao-private/my-project.json --profile deep-sca --execute
```

Preview показує target, profile, adapters/skips, новий audit ID, paths і digests.
Він читає ціль, не запускає scanners/Git/package managers і не створює run artifacts.
Код `0` цього preview не означає успішний аудит.

Для execute PAO сформує `RUN <audit-id> <plan-digest>`. Вставте саме показану
фразу у цей термінал. «Так», EOF, порожній рядок чи фраза попереднього запуску
не підходять. Зміни config/target/manifests після підтвердження спричиняють
відмову або новий preview; не обходьте її підміною hash/approval.

Snapshot/capture обмежує фактично прочитані bytes: 64 MiB на файл, 4 GiB на
verification/copy pass і 100,000 tree entries. Файл, що росте, replacement,
reparse path, неповний snapshot чи cancellation не допускають scanner launch.
Після підтвердження scanner читає приватну перевірену target copy, а не
робочу папку. Target VCS metadata лишається `UNAVAILABLE/UNKNOWN`, оскільки
Git subprocess вимкнений. Це не повний Git-history audit.

Tool/state/DB/rules/captured-input bytes переносяться в окремі bounded frozen
copies і перевіряються перед використанням; Docker CLI та supervisor також
мають pinned/frozen identity. Оригінали не монтуються для запису.
[Модель власників і concurrent writers](../security/frozen-inputs.md)
визначає межу довіри: operator та privileged administrators залишаються trusted.
Frozen copies не доводять сумісність будь-якого native DLL/plugin чи filesystem.

## Профілі й достатність покриття

Profile треба явно вибрати кожного разу.

| `--profile` | Поточні адаптери/межі |
| --- | --- |
| `fast` | Trivy filesystem vulnerability; без IaC/image/SARIF CLI claim |
| `deep-sca` | Syft → Grype та OSV-Scanner; inventory/DB support gaps лишаються видимими |
| `license` | ScanCode та REUSE; юридичне рішення приймає людина |
| `secrets` | Gitleaks filesystem; вся історія Git не заявляється |
| `sast` | Opengrep із погодженими локальними правилами |
| `ci-security` | zizmor лише за workflow/action/Dependabot/pre-commit inputs; `go.mod` сам по собі не є workflow |
| `sbom-quality` | Syft та окремо схвалений sbomqs на captured SBOM |
| `mvp` | Дев'ять scanner contracts плюс sbomqs, із dependency/conditional/support admission |

Відсутній потрібний input дає `SKIPPED_NOT_APPLICABLE`. Наявний unsupported
input/ecosystem — окрема причина. Поточна OSV DB покриває Go тільки:
Python-only OSV має `UNSUPPORTED` / `DB_ECOSYSTEM_UNSUPPORTED`; mixed Go/PyPI
може виконати Go частину, але support лишається partial. PyPI/npm/crates.io
не отримують Go-only vulnerability coverage. Custom `requirements.lock`
і `build-requirements.lock` — `UNSUPPORTED_INPUT_FORMAT`; будь-який `.lock`
не є доказом валідного dependency inventory.

`coverage_complete` у звіті зберігає execution/parsing meaning.
`inventory_coverage` порівнює detected expected ecosystems із verified Syft
observations; Actions-only inventory не закриває Python. Відсутні ecosystems,
versions чи unsupported formats лишають gaps. `analysis_coverage_complete`
також враховує support і inventory. Adequate не означає повного package graph,
усіх runtime/build/transitive dependencies або відсутності vulnerabilities.
Інформаційний score sbomqs не замінює цей контроль і не є legal/security verdict.
Без owner-approved sbomqs його quality coverage лишається `UNAVAILABLE`.

## Ізоляція й помилки

Підтримуваний engine — лише локальна Linux VM Docker Desktop із явним endpoint,
approved image/CLI та non-root VM користувачем. Ordinary/rootless Docker Engine,
remote context і root scanners unsupported. Кожен запуск доводить required
properties; native process mode не зменшує `container-vm` вимогу.

`pao-sandbox-linux-amd64` має бути поруч із PAO в обох пакетах.
Він працює всередині VM, читає тільки fixed admitted inputs/argv і повертає
bounded output. Scanner `/tmp` має 64 MiB/4,096 inodes, `/pao/out` — до
128 MiB/4,096 inodes (менше для нижчого adapter limit). Writable host output
mount відсутній. Result cap — максимум 64 MiB, diagnostic prefix — 256 KiB;
truncation/resource failures не можуть дати complete.

Windows synthetic byte/inode/private-input/frozen-input/lifecycle controls пройшли.
Linux real-host execution, candidate compatibility й чисте public onboarding
ще не підтверджені. Не переносіть Windows PASS на Linux чи кожен real scanner.
Native JSON має size/depth/count/version limits, але parser лишається всередині
PAO; окрема process isolation і human risk acceptance не завершені.

Host-owned reason codes пояснюють помилки без scanner-controlled text.
Missing/stale tool/DB/state/rules/runtime, неподтверджена isolation, unsafe path,
resource limit, malformed native output або hash/lineage mismatch залишають
`UNAVAILABLE`, `UNSUPPORTED`, `POLICY_BLOCKED` чи `INCOMPLETE`.
Перевірте названу причину й повторіть fresh preview; не поновлюйте approval
лише щоб прибрати nonpass.

## Файли результату й exit codes

Нові назви містять UTC дату/час, safe project fragment і random suffix.
Existing outputs не перезаписуються; failure evidence зберігається.

- `<evidence_base>/<year>/<audit-id>/`: private config/effective config,
  confirmation, plan lock, run record з original producer, raw results,
  diagnostics, private findings/details і target capture.
- `<report_base>/<year>/<audit-id>/06_report/SUMMARY.md` і `report.json`:
  closed statuses/reasons, counts, findings і SHA-256 refs без raw scanner text,
  private names/snippets/paths.
- Нові Windows directories мають protected current-user/SYSTEM/Administrators
  DACL; parent permissions не змінюються. Linux private-parent ownership/modes
  перевіряються окремо.

`run_producer` — фактичний PAO первинного запуску; `report_producer` — PAO
цього rendering. Записи містять version/revision/source state/content hash,
actual executable SHA-256 і Go version. Development/modified identity явні.
Старий run без producer не доповнюється вигаданими даними й лишається
`UNKNOWN_HISTORICAL`; parser version не доводить origin.

| Код configured `pao audit --config` / alias | Значення |
| ---: | --- |
| `0` | Успішний preview або довідка; scanners не виконані |
| `3` | Invalid CLI/config/path або filesystem/report-write failure |
| `4` | Run/report має review/incomplete outcome, включно з execution error |
| `5` | Confirmation refused, stale preview або policy-blocked scanner launch |

Поточне scanner execution завжди nonpass. Якщо execution error супроводжує
blocked outcome, command повертає `4` перед перевіркою blocked records.
Report status та command exit code — пов'язані, але окремі поля.

Inspection commands мають інші коди: `version`/успішний `doctor` — `0`;
`doctor` без executable identity — `5`; невірний command/inspection args
або snapshot error — `2`; неповний `inspect`/legacy dry `plan` — `4`.
Legacy `audit --target ... --no-adapters` завжди `INCOMPLETE`/`4`.
Legacy dry `plan` приймає лише `fast`/`mvp`; configured profiles ширші.
Внутрішній `internal/exitcode` helper і ширший roadmap CLI не є mapping цієї
configured команди.

## Зберігання й ручні зміни

Config v1 лишається тільки для historical local compatibility; fixed old catalog
не є переносним approval. PAO нічого не встановлює, не поновлює approval,
не завантажує/оновлює DB, не має telemetry чи automatic updater.

Private raw evidence може містити secrets/PII; portable output теж перегляньте
перед передаванням. Оновлюйте програму через окремий перевірений пакет, зберігайте
попередній для rollback і повторюйте synthetic preview. Uninstall програмної
папки не має видаляти private config, approvals, reports або evidence.
Ephemeral frozen prerequisites і збережений audit evidence мають різні lifecycles.

[Як читати зведений звіт](unified-report.md) пояснює observations і human review.
Success tests/CI/hash checks не є final security/license/release approval.
