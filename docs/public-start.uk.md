# PAO: початок роботи з публічним пакетом

Версія цього пакета: `@PAO_VERSION@`; tag: `@PAO_TAG@`;
source commit: `@PAO_REVISION@`. Звірте версію з `VERSION.json`, а source commit — із підписаним тегом
і `doctor`. У вихідному посібнику вони є шаблонами; пакувальник підставляє
ідентичність конкретної збірки.

Наявність архіву, контрольної суми чи успішного `doctor` не означає схвалення
випуску або готовність повного аудиту. Пакет містить основну програму PAO,
власний статичний Linux AMD64 помічник `pao-sandbox-linux-amd64`, десять
декларацій адаптерів, три порожні JSON-шаблони, цей посібник, ліцензії та
перелік SHA-256 файлів. Зберігайте помічник поруч із PAO в обох пакетах;
PAO перевіряє його hash і використовує лише всередині погодженої Linux VM.
Пакет не містить сторонніх сканерів, образів, баз вразливостей, правил,
конфіденційних налаштувань, звітів чи доказів. PAO не встановлює їх автоматично.

## Перед першим запуском

Оберіть Windows AMD64 ZIP або Linux AMD64 tar.gz. Опубліковані випуски
завантажуйте зі сторінки
[sSOFTINn/ProjectAuditOrchestrator Releases](https://github.com/sSOFTINn/ProjectAuditOrchestrator/releases).
Посилання не доводить, що цей випуск уже опубліковано. Звірте SHA-256 архіву
з `SHA256SUMS.txt` і перевірте підписаний тег та прив'язану до нього суму цього файла за
[інструкцією цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/release-verification.md).
Довірений підпис тега має підтверджувати exact commit і SHA-256 файла
`SHA256SUMS.txt`. Самі контрольні суми не підтверджують автора. Якщо перевірка не пройшла,
не запускайте пакет. Розпаковуйте в нову власну папку без прав адміністратора.

Windows, PowerShell 7, із папки завантаження:

```powershell
Get-FileHash -LiteralPath .\pao-@PAO_VERSION@-windows-amd64.zip -Algorithm SHA256
# Після звірки SHA-256 і підписаного тега; папка призначення має бути новою.
Expand-Archive -LiteralPath .\pao-@PAO_VERSION@-windows-amd64.zip -DestinationPath .\pao-@PAO_VERSION@
Set-Location .\pao-@PAO_VERSION@
.\pao.exe version
.\pao.exe doctor
```

Linux AMD64, оболонка sh, із папки завантаження:

```sh
sha256sum pao-@PAO_VERSION@-linux-amd64.tar.gz
# Після звірки SHA-256 і підписаного тега.
mkdir pao-@PAO_VERSION@
tar -xzf pao-@PAO_VERSION@-linux-amd64.tar.gz -C pao-@PAO_VERSION@
cd pao-@PAO_VERSION@
./pao version
./pao doctor
```

`doctor` показує ідентичність програми. Він не доводить справність Docker,
наявність сканерів чи ізоляцію запуску. Цільові ОС — Windows 11 x64 та Ubuntu
24.04 LTS x64. Підтримані версії Docker Desktop звіряйте з примітками
конкретного підписаного випуску; успішний `doctor` не підтверджує сумісність.

Провайдер допускає лише локальну Linux VM Docker Desktop на Windows або Linux,
із явно заданим локальним endpoint, перевіреним Docker CLI та погодженим образом.
Сканер працює від non-root користувача VM. Звичайний Docker Engine, rootless
Engine, віддалені контексти й root-сканер не підтримані. Не обходьте перевірки.

Сканер має лише read-only входи. Його `/tmp` і `/pao/out` розміщені в tmpfs
Linux VM з квотами байтів та кількості файлів/каталогів; writable host output
mount відсутній. Помічник повертає лише обмежені результати. Формат JSON
розбирається всередині PAO: спільний parser обмежує розмір, глибину й кількість
значень; окремий parser SBOMQS має обмеження розміру та перевірку результату.
Окремої процесної ізоляції parser-ів немає, тому помилка чи надмірно складний
вхід може зависнути або аварійно завершити PAO.

## Безпечна перша перевірка

Створіть окрему папку із синтетичним текстовим файлом без персональних даних.
Замініть абсолютний шлях у прикладі на цю папку:

```powershell
.\pao.exe inspect --target 'D:\PAO-demo\synthetic'
.\pao.exe plan --target 'D:\PAO-demo\synthetic' --profile fast --dry-run
```

```sh
./pao inspect --target /home/USER/pao-demo/synthetic
./pao plan --target /home/USER/pao-demo/synthetic --profile fast --dry-run
```

Ці команди читають ціль і формують план. Вони не запускають сканери,
Git subprocess, package managers чи код цілі. VCS commit/dirty у target snapshot
лишаються `UNAVAILABLE/UNKNOWN`. Не починайте з приватного робочого проєкту.

## Налаштування реального аудиту

`audit.json`, `toolchain.catalog.json` і `docker-provider.json` — шаблони з
порожніми/`REPLACE_...` значеннями та `UNAPPROVED`. Вони навмисно не дають
готового дозволу на запуск. Збережіть робочі копії у власній приватній папці.
Потрібні абсолютні шляхи до цілі, `adapters` із пакета, власного каталогу
інструментів, провайдера, доказів і звітів. Докази/звіти та trusted config
мають бути поза target. Windows JSON подвоює backslashes: `D:\\PAO\\adapters`.

Коротке ім'я `--config my-project.json` шукається лише в `PAO/config` усередині
системного `os.UserConfigDir`. Довільний відносний шлях не підтримується;
абсолютний шлях до приватного JSON працює на обох ОС.

Власник окремо встановлює й перевіряє інструменти, образи, бази та правила,
їхні точні SHA-256, версії, дати й ліцензійні умови. Наявність файла не створює
схвалення. Не копіюйте чужі дозволи, хеші чи дати. Порожній каталог означає
неповне покриття, а не відсутність проблем. Структура каталогу та дозволені
environment values описані в
[toolchain-catalog.md цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/toolchain-catalog.md).

Після налаштування підтримуваного хоста відкрийте preview:

```powershell
.\pao.exe audit --config 'D:\PAO-private\audit.json' --profile mvp
```

```sh
./pao audit --config /home/USER/pao-private/audit.json --profile mvp
```

Виконання потребує додаткового `--execute` і точного
`RUN <audit-id> <plan-digest>`, який PAO формує для поточного preview.
Фраза з попереднього запуску не підходить. Відсутні інструменти, прострочені
дані або непідтверджена ізоляція лишаються причиною відмови.
[Операторська інструкція цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/operations/configured-local-audit.md)
описує профілі, preview/execute і результати.

`deep-sca` не означає універсальне SCA. Поточна OSV DB покриває лише Go:
наявна PyPI/npm/Rust екосистема має `DB_ECOSYSTEM_UNSUPPORTED`. Python-only
OSV є `UNSUPPORTED`, mixed Go/Python має partial support. Назви
`requirements.lock` і `build-requirements.lock` не визначають підтриманий
формат і лишають `UNSUPPORTED_INPUT_FORMAT`. Самі GitHub Actions у Syft
не доводять інвентаризацію Python. Оцінка sbomqs є інформаційною й не закриває
ці прогалини.

## Результати, оновлення та підтримка

`PARTIAL`, `UNAVAILABLE`, `UNSUPPORTED`, `BLOCKED`, `REVIEW_REQUIRED` і
`NOT APPROVED` залишаються обмеженнями. Зелена перевірка файлів не є
висновком про безпеку, юридичну відповідність чи повне покриття. Raw evidence
зберігається локально; перед передаванням звіту перевіряйте його на секрети й PII.

У `report.json` старе `coverage_complete` означає завершення execution/parsing.
`inventory_coverage` окремо показує expected/observed ecosystems і gaps;
`analysis_coverage_complete` враховує також support та inventory.
Adequate inventory не доводить кожну транзитивну/build/runtime залежність.
`run_producer` описує програму первинного запуску, `report_producer` —
програму, яка створила цей звіт. Старий запуск без записаної ідентичності
лишається `UNKNOWN_HISTORICAL`; parser version не замінює hash виконуваного PAO.

Для `pao audit --config ...` коди: `0` — лише preview/довідка;
`3` — помилка аргументів, конфігурації або файлової операції;
`4` — виконання/звіт потребує review або лишається incomplete;
`5` — відхилене підтвердження, змінений preview або policy-blocked запуск.
Поточне виконання сканерів не повертає автоматичний PASS із кодом `0`.
`version`, `doctor`, `inspect` і legacy dry `plan` мають окремий контракт,
описаний в операторській інструкції.

PAO не має телеметрії й автоматичного оновлення. Для ручного оновлення звірте
новий випуск, розпакуйте в нову папку й повторіть synthetic перевірку. Збережіть
попередній пакет і приватні налаштування. Для rollback використайте збережений
перевірений пакет і новий preview; зміни catalog/provider потребують нового RUN.
Для uninstall приберіть окрему папку програми за власним рішенням. Не видаляйте
разом із нею приватні configs, approvals, reports і evidence; автоматичного
очищення цих даних немає. Підтримка охоплює найновіший опублікований stable release;
кандидати не мають обіцянки стабільності.

Для вразливостей використовуйте
[приватне повідомлення GitHub Security Advisory](https://github.com/sSOFTINn/ProjectAuditOrchestrator/security/advisories/new).
Не додавайте exploits, secrets чи private repos до public issue. Якщо приватна
форма недоступна, не переносіть повідомлення у public issue; доступність
приватного каналу має бути підтверджена перед публікацією.

PAO поширюється за Apache-2.0 (`LICENSE`). Обидва власні executable містять
Go runtime/stdlib, ліцензія яких у `licenses/GO-LICENSE.txt`.
Ліцензія PAO не надає прав на сторонні сканери, бази чи правила.
