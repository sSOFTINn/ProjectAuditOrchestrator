# PAO: початок роботи з публічним пакетом

Версія цього пакета: `@PAO_VERSION@`; очікувана назва тега опублікованого
випуску: `@PAO_TAG@`; базовий source commit: `@PAO_REVISION@`.
Звірте версію з `VERSION.json` та ідентичність із `doctor`. У вихідному
посібнику ці значення є шаблонами; пакувальник підставляє ідентичність збірки.

Локальний кандидат може не мати підписаного тега чи публікації. Очікувана назва
тега не доводить його існування. `source_state=modified` означає, що збірка
містить зміни поверх базового коміту; точний склад визначає `source_tree_sha256`
у `doctor` та приватному записі збірки. Такий пакет призначений для локального
оцінювання з довіреного джерела й не має статусу схваленого випуску.

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
з `SHA256SUMS.txt`. Для опублікованого випуску перевірте підписаний тег та прив'язану до нього суму цього файла за
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

## Перший аудит: профіль secrets

Почніть із `secrets`: потрібні лише **Gitleaks 8.30.1 для Linux AMD64**,
погоджений Docker Desktop runtime і три приватні JSON. Це точна версія з
`adapters/gitleaks/manifest.json` цього пакета. Навіть на Windows потрібен
Linux scanner `gitleaks`, бо він працює всередині Linux VM; Windows `gitleaks.exe`
для цього workflow не підходить. Окремі vulnerability DB, prepared state і rule
pack цьому профілю не потрібні. `mvp` додає інші інструменти та їхні prerequisites;
переходьте до нього після першого прийнятого запуску.

Наведені кроки описують підготовку. Вони не підтверджують, що нова інсталяція,
поточний кандидат або довільна версія Docker Desktop уже пройшли приймання.
Встановлення, мережеві завантаження й підготовка образу відбуваються окремо
від аудиту; PAO не виконує їх автоматично.

### 1. Підготуйте окремі каталоги

Нижче `D:\PAO-first-run` — приклад **нового** приватного каталогу на Windows,
`/home/USER/pao-first-run` — відповідний приклад Linux. Замініть їх своїми
абсолютними локальними шляхами. Папка перевіреного пакета PAO розташована окремо.
Не використовуйте мережеві папки, symlinks/junction або каталоги всередині
робочого проєкту. Конфігурації, інструменти, докази та звіти також мають бути
окремими сусідніми каталогами:

```text
PAO-first-run/
  config/       audit.json, toolchain.catalog.json, docker-provider.json
  tools/        gitleaks/8.30.1/bin/gitleaks
  reviews/      runtime-review.txt
  synthetic/    README.txt
  evidence/     приватні докази майбутніх запусків
  reports/      очищені локальні звіти майбутніх запусків
```

Створіть цю структуру від звичайного користувача. На Linux використовуйте
власника поточного користувача, mode `0700` для приватних каталогів і `0600`
для JSON/review-файлів; scanner має залишатися executable. На Windows перед
реальним аудитом підготуйте й перевірте ACL приватних roots за
[політикою прав доступу цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/security/windows-state-directory-acl.md).
Новий каталог із успадкованими правами ще не є доказом захисту.

У новому `synthetic/README.txt` збережіть лише текст `PAO synthetic example`.
Не додавайте справжніх токенів, даних людей, файлів робочого проєкту або
власних налаштувань Gitleaks. Далі всі команди аудиту використовують тільки
цю синтетичну ціль.

### 2. Отримайте й перевірте scanner

З офіційного [випуску Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
отримайте `gitleaks_8.30.1_linux_x64.tar.gz` та
[`gitleaks_8.30.1_checksums.txt`](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt).
Назва upstream `linux_x64` відповідає Linux AMD64. Ці назви й посилання
перевірено 2026-10-20; доступність посилання не схвалює завантажені bytes.
Збережіть походження, версію, контрольну суму й відомості про
[ліцензію цього випуску](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE)
у приватному записі перевірки.

Із папки завантажень виміряйте SHA-256 архіву й порівняйте **повні 64 hex-символи**
з рядком саме `gitleaks_8.30.1_linux_x64.tar.gz` в офіційному checksum-файлі:

```powershell
Get-FileHash -LiteralPath .\gitleaks_8.30.1_linux_x64.tar.gz -Algorithm SHA256
```

```sh
sha256sum gitleaks_8.30.1_linux_x64.tar.gz
```

Лише після збігу та перевірки джерела розпакуйте архів у новий
`tools/gitleaks/8.30.1/bin/`; збережіть його license notices. Перевірте, що
`gitleaks` — звичайний файл, а не посилання. На Linux надайте **цьому файлу**
право виконання для власника. Не запускайте Linux scanner безпосередньо на
Windows і не підміняйте його версією `latest`.

### 3. Підготуйте Docker runtime і запис перевірки

Встановіть версію Docker Desktop, для якої є приймання цього випуску PAO,
за офіційною інструкцією для
[Windows](https://docs.docker.com/desktop/setup/install/windows-install/) або
[Ubuntu](https://docs.docker.com/desktop/setup/install/linux/ubuntu/).
Окремо прийміть застосовні умови використання та можливий restart. На Linux
потрібна саме VM Docker Desktop і non-root користувач; системний Docker Engine
не замінює її. Публічні вимоги Docker не є доказом сумісності конкретного PAO.

Підготовка runtime потребує перевіреного source checkout того самого PAO tag.
У binary archive немає Dockerfile. Використовуйте
[`runtime/Dockerfile` цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/runtime/Dockerfile):
він задає base image за digest і встановлює `libgcc-s1`. Цей build може
завантажувати base image та пакети з мережі. Він створює нові bytes, які потрібно
окремо перевірити; digest base image не дорівнює ID готового runtime.

Після погодження цієї підготовки, **з кореня перевіреного source checkout**,
зі звичайними правами доступу до локальної VM, виконайте один варіант.
Підставте справжній абсолютний шлях до перевіреного Docker CLI без посилань:

```powershell
$paoDocker = 'REPLACE_WITH_ABSOLUTE_REGULAR_DOCKER_CLI_PATH'
$paoEndpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
& $paoDocker --host $paoEndpoint build --platform linux/amd64 --file .\runtime\Dockerfile --tag pao-runtime:first-secrets .\runtime
if ($LASTEXITCODE -ne 0) { throw 'Runtime build failed; do not approve it.' }
& $paoDocker --host $paoEndpoint image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{json .Config.Volumes}}' pao-runtime:first-secrets
if ($LASTEXITCODE -ne 0) { throw 'Runtime identity unavailable.' }
```

```sh
pao_docker='/REPLACE_WITH_ABSOLUTE_REGULAR_DOCKER_CLI_PATH'
pao_endpoint="unix://$HOME/.docker/desktop/docker.sock"
"$pao_docker" --host "$pao_endpoint" build --platform linux/amd64 --file ./runtime/Dockerfile --tag pao-runtime:first-secrets ./runtime || exit 1
"$pao_docker" --host "$pao_endpoint" image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{json .Config.Volumes}}' pao-runtime:first-secrets || exit 1
```

Запишіть отриманий локальний `.Id` виду `sha256:<64 lowercase hex>`.
У provider використовуйте цей **ID**, а не tag `pao-runtime:first-secrets` і
не registry manifest digest. Перевірте `linux/amd64` та відсутність оголошених
volumes. Сам успішний build або `image inspect` не перевіряє ізоляцію.
Порядок потрібних synthetic перевірок описано в
[container-vm readiness](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/operations/container-vm-readiness.md).

У `reviews/runtime-review.txt` власник фіксує точні PAO/Docker/scanner versions,
Docker CLI hash, image ID, час і результати перевірок: локальна Linux VM,
доступ non-root scanner до приватних входів, read-only target, відсутність мережі,
обмеження output/scratch, завершення та cleanup. Запис має містити реальний
висновок відповідального власника й строк дії, а не лише перелік бажаних властивостей.
Якщо приймання потрібного host/candidate не виконане або перевірка не пройшла,
збережіть `UNAPPROVED` і зупиніться до запуску.

### 4. Виміряйте hashes і заповніть три JSON

Після перевірки виміряйте SHA-256 **розпакованого scanner**, Docker CLI та
завершеного review-файла. Hash архіву Gitleaks не підходить замість hash scanner:

```powershell
(Get-FileHash -LiteralPath 'D:\PAO-first-run\tools\gitleaks\8.30.1\bin\gitleaks' -Algorithm SHA256).Hash.ToLowerInvariant()
(Get-FileHash -LiteralPath $paoDocker -Algorithm SHA256).Hash.ToLowerInvariant()
(Get-FileHash -LiteralPath 'D:\PAO-first-run\reviews\runtime-review.txt' -Algorithm SHA256).Hash.ToLowerInvariant()
```

```sh
sha256sum /home/USER/pao-first-run/tools/gitleaks/8.30.1/bin/gitleaks
sha256sum "$pao_docker"
sha256sum /home/USER/pao-first-run/reviews/runtime-review.txt
```

Нижче — повні мінімальні структури для цього одного профілю. Збережіть їх
у `config/` у UTF-8. **Приклади навмисно невалідні для запуску**: `UNAPPROVED`,
`REPLACE_...` та незаповнені дати не можна замінювати вигаданими значеннями.
У Windows JSON backslashes подвоєні; для Linux замініть усі абсолютні
Windows-шляхи на `/home/USER/pao-first-run/...`, а `manifest_root` — на
`/home/USER/pao-@PAO_VERSION@/adapters`. Шляхи `binary` всередині catalog
залишаються відносними зі знаком `/` на обох ОС.

`config/audit.json`:

```json
{
  "version": "pao.dev/local-audit-config/v2",
  "target": "D:\\PAO-first-run\\synthetic",
  "evidence_base": "D:\\PAO-first-run\\evidence",
  "report_base": "D:\\PAO-first-run\\reports",
  "toolchain_root": "D:\\PAO-first-run\\tools",
  "manifest_root": "D:\\pao-@PAO_VERSION@\\adapters",
  "toolchain_catalog": "D:\\PAO-first-run\\config\\toolchain.catalog.json",
  "docker_base_provider": "D:\\PAO-first-run\\config\\docker-provider.json",
  "docker_scancode_provider": "",
  "rule_pack_root": ""
}
```

`config/toolchain.catalog.json`:

```json
{
  "api_version": "pao.dev/toolchain-catalog/v1",
  "owner": "UNAPPROVED",
  "approved_at": "REPLACE_WITH_ACTUAL_CATALOG_APPROVAL_UTC",
  "expires_at": "REPLACE_WITH_REVIEWED_CATALOG_EXPIRY_UTC",
  "tools": [
    {
      "record": {
        "id": "gitleaks",
        "version": "8.30.1",
        "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SCANNER_HASH",
        "source_license": "MIT",
        "redistribution": "user-installed-only",
        "runtime_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_IMAGE_ID_WITHOUT_PREFIX",
        "runtime_at": "REPLACE_WITH_ACTUAL_RUNTIME_REVIEW_UTC"
      },
      "binary": "gitleaks/8.30.1/bin/gitleaks",
      "provider": "base"
    }
  ]
}
```

`config/docker-provider.json`:

```json
{
  "api_version": "pao.dev/docker-provider/v1alpha1",
  "docker_path": "REPLACE_WITH_ABSOLUTE_REGULAR_DOCKER_CLI_PATH",
  "docker_sha256": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DOCKER_CLI_HASH",
  "runtime_image": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_IMAGE_ID_WITHOUT_PREFIX",
  "runtime_approval": {
    "id": "UNAPPROVED",
    "owner": "UNAPPROVED",
    "evidence_digest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_REVIEW_FILE_HASH",
    "expires_at": "REPLACE_WITH_REVIEWED_RUNTIME_EXPIRY_UTC"
  }
}
```

Заповнюйте поля лише за власними перевіреними даними:

| Поле | Що записати |
| --- | --- |
| Catalog `owner`; provider `runtime_approval.owner/id` | Відповідального власника та ID його фактичного рішення |
| `approved_at`, `runtime_at` | Зафіксований час відповідної завершеної перевірки, UTC RFC3339 (`YYYY-MM-DDTHH:MM:SSZ`) |
| Catalog `expires_at` | Майбутній строк, погоджений власником, не більш як 90 днів від `approved_at` |
| Provider `runtime_approval.expires_at` | Строк саме перевірки runtime; він не поновлюється через новий catalog |
| Catalog `sha256` | Виміряний hash файла `gitleaks`, 64 lowercase hex без префікса |
| Catalog `runtime_sha256`; provider `runtime_image` | Один локальний image ID: без `sha256:` у catalog, з ним у provider |
| Provider `docker_sha256`, `evidence_digest` | Виміряні hashes Docker CLI й завершеного review-файла, з префіксом `sha256:` |

Не підставляйте дату публікації Gitleaks, дату цього посібника чи поточний час
замість часу реальної перевірки. Не подовжуйте строк лише щоб прибрати відмову.
Runtime freshness і catalog approval перевіряються окремо. Повний контракт:
[toolchain-catalog.md цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/toolchain-catalog.md).

### 5. Перегляньте план і підтвердьте синтетичний запуск

Із папки перевіреного пакета PAO, звичайні права:

```powershell
.\pao.exe audit --config 'D:\PAO-first-run\config\audit.json' --profile secrets
```

```sh
./pao audit --config /home/USER/pao-first-run/config/audit.json --profile secrets
```

Preview має показати лише Gitleaks, синтетичну ціль, окремі evidence/report paths,
застосовність і підтримку входів. Код `0` тут означає лише preview.
`PREFLIGHT_REQUIRED` повідомляє, що перевірки інструмента та VM ще попереду.
Якщо JSON або approval невалідні, виправте названу причину за реальними доказами;
не копіюйте чужий готовий config.

Коли власник готовий до цього точного запуску, повторіть команду:

```powershell
.\pao.exe audit --config 'D:\PAO-first-run\config\audit.json' --profile secrets --execute
$paoAuditExit = $LASTEXITCODE
$paoAuditExit
```

```sh
./pao audit --config /home/USER/pao-first-run/config/audit.json --profile secrets --execute
pao_audit_exit=$?
printf '%s\n' "$pao_audit_exit"
```

PAO покаже новий preview і фразу `RUN <audit-id> <plan-digest>`. Введіть
**саме її** в цьому терміналі. Старий RUN, «так», порожній ввід або EOF не
підтверджують запуск. Зміна config/catalog/provider/target потребує нового preview.
Коротке ім'я `--config audit.json` шукається лише у приватному системному
`PAO/config`; наведені абсолютні шляхи прибирають цю неоднозначність.

Після завершення Gitleaks із повністю прочитаним результатом очікується
`REVIEW_REQUIRED` і **код `4`**, навіть коли знахідок немає. Код `4` також
можливий для incomplete execution, тому прочитайте статус, покриття й причини
у `<report_base>/<year>/<audit-id>/06_report/SUMMARY.md`. Для цього профілю
йдеться лише про перевірку файлів Gitleaks, а не всієї Git-історії чи інших
можливостей PAO. Raw output лишається у приватному evidence root.

Збережіть результати першого запуску та перевірте права доступу й завершення
контейнера. Цей посібник не означає, що приймання на чистій Windows/Ubuntu
машині для поточного кандидата вже пройдене. Для інших профілів та усунення
відмов дивіться
[операторську інструкцію цього tag](https://github.com/sSOFTINn/ProjectAuditOrchestrator/blob/@PAO_TAG@/docs/operations/configured-local-audit.md).

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
`verified_empty_declared_ecosystems` окремо позначає підтверджені порожні
оголошення залежностей Go без додавання вигаданого Go-компонента.
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
