# Отчёт по аудиту безопасности — mytonctrl

> Issue: [#1 «🔒 Comprehensive Security Audit Request»](https://github.com/xlabtg/mytonctrl/issues/1)
> Программа: TON Bug Bounty Program (scope: репозиторий `mytonctrl`).
> Принцип отчёта: **никаких ложноположительных срабатываний** — публикуются только уязвимости,
> подтверждённые воспроизводимым PoC в изолированном окружении. Тестирование на mainnet/testnet
> **не проводилось**.

## 1. Краткое резюме

`mytonctrl` — это CLI/демон на Python, который управляет нодой-валидатором TON и работает с
правами `root` (или выделенного оператора). Он хранит и экспортирует чувствительный материал:
приватные ключи кошельков (`.pk`), приватные ключи валидатора (keyring), конфигурацию ноды и
токен Telegram-бота оповещений.

Главный подтверждённый класс уязвимостей — **небезопасные права доступа к файлам и каталогам с
секретами** (CWE-312, CWE-732, CWE-377). При стандартном `umask 022` процесса `root` все эти
файлы создавались с правами `0644` (читаемы всем миром), а каталоги — `0755` (проходимы всем
миром). В результате любой локальный непривилегированный пользователь (или скомпрометированный
сервис с низкими правами) на хосте валидатора мог прочитать приватные ключи и токен бота.

Подтверждено и устранено **5 находок** (1 × Medium, 4 × High). Дополнительно приведены наблюдения
по усилению (hardening), которые не являются эксплуатируемыми в текущей модели угроз, но
рекомендуются как defense-in-depth.

| ID | Уязвимость | Severity | CVSS v3.1 | CWE | Статус |
|----|------------|----------|-----------|-----|--------|
| F-01 | Конфиг-БД `mytoncore.db` (токен бота) доступна на чтение всем | Medium | 5.5 | CWE-312, CWE-732 | Исправлено |
| F-02 | Приватные ключи кошельков `.pk` доступны на чтение всем | High | 7.0 | CWE-312, CWE-732 | Исправлено |
| F-03 | Каталог экспорта keyring валидатора в `/tmp` проходим всем | High | 7.0 | CWE-377, CWE-732 | Исправлено |
| F-04 | Архив бэкапа (все ключи) создаётся доступным на чтение всем | High | 7.3 | CWE-312, CWE-377, CWE-59 | Исправлено |
| F-05 | Авто-бэкапы (все ключи) пишутся в `/tmp` доступными всем | High | 7.0 | CWE-312, CWE-732 | Исправлено |

## 2. Модель угроз

Все находки относятся к нарушению границы привилегий **внутри хоста**: атакующий —
непривилегированный локальный пользователь либо процесс, исполняющийся под другим (не-root) UID на
той же машине, где работает нода-валидатор. Это реалистично, когда:

- на хосте есть учётные записи помимо оператора ноды;
- скомпрометирован какой-либо низкопривилегированный сервис на том же сервере;
- хост является общим/арендованным.

Удалённого (сетевого) вектора в подтверждённых находках нет, поэтому метрика `AV` во всех CVSS —
`Local`, а `PR` — `Low` (требуется любой локальный аккаунт). Это сознательно ограничивает оценку:
мы не завышаем severity.

## 3. Методология

- **Фаза 1. Разведка.** Картирование точек входа (CLI-команды, демон `mytoncore`, инсталлятор,
  Telegram-бот оповещений), механизмов аутентификации, потоков данных для ключей/учётных данных,
  модели исполнения (root-режим `/usr/local/bin` vs user-режим `~/.local/share`).
- **Фаза 2. Статический анализ.** Поиск `os.system`/`subprocess`/`eval`/`exec`, конкатенации SQL,
  захардкоженных секретов, слабой криптографии, небезопасной десериализации, отключённой проверки
  TLS, прав доступа к секретам.
- **Фаза 3. Анализ зависимостей.** Просмотр сторонних библиотек (`requests`, `psutil`, `pynacl`,
  `fastcrc`).
- **Фаза 4. Логический анализ.** Обработка приватных ключей, подпись транзакций, бэкап/восстановление,
  сетевое взаимодействие.

## 4. Подтверждённые находки (с PoC)

Общий PoC, воспроизводящий и проверяющий устранение всех находок класса прав доступа:
[`experiments/poc_perms.py`](experiments/poc_perms.py). Вывод **до** исправления:

```
mytoncore.db (bot token)      : 0o644  world_readable=True
wallet .pk (private key)      : 0o644  world_readable=True
backup dir (keyring export)   : 0o755  world_traversable=True
```

Вывод **после** исправления:

```
mytoncore.db (bot token)      : 0o600  world_readable=False
wallet .pk (private key)      : 0o600  world_readable=False
backup dir (keyring export)   : 0o700  world_traversable=False
```

Каждая находка дополнительно покрыта автотестами-регрессиями в
[`tests/integration/test_security_permissions.py`](tests/integration/test_security_permissions.py)
и [`tests/unit/test_permissions.py`](tests/unit/test_permissions.py).

---

### F-01 — Конфиг-БД `mytoncore.db` доступна на чтение всем (токен Telegram-бота)

- **Severity:** Medium
- **CVSS v3.1:** 5.5 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-732 (Incorrect Permission Assignment)
- **Компонент:** `mypylib/mypylib.py` → `MyPyClass._write_file_atomic` / `write_db` / `lock_file`

**Описание.** Конфигурационная БД (JSON-файл `*.db`) хранит, среди прочего, токен Telegram-бота
оповещений (`BotToken`), идентификаторы чатов и параметры подключения к lite-server/validator-console.
Атомарная запись создавала временный файл обычным `open(..., 'wt')` и затем `os.replace`. При
`umask 022` итоговый файл получал права `0644`.

**Влияние.** Любой локальный пользователь мог прочитать токен бота и выдавать себя за бота
оповещений ноды (рассылка ложных алертов оператору, утечка телеметрии), а также узнать топологию
подключения ноды.

**PoC.** См. блок «BEFORE fix» в `experiments/poc_perms.py` (`mytoncore.db … 0o644 world_readable=True`).
Регрессия: `test_db_written_owner_only`, `test_db_lock_file_not_world_readable`.

**Исправление.** `_write_file_atomic` теперь создаёт временный файл сразу с правами `0o600`
(`os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o600)` + явный `os.chmod` перед `os.replace`), поэтому
окна world-readable не возникает. Lock-файл создаётся с `0o600`.

```python
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)  # mode = 0o600
with os.fdopen(fd, 'wt') as file:
    file.write(text)
os.chmod(tmp_path, mode)
os.replace(tmp_path, path)
```

---

### F-02 — Приватные ключи кошельков `.pk` доступны на чтение всем

- **Severity:** High
- **CVSS v3.1:** 7.0 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CWE:** CWE-312, CWE-732
- **Компонент:** `modules/wallet.py` → `do_import_wallet`, `create_wallet`; каталог `mytoncore/mytoncore.py` → `walletsDir`/`poolsDir`/`contractsDir`

**Описание.** Приватные ключи кошельков хранятся в файлах `<name>.pk` (32 байта ed25519) в каталоге
`wallets/`. При импорте (`do_import_wallet`) файл создавался `open(..., 'wb')` без последующего
`chmod`, а при создании (`create_wallet`) ключ пишет fift-скрипт `new-wallet*.fif`, наследующий
`umask` родительского процесса. Итог — права `0644`. Сам каталог `wallets/` создавался `0755`.

**Влияние.** Чтение `.pk` равнозначно компрометации кошелька: атакующий получает приватный ключ и
может подписывать произвольные транзакции (вывод средств). Поэтому в CVSS выставлены `C:H` (чтение
ключа) и `I:H` (возможность подделки транзакций).

**PoC.** Блок «BEFORE fix» (`wallet .pk … 0o644 world_readable=True`). Регрессия:
`test_imported_wallet_pk_owner_only`, `test_wallet_pool_contract_dirs_owner_only`.

**Исправление.** После записи `.pk` (и при импорте, и при создании) вызывается
`set_secret_file_perms(path)` → `chmod 0o600`. Каталоги `wallets/`, `pools/`, `contracts/`
создаются через `create_secret_dir` с правами `0o700`, что дополнительно блокирует доступ даже на
короткое окно между созданием и `chmod`.

---

### F-03 — Каталог экспорта keyring валидатора в `/tmp` проходим всем

- **Severity:** High
- **CVSS v3.1:** 7.0 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CWE:** CWE-377 (Insecure Temporary File), CWE-732
- **Компонент:** `modules/backups.py` → `create_tmp_ton_dir` / `create_keyring`

**Описание.** При создании бэкапа выполняется `validator-console … exportallprivatekeys <dir>`,
который выгружает приватные ключи валидатора (keyring) в каталог
`/tmp/mytoncore/ton_backup_<ms>/db/keyring`. Каталог создавался `os.makedirs(...)` с правами `0755`
внутри проходимого всем `/tmp`.

**Влияние.** Компрометация приватных ключей валидатора: имперсонация ноды, кража ADNL-идентичности,
потенциальное вредоносное поведение от имени валидатора.

**PoC.** Блок «BEFORE fix» (`backup dir … 0o755 world_traversable=True`). Регрессия:
`test_backup_staging_dir_owner_only` (мокает `validator-console` и проверяет, что staging-каталог
имеет права `0o700`).

**Исправление.** Промежуточный каталог создаётся через `create_secret_dir(dir_name)` (`0o700`) до
того, как в него выгружаются любые секреты; родительский `0o700` гарантирует недоступность keyring
другим пользователям независимо от прав отдельных файлов.

---

### F-04 — Архив бэкапа (полный набор ключей) создаётся доступным на чтение всем

- **Severity:** High
- **CVSS v3.1:** 7.3 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **CWE:** CWE-312, CWE-377, CWE-59 (Link Following)
- **Компонент:** `mytonctrl/scripts/create_backup.sh`

**Описание.** Скрипт собирал во временный каталог с **фиксированным предсказуемым именем**
`/tmp/mytoncore/backupv2` файлы `config.json`, `keyring` (ключи валидатора), `keys/` и каталог
`mytoncore/` (содержащий `mytoncore.db` и приватные ключи кошельков `.pk`), после чего паковал их в
`*.tar.gz`. Скрипт не задавал `umask`, поэтому архив и промежуточные файлы получали права `0644`.
Фиксированное имя в `/tmp` дополнительно подвержено атакам через предварительное создание/симлинк
(CWE-59), а итоговый архив агрегирует **все** секреты ноды в одном world-readable файле.

**Влияние.** Самая критичная точка: одно чтение `*.tar.gz` (или промежуточного каталога) даёт
атакующему полный набор секретов ноды — ключи валидатора, ключи кошельков и токен бота. Метрика
`A:L` отражает риск порчи/подмены содержимого через предсказуемый путь.

**PoC.** Сквозной тест-регрессия `test_create_backup_script_archive_owner_only` запускает реальный
`create_backup.sh` на синтетических данных и проверяет, что итоговый архив имеет права `0o600`.

**Исправление.** В начало скрипта добавлен `umask 077`; фиксированный путь заменён на
`mktemp -d` (непредсказуемое имя, права `0o700`); итоговый архив принудительно ограничивается
`chmod 600` перед сменой владельца; переменные пути закавычены.

```sh
umask 077
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mytoncore_backup.XXXXXXXX") || exit 1
...
tar -zcf "$dest" -C "$tmp_dir" .
chmod 600 "$dest"
chown "$user:$user" "$dest"
```

---

### F-05 — Авто-бэкапы (полный набор ключей) пишутся в `/tmp` доступными всем

- **Severity:** High
- **CVSS v3.1:** 7.0 — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **CWE:** CWE-312, CWE-732
- **Компонент:** `mytoncore/mytoncore.py` → `make_backup`; настройка `auto_backup_path`

**Описание.** При включённом `auto_backup` нода на каждых выборах создаёт архив бэкапа в
`self.tempDir + "/auto_backups"` (по умолчанию `/tmp/mytoncore/auto_backups`), каталог создавался
`os.makedirs(..., exist_ok=True)` с правами `0755`. Архивы (см. F-04) хранятся там до 7 дней.

**Влияние.** То же, что и F-04, но автоматически и периодически: полный набор ключей ноды
оказывается в world-traversable каталоге `/tmp` на продолжительное время.

**PoC.** Регрессия `test_auto_backup_dir_owner_only` (включает `auto_backup`, мокает реальную
упаковку и проверяет права `0o700` на каталоге назначения).

**Исправление.** Каталог авто-бэкапов создаётся через `create_secret_dir(backups_dir)` (`0o700`);
в сочетании с F-04 сами архивы имеют права `0o600`.

## 5. Новые вспомогательные функции

В `mypylib/mypylib.py` добавлены переиспользуемые помощники (покрыты unit-тестами):

```python
SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700

def set_secret_file_perms(path, mode=SECRET_FILE_MODE): ...  # best-effort chmod секрета
def create_secret_dir(path, mode=SECRET_DIR_MODE): ...       # makedirs + принудительный chmod
```

`set_secret_file_perms` намеренно «best-effort» (глотает `OSError`), чтобы не ломать работу на ФС,
не поддерживающих `chmod` (некоторые сетевые/FAT-разделы).

## 6. Проверено и НЕ подтверждено (во избежание ложноположительных)

Следующие классы из scope были проверены и **не дали** эксплуатируемых находок:

- **RCE / command injection.** Все вызовы внешних программ (`mytoncore/clients.py`, `run_as_root`,
  `BackupModule.run_*`) используют list-форму `subprocess` (`shell=False`) — инъекция через shell
  невозможна. Единственный `shell=True` (`mytoncore/telemetry.py:198`) — это захардкоженная строка
  `df -h /var/ton-work/ | sed … | awk …` без пользовательского ввода. Вызовы `os.system` используют
  либо константы (`mypyconsole.py: "clear"`), либо внутренние **константные** имена сервисов
  (`get_service_status("mytoncore"/"validator"/"btc_teleport")`), не управляемые атакующим.
- **Insecure deserialization.** В коде нет `pickle`/`marshal`/`yaml.load` — используется только
  `json.load`/`json.loads`.
- **Отключённая проверка TLS.** В кодовой базе нет `verify=False`.
- **SQL injection.** SQL-слой отсутствует — конфигурация хранится в JSON.
- **`eval`/`exec`.** Не используются.

## 7. Дополнительные наблюдения (рекомендации по усилению)

Эти пункты **не** являются подтверждёнными эксплуатируемыми уязвимостями в текущей модели угроз
(нет PoC), поэтому вынесены отдельно. Рекомендуются как defense-in-depth:

- **`os.system` со строковой интерполяцией.** `mypylib.get_service_status` и
  `mytoninstaller/settings.py` (`DownloadDump`) формируют команды через f-строки. Сейчас входные
  данные константны/конфигурационны и не управляются локальным атакующим, но переход на list-форму
  `subprocess` исключил бы риск регрессии, если в будущем туда попадёт внешний ввод.
- **World-writable каталоги в инсталляторе.** `mytoninstaller/settings.py` (`chmod o+w`/`o+wx`) и
  `modules/general.py` (`mkdir -m 777 /var/ton-work/tmp`) создают каталоги, доступные на запись
  всем. Рекомендуется заменить на выдачу прав конкретному пользователю через `chown`/группу. Эти
  операции выполняются инсталлятором под `root` и требуют отдельной валидации в стенде с TON-бинарями.

## 8. Затронутые файлы (исправления в этом PR)

- `mypylib/mypylib.py` — `_write_file_atomic` (db `0o600`), lock-файл `0o600`, помощники
  `set_secret_file_perms`/`create_secret_dir`.
- `modules/wallet.py` — `chmod 0o600` для `.pk` при импорте и создании.
- `modules/backups.py` — staging-каталог экспорта keyring `0o700`.
- `mytoncore/mytoncore.py` — каталоги `wallets/`/`pools/`/`contracts/` и каталог авто-бэкапов `0o700`.
- `mytonctrl/scripts/create_backup.sh` — `umask 077`, `mktemp -d`, `chmod 600` архива.
- `tests/unit/test_permissions.py`, `tests/integration/test_security_permissions.py` — регрессии.
- `experiments/poc_perms.py` — PoC (before/after).

## 9. Ссылки

- CWE-312: https://cwe.mitre.org/data/definitions/312.html
- CWE-377: https://cwe.mitre.org/data/definitions/377.html
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
- CWE-59: https://cwe.mitre.org/data/definitions/59.html
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- TON Bug Bounty Program: https://github.com/ton-blockchain/bug-bounty
