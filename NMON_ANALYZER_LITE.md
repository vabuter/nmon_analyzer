# nmon_analyzer.py — краткая инструкция (для сред с малым контекстом)

`nmon_analyzer.py` — однофайловый анализатор файлов nmon (Linux) для RCA узлов и кластеров Apache Ignite 2.x через
shell (Python ≥ 3.12, только stdlib). Все опции команды — `<команда> --help`; индекс «вопрос → команда» —
`$A questions`; полное руководство — `NMON_ANALYZER.md`.

## 1. Запуск и входные данные

```bash
A='python3 /path/to/nmon_analyzer.py'  # полный путь к скрипту, задать один раз
D=/path/to/nmon; F=$D/node01.nmon      # каталог кластера; файл одного хоста
S=/path/to/workdir                     # ваш рабочий/временный каталог для файлов вывода (-o)
```

- `$A <команда> [опции] <пути>`. Пути: файл `.nmon` (и `.gz`), каталог (рекурсивно) или маска в кавычках. Хост — по
  `AAA,host`; файлы одного хоста склеиваются в один ряд (`--no-merge` — каждый файл отдельным хостом).
- Каждая команда заново разбирает все переданные файлы (~1 с на 10 MB). Все, кроме `cluster` и `questions`, печатают
  **отдельный отчёт на каждый хост** (заголовок `<отчёт>  [host]`): `at`/`java`/`report` по `$D` — N отчётов подряд.
  Один хост — его файл или `--host '^node01$'`.
- Окно `--from/--to/--around` принимают все команды, кроме `questions`; средние, пики и TOP тогда — по окну.
- Файлы `.nmon` сами не читайте (`cat`, `head`, `grep`): это мегабайты сырых строк. Значения — `export`, конфигурация
  (lscpu, meminfo, df, ifconfig) — `bbbp --block REGEX` или `bbbp --grep=REGEX`.
- `--format` не меняйте: `text` (по умолчанию) — самый короткий.

## 2. Как держать вывод маленьким (обязательно)

Объём: `health --no-info` — сотни токенов на хост; `health`, `info`, `check`, `at`, `java`, подсистемные команды —
1–3 тыс. на хост; `report` — несколько тысяч на хост; `cluster` по нескольким узлам и `metrics` — больше 10 тыс.;
`timeline` без окна и `--step` по суточному файлу — десятки тысяч.

- `info`/`check` по каталогу — только через `grep` из рецепта. Тяжёлое (`health` по каталогу, `cluster`, `report`) —
  **один раз** в файл `-o $S/x.txt`, дальше только `grep`/`sed` по файлу: `grep -n '^--- ' $S/x.txt` — оглавление
  (блок начинается строкой `--- <название> ---`), `sed -n '/^--- Выбросы/,/^--- /p' $S/x.txt` — один блок. Ту же
  команду повторно не запускайте. `cluster` с `--from/--to` и `--metrics` короче.
- «На каких узлах есть X» — `grep` кода по сохранённому `health` всех хостов; JVM жива / PID тот же — нет `JAVA_`
  там же (при TOP в `info`); `java` — только ради RSS/threads. Сравнение хостов — блоки `cluster` («Метрики по
  хостам», «Выбросы»), а не подсистемная команда на каждом хосте.
- `timeline` — только с окном, ≤ 6 метриками `--metrics` (значение берите по заголовку колонки; при сомнении —
  второй вызов) и при длинном окне `--step 5m --agg max` (max сохраняет пики; провал ищите с `--agg min`). `--limit`
  обрезает ряд с начала — не замена окну. Соседи в момент T — один вызов `timeline $D --around T --window 5m --step 1m --metrics …` (блок на хост), а не `at` по `$D`.
- Широкие таблицы (`at`, `check`, «Метрики по хостам» в `cluster`) — `| cut -c1-200`.
- Сокращение: `--no-info`, `--min-severity WARN`, `--top N`, `--limit N`, `at --window-snaps 0|1`. `metrics` — только
  с фильтром: `metrics $F | grep -E '^(disk|net)\.'`.
- Добавляйте `2>&1`: в stderr — `WARN:`, `ERROR:`, строка `окно времени: A .. B`, `записано: FILE`.

Рецепт (пути — до `--metrics`; коды 1/2 — результат, не сбой):

```bash
$A info $D | grep -E '^(host|interval|начало|конец|CPU \(|memtotal|TOP|UARG|разрывов)'
$A check $D --min-severity WARN 2>&1 | grep -E '\]$|^данные|^(WARN|CRIT) '
$A health $D -o $S/h.txt; grep -E '\]$|^\[(CRIT|WARN)\]' $S/h.txt   # строка на замечание (INFO — тоже в файле)
grep -A1 -E '\]$|^\[(CRIT|WARN)\] JAVA_' $S/h.txt                    # + строка «факты:»
$A cluster $D -o $S/cl.txt; grep -n '^--- ' $S/cl.txt                # если хостов > 1
grep -A2 -E '^\[(CRIT|WARN)\]' $S/cl.txt | cut -c1-250                # замечания уровня кластера
sed -n '/^--- Покрытие/,/^--- Полоса/p' $S/cl.txt   # начало, конец, разрывов по хостам; общее окно
$A health $F --from 'YYYY-MM-DD HH:MM' --to 'YYYY-MM-DD HH:MM' --no-info 2>&1
$A at --time 'YYYY-MM-DD HH:MM:SS' $F --window-snaps 1 --top 10 2>&1 | cut -c1-200
$A timeline $F --around 'YYYY-MM-DD HH:MM' --window 30m --step 1m --agg max --metrics cpu.busy cpu.wait proc.blocked disk.write net.read top.java.cpu
$A top $F --from 'YYYY-MM-DD HH:MM' --to 'YYYY-MM-DD HH:MM' --sort rss --top 5
$A compare $F --a HH:MM-HH:MM --b HH:MM-HH:MM
```

## 3. Порядок разбора

1. `info` (хосты, период, interval, TOP/UARG, разрывы) → `check` (вердикт `данные : пригодны` / `пригодны с
   оговорками` / `непригодны`) → `health $D` → `cluster` (хостов > 1) → `report`/подсистемы по 1–2 хостам.
2. Момент из лога: `health --from/--to` (или `--around`) → `at --time` → `timeline --around` → `compare` («до»
   против «во время»). Логи в другой зоне — `--tz-shift` (§6).
3. Команда подсистемы — та, которую называет `подсказка:`.
4. Замечание: `[SEV] CODE @ время: метрика = значение (порог …)`, под ним `факты:` (числа: границы эпизода, max/avg,
   `Runnable max N при K CPU`, топ-процесс) и `подсказка:` (что это значит для Ignite и что проверить). Пороги знать не
   нужно; замечание можно цитировать в RCA как есть.
5. Стоп, когда симптом из лога объяснён замечанием в окне и подтверждён вторым источником (`at`/`timeline`/`top`),
   либо в окне нет CRIT/WARN при пригодных данных: тогда «на уровне ОС nmon аномалий не показывает» + чего nmon не видит
   (§12) и какие данные запросить. Причину подтверждайте логами Ignite/GC и dmesg/journal (`Checkpoint
   started/finished`, `Too many dirty pages`, `Long JVM pause`, `Node FAILED`/`Node LEFT`, `Local node SEGMENTED`,
   PME/exchange, rebalance).
6. **Ответ — обязательные строки** (их чаще всего пропускают):
   - Первая фраза прямо отвечает на вопрос (да/нет, что и где).
   - Факты: хост, время, `КОД SEV`, метрика = значение (порог); каждое число — с кодом правила, из `факты:` и из
     вывода по тому же набору файлов.
   - `Фон:` значение до / во время / после эпизода числом (busy, трафик, запись); у выброса — «вне эпизода p95 хоста
     как у остальных».
   - `Исключено:` по **отсутствующим** правилам — ОС не перезагружалась (нет `BOOT_RECENT`), хост не замирал (нет
     `NMON_GAP`), JVM та же (нет `JAVA_RESTART`/`JAVA_GONE`), пропал весь bond, а не слейв (нет `NET_BOND_MEMBER`),
     данные не кончились раньше (нет `CLUSTER_COVERAGE`).
   - Перезапуск/гибель JVM: простой (`между`), CPU busy узла в простое, RSS и threads старого и нового PID (блоки
     `java[PID]` в `java $F` — не обрезайте); `JAVA_RSS_GROWTH` у нового PID — прогрев, не утечка: так и напишите.
   - Код возврата: «0/1/2 — результат (нет / WARN / CRIT), не сбой; 3 — сбой (`ERROR` в stderr)».
   - «Можно ли доверять данным»: по каждому хосту вердикт `check`, `interval` и `разрывов` (`info $D | grep`; `check`
     их не печатает), начало/конец и общее окно (`cluster`: «Покрытие данными», «Окна»); разное начало — старт nmon;
     коды `DATA_QUALITY`/`NMON_GAP`; перекрёстные проверки сходятся, если нет WARN «перекрёстная проверка не
     пройдена»; итог «N из M пригодны».
   - Условие из `подсказка:` — в вывод дословно (`COMMIT_LIMIT`: проверить `sysctl vm.overcommit_memory`; значение —
     на старте nmon).
   - Чего nmon не видит (§12) и что запросить; причина без подтверждения логами — гипотеза.

## 4. Команды

| Команда | Вопрос | Ключевые опции; блоки вывода |
|---|---|---|
| `info` | хост, период, interval, CPU, RAM, TOP/UARG, разрывы, запуски nmon | — |
| `check` | можно ли доверять данным | `--min-severity WARN`; Вердикт, Замечания, Перекрёстные проверки |
| `health` | что не так по порогам | `--from/--to`, `--no-info`, `--thr` |
| `report` | общая картина хоста | `--host`, `--no-info` |
| `cluster` | узлы между собой | `--sort метрика:агрегат` (`net.read:mean`), `--metrics` (для синхронных выбросов); Покрытие данными, Окна, Метрики по хостам, Выбросы среди хостов, Синхронные выбросы, Кластерный таймлайн, Замечания уровня кластера, Health по хостам (сводка CRIT/WARN, в конце) |
| `at` | что было в момент T | `--time T` (без неё — пик CPU), `--window-snaps K` (2), `--metrics`, `--top`; Снимок, метрики вокруг, TOP, Диски, Сеть, Ядра |
| `timeline` | ряд метрик | `--metrics`, `--step`, `--agg mean\|max\|min\|sum\|last` (mean), `--limit`; колонки — в порядке `--metrics` |
| `compare` | «до» против «во время» | `--a`, `--b` (оба обязательны), `--metrics`, `--top` |
| `events` | аномалии во времени | `--metrics`, `--z` (4), `--limit` |
| `correlate` | связь метрик | `--target M`, `--limit` |
| `cpu`; `cores` | CPU, эпизоды насыщения, ядра; каждое CPU, NUMA | `cores --sort avg\|p95\|max\|sys\|wait` |
| `proc` | Runnable, Blocked (D-state) | — |
| `mem`; `vm` | память, минимум avail; swap, reclaim, faults, dirty | — |
| `disk`; `diskmap` | busy, KB/s, IOPS, размер IO, пики; диск под WAL/persistence, тип диска | `--dev REGEX` (и имя LV), `--all` |
| `fs` | заполненность ФС, рост | `--mount REGEX` |
| `net` | интерфейсы, bond, провалы, ошибки | `--iface REGEX`, `--all`, `--link-mbit N` |
| `top` | процессы: CPU, RSS, потоки, смена PID | `--cmd REGEX`, `--pid N`, `--by-cmd`, `--sort cpu\|rss\|threads\|majflt\|…` |
| `java` | JVM: CPU, RSS, потоки, перезапуски, соседи | `--top`; java[PID] (впервые, последний раз, RSS и threads начало/max/конец), Перезапуски java (смена PID; нет блока — смены PID не было), Другие процессы |
| `uarg` | флаги JVM: Xmx, GC, MaxDirectMemorySize (только nmon с `-T`) | `--cmd REGEX`, `--full` |
| `export`; `bbbp` | значения; сырой lscpu, meminfo, df, ifconfig | `--metrics` или `--section X --columns REGEX`; `--block REGEX`, `--grep=REGEX` |
| `metrics`; `sections` | имена метрик; секции и колонки | только с `\| grep` |

`--dev`/`--mount`/`--iface`/`--columns` — regex, полное совпадение; `top --cmd`/`uarg --cmd` — подстрока.

## 5. Общие опции

| Опция | Смысл |
|---|---|
| `--host REGEX` | **подстрока**: `node1` выберет и `node10`; якорьте `'^node1$'`; можно повторять |
| `--from T --to T`; `--around T --window D` | окно; D — **полуширина** (T ± D, по умолчанию 10m); `--around` перекрывает `--from/--to` |
| `--tz-shift=±D` | сдвиг меток nmon (`-3h`, `+02:00`); отрицательное — только через `=` |
| `--no-info`, `--min-severity CRIT\|WARN\|INFO` | скрывают только вывод; итог и код возврата — по всем («показано N из M») |
| `--thr CODE=WARN[,CRIT]` | свой порог правила (можно несколько; для ролей без persistence можно ослабить) |
| `--link-mbit N` | скорость **одного** порта, Mbit/s; без неё `NET_LINK_UTIL` не считается |
| `--skip-first` | убрать первый снимок (T0001) файла/запуска, и в `at`/`timeline`/`export` |
| `-o FILE`, `--top N`, `-v` | вывод в файл; строк/пиков; ход разбора в stderr |

## 6. Время и окна

- Форматы T: `HH:MM[:SS]`, `YYYY-MM-DD HH:MM[:SS]`, `YYYY-MM-DDTHH:MM[:SS]`, `DD-MON-YYYY HH:MM[:SS]`, `YYYY-MM-DD`
  (`--from D --to D` — весь день); длительности `90s`, `10m`, `2h`, `1d`. Метку из лога вставляйте как есть
  (дробные секунды и `[ ]` отбрасываются); смещение зоны (`Z`, `+03:00`) — ERROR: уберите его.
- Время без даты получает дату самого раннего снимка выбранных хостов (переход через полночь учтён; `--to` без даты —
  на дату `--from`); данные длиннее суток → `WARN … взята дата …`: указывайте дату (из `info`). Сверяйте фактическое
  окно по stderr `окно времени: A .. B`.
- nmon пишет **локальное время хоста без зоны**. nmon в UTC+3, логи в UTC → `--tz-shift=-3h`; после сдвига
  `--from/--to/--time` — во времени логов.
- `--time` есть только у `at`; `compare --a 'HH:MM-HH:MM'`, с датами — `'YYYY-MM-DD HH:MM..YYYY-MM-DD HH:MM'`.
- Окно без снимков у всех хостов — ERROR (код 3) с периодами данных; только у части — WARN.

## 7. Ловушки CLI и коды возврата

- Пути — **до** `--metrics`/`--columns`: эти опции забирают следующие слова; путь с опечаткой станет «неизвестной
  метрикой» (`WARN:`, метрика пропущена), без путей — ошибка usage (код 3).
- Значение, начинающееся с `-`, — через `=`: `--tz-shift=-3h`, `--grep=-x` (иначе ошибка usage).
- Коды `health`/`report`/`cluster`: 0 — нет WARN/CRIT, 1 — есть WARN (CRIT нет), 2 — есть CRIT. Это **результат:
  вывод полный и верный, не сбой, не повод перезапускать**. 3 — ошибка (`ERROR: …` или `usage … error:` в stderr).
  Остальные команды, включая `check`, при успехе возвращают 0 — вердикт `check` читайте в тексте.
- В конвейере `$?` — код `grep`; код скрипта — `${PIPESTATUS[0]}` или запуск с `-o`.

## 8. Метрики (`timeline`, `events`, `correlate`, `compare`, `export`, `at`/`cluster --metrics`)

| Группа | Имена | Единица |
|---|---|---|
| CPU | `cpu.busy` (= user + sys, без steal), `cpu.user`, `cpu.sys`, `cpu.wait`, `cpu.idle`, `cpu.steal`, `cpu.core_max` | % всех CPU |
| PROC | `proc.runq`, `proc.blocked` (мгновенные), `proc.pswitch` | шт.; /s |
| MEM | `mem.free`, `mem.cached`, `mem.used`, `mem.avail`, `mem.avail_cal` (≈ MemAvailable ядра — её и смотрите), `mem.swap_used` | MB |
| VM | `vm.pgmajfault` (/s); `vm.pswpin`, `vm.pswpout`, `vm.pageoutrun` (за интервал); `vm.nr_dirty` (MB) | |
| DISK | `disk.busy_max` (%), `disk.read`, `disk.write` (KB/s), `disk.iops`, `disk.<dev>.busy\|read\|write\|iops` | |
| NET | `net.read`, `net.write` (KB/s), `net.rx_size`, `net.tx_size` (B/пакет), `net.<if>.read\|write` | |
| FS | `fs.<mount>.pct` | % |
| TOP | `top.java.cpu`, `top.java.sys` (% одного ядра), `top.java.rss` (MB), `top.java.threads`, `top.<cmd>.cpu\|rss\|threads` (по префиксу имени), `top.pid<PID>.cpu`, `top.kswapd.cpu` | |
| RAW | `raw.<SECTION>.<column>` | как в секции |

Единицы двоичные: GB = MB/1024 (не /1000). Значения в GB берите из текста `java`/`mem`/`top`, не пересчитывайте.
Прочие имена — `metrics $F | grep`.

## 9. Правила health

CRIT/WARN — превышение порога; INFO — контекст, **не причина** (без подтверждения до INFO понижаются `MEM_FREE_LOW`,
`KSWAPD_ACTIVE`, `BLOCKED_*`, `CPU_SYS_SHARE`, `JAVA_SYS_SHARE`, `RUNQ_RUN` при простаивающем CPU). `_RUN` — самый
длинный эпизод (≥ 2 снимков подряд; в `факты:` — границы, max/avg); без суффикса — p95/avg/max за период или окно.
Время замечания — пик или начало эпизода.

- **Данные**: `NMON_GAP` — разрыв снимков **внутри** запуска nmon (WARN ≥ 1.5×, CRIT ≥ 5× interval). Внутри запуска
  nmon сам не останавливается: хост/ВМ был заморожен или перегружен — это улика (при «Long JVM pause» — пауза всего
  хоста, а не только GC). `NMON_COVERAGE_GAP` — разрыв **между** файлами/запусками: nmon не работал, это не заморозка.
  `BOOT_RECENT` — недавняя перезагрузка ОС или перезагрузка во время наблюдения (нет его — ОС не перезагружалась);
  `DATA_QUALITY` — проблемы разбора (детали — `check`); `NMON_SHORT`/`WINDOW_SHORT` — мало данных; `NMON_FIRST_ONLY` —
  в окне только T0001: расширьте окно.
- **CPU**: `CPU_SATURATION`/`_RUN` — высокий busy; `RUNQ_HIGH`/`RUNQ_RUN` — Runnable больше числа CPU (потоки
  discovery/communication ждут CPU); `CPU_STEAL` — гипервизор отбирает CPU (таймауты failure detection);
  `CPU_HOT_CORE`/`_RUN` — ядро > 90 % при общей < 50 %: однопоточное узкое место или прерывания; `CPU_WAIT`/
  `CPU_WAIT_PEAK` — iowait; `CPU_SYS_SHARE`.
- **I/O**: `DISK_BUSY`/`_SUSTAINED`/`_RUN` — util физического диска; `IO_STALL` — Blocked ≥ 5, iowait ≥ 5 % и диск
  ≥ 90 % одновременно: потоки стоят на диске; `BLOCKED_HIGH`/`_RUN` — D-state; `DISK_LATENCY` — только при DISK*SERV;
  INFO: `DISK_SMALL_IO` (fsync-профиль), `CHECKPOINT_PERIOD` (период 135–225 с ≈ checkpointFrequency 180 с).
- **Память**: `MEM_AVAIL_LOW` — главное правило; `MEM_FREE_LOW`/`KSWAPD_ACTIVE` значимы только на WARN/CRIT;
  `MAJFAULT_HIGH` — по `vm.pgmajfault`; `SWAP_USED`/`SWAP_ACTIVITY` — swap для Ignite недопустим (паузы JVM);
  `NO_SWAP` (INFO: swap не настроен; скрыт `--no-info`); `MEM_GROWTH` — тренд к исчерпанию; `COMMIT_LIMIT` — значим
  только при `vm.overcommit_memory=2` (ENOMEM: `unable to create native thread`, отказ выделения off-heap): проверить
  `sysctl vm.overcommit_memory`, значение — на старте nmon; `OVERCOMMIT`; `THP_ACTIVE`/`THP_COMPACTION` — всплески
  sys, задержки аллокаций.
- **ФС**: `FS_FULL` (в конце периода; при нехватке места Ignite останавливает узел), `FS_GROWTH` (часов до 100 %).
- **Сеть**: `NET_DROP` — провал до остаточного служебного трафика (типичная изоляция узла; `NET_ZERO` её не видит);
  `NET_ZERO` — трафик в ноль; `NET_BOND_MEMBER` — отказ слейва при живом bond или смена активного слейва. `NET_DROP`
  на bond **без** `NET_BOND_MEMBER` — пропал весь bond (линк/свитч/изоляция), а не один слейв. `NET_LINK_UTIL` — нужен
  `--link-mbit`; `NET_ERRORS` — накоплены с загрузки ОС, момент неизвестен.
- **JVM**: `JAVA_RESTART` — смена PID основного JVM (CRIT: перезапуск **JVM**, не ОС — ОС смотрите по `BOOT_RECENT`;
  в `факты:` — простой и RSS нового; малый RSS — холодный старт). `JAVA_GONE` — основной JVM исчез до конца данных,
  нового PID нет: JVM остановилась и не поднималась (это **не** перезапуск); nmon при этом пишет дальше. `JAVA_START` —
  стартовала во время записи; `JAVA_ABSENT` — пропадал из TOP подряд (завис без CPU или остановлен); `JAVA_CPU_DROP` —
  провал CPU JVM (пауза GC/safepoint, блокировка на I/O); `JAVA_RSS`/`_GROWTH` — анонимная RSS близко к RAM / рост
  (у нового PID после `JAVA_RESTART` — прогрев); `JAVA_THREADS`/`_GROWTH` — соединения, пулы, утечка потоков;
  `JAVA_SYS_SHARE`.
- **Кластер**: `CLUSTER_OUTLIER` — хост отличается от медианы (≥ 4 хостов); `CLUSTER_SYNC` — синхронно у многих
  (`метрика↑` всплеск/плато, `метрика↓` провал; `×значение/фон` — кратность к фону, не абсолют); `CLUSTER_COVERAGE` —
  данные хоста кончились раньше: остановился nmon или упал узел/ОС. При гибели только JVM его нет — там `JAVA_GONE`
  и `NET_DROP`.

Окно меняет правила: с `--from/--to` доли и перцентили считаются по окну (правило может вырасти с INFO до WARN), а
`*_RUN` не печатается, если то же правило без `_RUN` (`CPU_SATURATION`, `RUNQ_HIGH`, `DISK_BUSY`, `BLOCKED_HIGH`,
`CPU_HOT_CORE`) уже дало тот же или более высокий уровень. Границы, max/avg эпизода берите из `факты:` `*_RUN` в
`health` по всему файлу. Без окна на суточном файле, наоборот, правила без `_RUN` теряют 10-минутный инцидент.
Жизненный цикл JVM — по полному ряду.

## 10. Интерпретация: если X — значит Y, а не Z

- Метка снимка — **конец** интервала, значения — средние за интервал: событие HH:52:30 — в снимке HH:53 (`at --time`
  сам берёт нужный снимок). Короче интервала (GC-пауза, fsync-шторм) — усредняется: не видно ≠ не было.
- Первая строка `timeline`/`at`/`export` по файлу — T0001 (1–2 с, без TOP): не пик (`--skip-first`).
- Разрыв `NMON_GAP`: значений внутри нет, ничего «в разрыве» не приводите (`at` печатает «ВНИМАНИЕ»); первый снимок
  после разрыва усреднён за весь разрыв — не цитируйте его как «после». JVM та же — один PID java до и после.
- Обрезанная последняя строка / неполный последний снимок (`check`: «…обрезана: nmon ещё писал файл или узел упал»):
  затронут только этот снимок. Конец данных как у соседей («Покрытие данными»), java в TOP до конца, нет
  `CLUSTER_COVERAGE` → «узел не падал: файл скопирован во время записи; данные пригодны с оговорками». Иначе
  падение узла или nmon не исключено — проверьте dmesg/journal и логи.
- Разное «начало» у хостов — время старта nmon. Общее окно всех хостов — блок «Окна» в `cluster`.
- memfree ≈ 0 — норма Linux (page cache), если `mem.avail_cal` высокий и `MEM_FREE_LOW` — INFO. Нули `allocstall`,
  `pgscan_*`, `pgsteal_*` на современных ядрах — **не** «reclaim не было»: признаки reclaim — `vm.pageoutrun` > 0,
  kswapd* в TOP, падение `mem.cached`, рост `vm.pgmajfault`; прямой reclaim на ядрах ≥ 4.10 nmon не видит.
  `MEM_FREE_LOW` на WARN/CRIT вместе с `MEM_AVAIL_LOW` — подтверждённое давление, а не норма.
- TOP `%CPU` — % **одного ядра** (800 % = 8 ядер; на 64 CPU — 12.5 % машины). В TOP — только процессы с заметным CPU
  и со второго снимка: нет в снимке или `top.<cmd>.cpu` = 0 ≠ не работал. PID `pid@HH:MM` — процесс после
  перезагрузки ОС.
- TOP `MajorFault`/`top.java.majflt` на порядки выше системных (faults после повтора) — не чтения с диска; реальные —
  только `vm.pgmajfault`.
- `Sys%` = system + irq + softirq: сеть поднимает sys. Средний busy скрывает ядро на 100 % (`CPU_HOT_CORE`, `cpu` блок
  «Ядра»; счётчики там — число **снимков**, не ядер). Горячее ядро с sys ≫ user — сетевые прерывания (IRQ affinity,
  RSS/RPS), с user — поток приложения. iowait при загруженном CPU занижен; steal > 0 — только ВМ.
- Runnable/Blocked — мгновенные; их max — в `факты:` правил `RUNQ_*`/`BLOCKED_*` и в `proc`, а не в пиках busy `cpu`.
- `svc≈ms` — грубая оценка, **не** await; busy 100 % на NVMe — ещё не предел (смотрите IOPS, размер IO, iowait,
  Blocked). Тип диска — `diskmap` (HDD > 5 ms, SSD/NVMe < 1 ms). `disk.*` — только физические диски; разделы и dm-*
  не складывайте. Размер IO 4–8 KB при высоком busy — мелкие синхронные записи (WAL fsync, checkpoint); 8–32 KB —
  смешанный профиль, тип записи не утверждайте; ≥ 64 KB — последовательные (архив WAL, снапшот, бэкап).
- `net.*` — основные интерфейсы без lo, слейвов, VLAN: bond уже включает слейвы — не складывайте. Молчание резервного
  слейва active-backup — норма. Пакет 100–500 B — RPC; ~MTU (jumbo — KB) — массовая передача (rebalance, снапшот);
  смотрите в пиках (`B/pkt в пиках` в `net`, `net.tx_size` у отдающих, `net.rx_size` у принимающих).
- Выброс `:max` в `cluster` — обычно эпизод, а не уровень: время, границы и коды — из `health` хоста (`*_RUN`,
  `IO_STALL` в `факты:`), их и цитируйте; p95 хоста сравните с остальными («Метрики по хостам»). `disk.read`↑ сразу
  после давления на память — дочитывание page cache, не проблема диска.
- Счётчики «с загрузки ОС» (ошибки NIC, `/proc/diskstats`) накоплены до старта nmon — к инциденту не приписывать. BBBP
  (meminfo, df, ifconfig) — один снимок на старте.
- Нет замечания ≠ всё хорошо, если нет данных: `TOP … нет` (nmon без `-t`) — нет JAVA_*; `UARG … нет` (без `-T`) — нет
  флагов JVM и командных строк (процесс известен только по имени); без `--link-mbit` — нет `NET_LINK_UTIL`.
- `correlate`: судите по `r Δ`, не по `r`; корреляция ≠ причинность. `events` — короткие всплески; плато — `*_RUN`.
- RSS JVM = heap + off-heap регионы + checkpoint buffer + metaspace + стеки. Рост после старта до суммы регионов —
  прогрев (норма), рост после плато — утечка. `top.java.rss`/`threads` — по основным JVM, `top.java.cpu` — по всем java.
- `cluster`: «первый хост» указан, только если опередил других почти на интервал; порядок событий между узлами надёжен
  лишь при синхронных часах. `CLUSTER_SYNC` `net.*↑`: Σtx ≈ Σrx — обмен внутри набора (rebalance), rx ≪ tx — трафик
  наружу (клиенты, узлы без nmon); объём ≥ 1 GB — не сообщения PME. `net.write↑` вместе с `disk.write↓`/
  `top.java.cpu↓` у всех хостов — обычно смена профиля нагрузки (массовая отдача), а не остановка узлов;
  читайте `подсказка:`.

## 11. Сигнатуры инцидентов Ignite

| Инцидент | Признаки в nmon | Команды; что сообщить |
|---|---|---|
| Checkpoint, write throttling, «тормозит каждые N минут» | регулярные пики `disk.write` (`CHECKPOINT_PERIOD`; при interval 60 с цикл 180 с на пределе — смотрите пики `disk`); в пиках `disk.busy_max` ≈ 100 %, `proc.blocked`↑, `cpu.wait`↑, `top.java.cpu`↓ (`IO_STALL`, `BLOCKED_*`, `DISK_BUSY_RUN`); мелкий IO — `DISK_SMALL_IO` | `disk`, `diskmap` (WAL, persistence и архив на одном диске?); метрики `disk.write disk.busy_max proc.blocked cpu.wait top.java.cpu vm.nr_dirty`; `Checkpoint started/finished`, `Too many dirty pages` |
| Узел выпал из топологии, SEGMENTED | на узле: `NET_DROP`/`NET_ZERO`, `NET_BOND_MEMBER`, `NMON_GAP` (хост замер), `JAVA_CPU_DROP`/`JAVA_ABSENT`/`JAVA_GONE`, `CPU_STEAL`, `SWAP_ACTIVITY`, `CPU_SATURATION_RUN` + `RUNQ_RUN`; у остальных — `CLUSTER_SYNC` (короткий провал `disk.write↓`/`top.java.cpu↓` — PME/exchange), затем rebalance | `timeline $D --around T --window 5m --step 1m --metrics net.read net.write top.java.cpu`: у соседей трафик обычный → проблема локальна; сообщите, что исключено (JVM жива, разрывов нет, CPU/память в норме); «замер сам» или «исключили» nmon не различает |
| Перезапуск JVM | `JAVA_RESTART`; перед ним `MEM_AVAIL_LOW`, `JAVA_RSS`, `SWAP_*`, `MAJFAULT_HIGH`, рост `JAVA_RSS_GROWTH`/`MEM_GROWTH`/`JAVA_THREADS_GROWTH`; `BOOT_RECENT` нет — ОС не перезагружалась | `grep -A1 JAVA_ $S/h.txt` по всем хостам; `java $F`: «Перезапуски java (смена PID)» (`между` = простой), RSS и threads старого/нового; CPU и сеть узла в простое (`NET_DROP`); рост RSS нового — прогрев |
| Гибель JVM / OOM-killer | `JAVA_GONE` (нового PID нет), затем `NET_DROP` до конца данных, memfree↑; `COMMIT_LIMIT` — ENOMEM без OOM-kill | `java`, `mem`, `uarg` (Xmx + MaxDirectMemorySize + data regions против RAM); OOM-kill, kill, crash nmon не различает — dmesg/journal |
| Давление на память без swap | `MEM_AVAIL_LOW`, `MEM_FREE_LOW`/`KSWAPD_ACTIVE` на WARN, `MAJFAULT_HIGH`, `mem.cached`↓, `proc.blocked`↑ | `health $F --from A --to B` (часть правил видна только в окне); метрики `mem.free mem.cached mem.avail_cal vm.pgmajfault disk.read top.kswapd.cpu`, второй вызов — `top.java.rss proc.blocked`; **кто занял память**: `top $F --from A --to B --sort rss --top 5` (часто не JVM: скрипт, бэкап; процесс, исчезнувший перед ростом memfree, — источник; ровный `top.java.rss` снимает вину с JVM; без UARG — только имя и PID, командную строку запросите) |
| Rebalance, снапшот, загрузка | `net.read`↑ у принимающих, `net.write`↑ у отдающих, пакет ~MTU, `disk.read` у отдающих, `disk.write` у принимающих, `top.java.cpu`↑; снапшот — крупный последовательный IO, рост `fs.<mount>.pct`; `CLUSTER_SYNC` `net.*↑` на многих узлах | `cluster --sort net.read:mean`, `net`, `disk --all`, `fs` |
| Долгие GC-паузы | nmon GC не видит; косвенно `JAVA_CPU_DROP` или всплеск `top.java.cpu` с `cpu.user`; пауза короче интервала усредняется; `NMON_GAP` — пауза всего хоста | `Long JVM pause`, GC-лог; `uarg` (GC, Xmx, AlwaysPreTouch) |
| Кончается место (WAL-архив, снапшоты) | `FS_FULL`, `FS_GROWTH`, скачки в `fs`, растущая запись на этот диск | `fs --mount REGEX`, `diskmap`, `disk --dev <LV>` |
| Медленно при «нормальном» CPU | `CPU_HOT_CORE`/`_RUN` (один поток: checkpoint, exchange-worker, striped-пул, GC; sys ≫ user — прерывания сети), `JAVA_SYS_SHARE`, `RUNQ_RUN`, `THP_COMPACTION` | `cpu`, `cores --sort max`; какой поток — thread dump/JFR |
| Насыщение CPU | `CPU_SATURATION_RUN`, `RUNQ_RUN` (`факты:` — эпизод, max/avg, Runnable при K CPU, топ-процесс) | `at --time T` (TOP: кто грузил, user/sys); фон до/после — `cpu $F --from/--to`; iowait и steal ≈ 0 исключают диск и гипервизор |
| Диск одного узла выделяется | `CLUSTER_OUTLIER` по `disk.*`, `DISK_BUSY_RUN`, `IO_STALL`, `BLOCKED_RUN` | эпизод или уровень (§10); I/O по процессам nmon не видит: `топ-процесс` в пиках `disk` — по CPU, не по I/O; «кто писал» — только вывод |
| Соседи, виртуализация | `CPU_STEAL` + провалы `top.java.cpu` в те же моменты; антивирус, бэкап, мониторинг | `java` («Другие процессы»), `top --by-cmd` |

## 12. Чего nmon не показывает

GC-паузы, safepoint, heap/off-heap, потоки JVM; состояние Ignite (checkpoint buffer, dirty pages, PME, rebalance);
**задержки чтения/записи Ignite** и latency диска без DISK*SERV — вместо них сообщайте `vm.pgmajfault`, `disk.read`,
`disk.busy_max`, `proc.blocked`, `cpu.wait`, `mem.avail_cal`/page cache; глубину очереди и I/O по процессам; TCP
(retransmits, RTT), кто с кем обменивался; состояние линка и LACP; dmesg (OOM-kill, link down, hung task); sysctl,
cgroup, PSI; load average; события короче интервала; процессы ниже порога TOP; командные строки без `-T`; зону и
рассинхрон часов. Это повод запросить данные (логи Ignite/GC, dmesg, sysctl, jstack), а не вывод «проблемы не было».
Сбор: `nmon -fT -s 30` (`-T` — UARG), синхронные часы (chrony/NTP).

## 13. Перед ответом проверьте

- Все строки §3 п. 6 на месте.
- Каждый CRIT-выброс `cluster` объяснён; у разных хостов причины разные.
- Код 1/2 не принят за сбой; окно из stderr совпало; зона учтена; `--host` заякорен; GB = MB/1024.
- Пик не из T0001; INFO не названо причиной; `MajorFault` TOP и `svc≈ms` не приняты за чтения и латентность; bond и
  слейвы, диск и dm-* не сложены; причина «из nmon» подтверждена логами или помечена как гипотеза.
