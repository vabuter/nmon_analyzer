#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmon_analyzer.py — однофайловый анализатор файлов NMON (nmon for Linux).

Назначение: быстрый ответ на вопросы о поведении ОС (CPU, память, подкачка, диски,
файловые системы, сеть, процессы и JVM, качество данных nmon, сравнение узлов) по файлам
nmon, снятым с узлов кластера Apache Ignite 2.17–2.19. Ориентирован на использование
ИИ-агентами через shell.

Требования: Python >= 3.12, только стандартная библиотека.

Запуск:  python3 nmon_analyzer.py <команда> [опции] <файлы|каталоги|маски>
Справка: python3 nmon_analyzer.py --help ; python3 nmon_analyzer.py <команда> --help
Полное описание команд и интерпретации — в NMON_ANALYZER.md.
"""
from __future__ import annotations

import argparse
import bisect
import glob
import json
import math
import os
import re
import sys
import zlib
from array import array
from collections import defaultdict, deque
from datetime import datetime, timedelta

VERSION = "1.0.0"
NAN = float("nan")
MONTHS = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
    "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}
RE_TSNAP = re.compile(r"^T\d{4,}$")
RE_SPLIT_DIGITS = re.compile(r"^([A-Z_]+?)(\d+)$")
# Секции, которые nmon делит на продолжения (DISKBUSY, DISKBUSY1, DISKBUSY2, ...)
# когда устройств больше, чем disks_per_line.
SPLITTABLE = {
    "DISKBUSY", "DISKREAD", "DISKWRITE", "DISKXFER", "DISKBSIZE",
    "DISKREADSERV", "DISKWRITESERV", "DISKRIO", "DISKWIO", "DISKAVGRIO",
    "DISKAVGWIO", "DISKSERV", "DISKWAIT", "DISKRXFER", "JFSFILE", "JFSINODE",
}
DISK_SECTIONS = ["DISKBUSY", "DISKREAD", "DISKWRITE", "DISKXFER", "DISKBSIZE",
                 "DISKREADSERV", "DISKWRITESERV"]

# Описание известных секций (для команды `sections` и для документации).
SECTION_INFO = {
    "AAA": ("Метаданные запуска nmon: host, OS, interval, snapshots, cpus, boottime, command", ""),
    "BBBP": ("Снимок конфигурации ОС на старте: lscpu, /proc/meminfo, lsblk, df, mount, ifconfig и др.", ""),
    "ZZZZ": ("Соответствие снимка Tnnnn реальному времени (HH:MM:SS, DD-MON-YYYY)", ""),
    "CPU_ALL": ("Суммарная загрузка CPU: User%, Sys%, Wait%, Idle%, Steal%, CPUs", "%"),
    "CPUnnn": ("Загрузка каждого логического CPU: User%, Sys%, Wait%, Idle%, Steal%", "%"),
    "MEM": ("Память в MB: memtotal, memfree, cached, buffers, active, inactive, swaptotal, swapfree, swapcached", "MB"),
    "VM": ("Счётчики vmstat: nr_* — текущие значения (страницы); остальные — приращения за интервал (pgpgin/pgpgout в KB)", "mixed (см. описание)"),
    "PROC": ("Планировщик: Runnable (очередь), Blocked (D-state), pswitch/s, fork/s (-1 = недоступно)", "count, /s"),
    "NET": ("Сетевой трафик по интерфейсам: <if>-read-KB/s, <if>-write-KB/s", "KB/s"),
    "NETPACKET": ("Пакеты по интерфейсам: <if>-read/s, <if>-write/s", "pkt/s"),
    "NETERROR": ("Ошибки сети по интерфейсам (если есть)", "/s"),
    "DISKBUSY": ("Занятость устройства (util), по устройствам", "%"),
    "DISKREAD": ("Чтение с устройства", "KB/s"),
    "DISKWRITE": ("Запись на устройство", "KB/s"),
    "DISKXFER": ("Операций ввода-вывода в секунду (IOPS)", "/s"),
    "DISKBSIZE": ("Средний размер операции ввода-вывода", "KB"),
    "DISKREADSERV": ("Среднее время обслуживания чтения (если есть)", "ms"),
    "DISKWRITESERV": ("Среднее время обслуживания записи (если есть)", "ms"),
    "JFSFILE": ("Заполненность файловых систем по точкам монтирования", "%"),
    "JFSINODE": ("Заполненность inode файловых систем (если есть)", "%"),
    "TOP": ("Процессы: PID, %CPU, %Usr, %Sys, Size(VSZ KB), ResSet(RSS KB), faults, Command, Threads, IOwaitTime", "mixed"),
    "UARG": ("Полные командные строки процессов (только при запуске nmon с -T)", ""),
    "DGBUSY": ("Группы дисков (-g): занятость", "%"),
    "DGREAD": ("Группы дисков (-g): чтение", "KB/s"),
    "DGWRITE": ("Группы дисков (-g): запись", "KB/s"),
    "DGXFER": ("Группы дисков (-g): IOPS", "/s"),
    "DGSIZE": ("Группы дисков (-g): размер операции", "KB"),
    "NFSSVRV3": ("NFS сервер v3 (если есть, -N)", "/s"),
    "NFSCLIV3": ("NFS клиент v3 (если есть, -N)", "/s"),
}

# --------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------


def warn(msg: str) -> None:
    sys.stderr.write(f"WARN: {msg}\n")


def to_float(s: str) -> float:
    """Число из строки nmon; пустое/некорректное -> NaN."""
    s = s.strip()
    if not s:
        return NAN
    try:
        return float(s)
    except ValueError:
        return NAN


def clean(vals) -> list:
    """Список конечных значений (без NaN/None/inf). None вместо ряда -> пустой список."""
    if vals is None:
        return []
    return [v for v in vals if v is not None and v == v and v not in (math.inf, -math.inf)]


def fmean(vals):
    c = clean(vals)
    return sum(c) / len(c) if c else NAN


def fsum(vals):
    c = clean(vals)
    return sum(c) if c else NAN


def fmin(vals):
    c = clean(vals)
    return min(c) if c else NAN


def fmax(vals):
    c = clean(vals)
    return max(c) if c else NAN


def fmedian(vals):
    c = sorted(clean(vals))
    n = len(c)
    if not n:
        return NAN
    m = n // 2
    return c[m] if n % 2 else (c[m - 1] + c[m]) / 2.0


def fstdev(vals):
    c = clean(vals)
    n = len(c)
    if n < 2:
        return NAN
    mu = sum(c) / n
    return math.sqrt(sum((x - mu) ** 2 for x in c) / (n - 1))


def percentile(vals, p: float):
    """Перцентиль с линейной интерполяцией (как numpy по умолчанию)."""
    c = sorted(clean(vals))
    n = len(c)
    if not n:
        return NAN
    if n == 1:
        return c[0]
    k = (n - 1) * p / 100.0
    f = math.floor(k)
    cidx = min(f + 1, n - 1)
    return c[f] + (c[cidx] - c[f]) * (k - f)


def argmax(vals):
    """Индекс максимума среди конечных значений; -1 если нет данных."""
    best, bi = None, -1
    for i, v in enumerate(vals or []):
        if v is not None and v == v and (best is None or v > best):
            best, bi = v, i
    return bi


def argmin(vals):
    best, bi = None, -1
    for i, v in enumerate(vals or []):
        if v is not None and v == v and (best is None or v < best):
            best, bi = v, i
    return bi


def count_above(vals, thr: float) -> int:
    return sum(1 for v in (vals or []) if v is not None and v == v and v > thr)


def linreg(xs, ys):
    """МНК по парам с конечными y. Возвращает (slope, intercept, n, r2)."""
    pts = [(x, y) for x, y in zip(xs, ys or []) if y is not None and y == y]
    n = len(pts)
    if n < 3:
        return NAN, NAN, n, NAN
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    if sxx == 0:
        return NAN, NAN, n, NAN
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pts)
    slope = sxy / sxx
    intercept = my - slope * mx
    syy = sum((p[1] - my) ** 2 for p in pts)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else NAN
    return slope, intercept, n, r2


def mad(vals, med=None):
    c = clean(vals)
    if not c:
        return NAN
    if med is None or med != med:
        med = fmedian(c)
    return fmedian([abs(v - med) for v in c])


CLUSTER_Z_REL_FLOOR = 0.05  # масштаб robust_z не меньше 5% |медианы|: почти одинаковые хосты не дают z ≈ 10


def robust_z(vals):
    """Робастный z-score: (v − медиана) / масштаб, масштаб = 1.4826·MAD; при MAD = 0 — 1.2533·среднее |v − медиана|
    (stdev включал бы сам выброс, и один отклонившийся хост из N давал бы z ≤ √N). Масштаб не меньше
    CLUSTER_Z_REL_FLOOR·|медиана|; если он всё равно 0 (все значения равны нулю) — NaN."""
    c = clean(vals)
    if not c:
        return [NAN] * len(vals)
    med = fmedian(c)
    m = mad(c, med)
    scale = 1.4826 * m if m > 0 else 1.2533 * sum(abs(v - med) for v in c) / len(c)
    scale = max(scale, CLUSTER_Z_REL_FLOOR * abs(med))
    if not scale > 0:
        return [NAN] * len(vals)
    return [(v - med) / scale if v is not None and v == v else NAN for v in vals]


def pearson(xs, ys):
    pts = [(x, y) for x, y in zip(xs, ys) if x == x and y == y]
    n = len(pts)
    if n < 3:
        return NAN
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    syy = sum((p[1] - my) ** 2 for p in pts)
    if sxx == 0 or syy == 0:
        return NAN
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pts)
    return sxy / math.sqrt(sxx * syy)


def fmt_num(v, prec=1):
    """Компактный вывод числа: NaN -> '-', большие целые с разделителями."""
    if v is None:
        return "-"
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (math.inf, -math.inf):
            return "-"
        if abs(v) >= 1e6 or prec == 0:
            return f"{v:.0f}"
        return f"{v:.{prec}f}"
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def fmt_bytes_kb(kb):
    """KB -> строка с удобной единицей (KB/MB/GB/TB)."""
    if kb is None or kb != kb:
        return "-"
    units = ["KB", "MB", "GB", "TB", "PB"]
    v = float(kb)
    i = 0
    while abs(v) >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    return f"{v:.1f} {units[i]}"


def fmt_mb(mb):
    if mb is None or mb != mb:
        return "-"
    return fmt_bytes_kb(mb * 1024.0)


def fmt_dur(seconds):
    if seconds is None or seconds != seconds:
        return "-"
    s = int(round(seconds))
    if s < 0:
        return "-" + fmt_dur(-s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m:02d}m" if (h or d) else f"{m}m")
    if not d and not h:
        parts.append(f"{s:02d}s")
    return " ".join(parts)


def ts(dt) -> str:
    if dt is None:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_nmon_date(s: str):
    """'01-AUG-2026' -> date. Также '2026-08-01' и '01/08/2026' (dd/mm/yyyy)."""
    s = s.strip()
    m = re.match(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})$", s)
    if m:
        mon = MONTHS.get(m.group(2).upper())
        if mon:
            try:
                return datetime(int(m.group(3)), mon, int(m.group(1))).date()
            except ValueError:
                return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).date()
        except ValueError:
            return None
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", s)
    if m:
        try:
            return datetime(int(m.group(3)), int(m.group(2)), int(m.group(1))).date()
        except ValueError:
            return None
    return None


def parse_nmon_time(s: str):
    """'14:05:09' или '14:05.09' -> (h, m, s); None, если не разобрать или вне диапазона (часы 0–23, минуты и
    секунды 0–59): испорченная метка ZZZZ/AAA,time считается нераспознанной, а не роняет разбор."""
    s = s.strip()
    m = re.match(r"^(\d{1,2}):(\d{2})[:.](\d{2})$", s)
    if m:
        t = int(m.group(1)), int(m.group(2)), int(m.group(3))
    else:
        m = re.match(r"^(\d{1,2}):(\d{2})$", s)
        if not m:
            return None
        t = int(m.group(1)), int(m.group(2)), 0
    return t if t[0] <= 23 and t[1] <= 59 and t[2] <= 59 else None


class UserError(ValueError):
    """Ошибка во входных данных пользователя (время, длительность, окно): main печатает «ERROR: …» и возвращает код 3.
    Прочие исключения при анализе — внутренние ошибки: трассировка в stderr и тот же код 3 (см. __main__)."""


RE_USER_TOD = re.compile(r"^\d{1,2}:\d{2}(?::\d{2})?$")
RE_USER_DATE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}|\d{1,2}-[A-Za-z]{3}-\d{4})$")
MSG_TIME_FORMATS = ("ожидается 'YYYY-MM-DD HH:MM[:SS]', 'YYYY-MM-DDTHH:MM[:SS]', 'DD-MON-YYYY HH:MM[:SS]', "
                    "'YYYY-MM-DD' или 'HH:MM[:SS]'; дробные секунды и [скобки] из логов допускаются")


def normalize_user_time(s: str) -> str:
    """Метка времени из лога -> вид для parse_user_time: без обрамляющих [скобок] и дробных секунд
    ('2026-03-14T03:52:10,123' -> '2026-03-14T03:52:10'). Метка со смещением зоны (Z, +03:00, +0300) — ValueError:
    nmon пишет локальное время хоста без зоны."""
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if re.search(r"\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?\s*(?:Z|[+-]\d{2}:?\d{2})$", s):
        raise UserError(f"метка {s!r} содержит смещение зоны; nmon пишет локальное время хоста без зоны — "
                         f"уберите смещение и при необходимости используйте --tz-shift")
    return re.sub(r"(\d{1,2}:\d{2}:\d{2})[.,]\d{1,9}$", r"\1", s)


def user_time_kind(s: str) -> str:
    """Вид времени пользователя: 'time' (только время суток), 'date' (только дата) или 'datetime'."""
    s = normalize_user_time(s)
    if RE_USER_TOD.match(s):
        return "time"
    return "date" if RE_USER_DATE.match(s) else "datetime"


def parse_user_time(s: str, ref):
    """Время из аргумента пользователя.
    Поддерживает: 'YYYY-MM-DD HH:MM[:SS]', 'YYYY-MM-DDTHH:MM[:SS]', 'YYYY-MM-DD', 'DD-MON-YYYY[ HH:MM[:SS]]',
    'HH:MM[:SS]' (дата берётся от ref); метки логов — с дробными секундами и в [скобках] (normalize_user_time).
    Без учёта перехода через полночь — см. resolve_user_time."""
    if s is None:
        return None
    s = normalize_user_time(s)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    try:
        m = re.match(r"^(\d{1,2}-[A-Za-z]{3}-\d{4})(?:[ T](\d{1,2}:\d{2}(?::\d{2})?))?$", s)
        if m:
            d = parse_nmon_date(m.group(1))
            t = parse_nmon_time(m.group(2)) if m.group(2) else (0, 0, 0)
            if d and t:
                return datetime(d.year, d.month, d.day, *t)
        t = parse_nmon_time(s)
        if t and ref is not None:
            return datetime(ref.year, ref.month, ref.day, *t)
    except ValueError:
        pass
    if re.match(r"^(?:\d{4}-\d{2}-\d{2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?|\d{1,2}-[A-Za-z]{3}-\d{4}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?"
                r"|\d{1,2}:\d{2}(?::\d{2})?)$", s):
        raise UserError(f"не удалось разобрать время {s!r}: часы 0–23, минуты/секунды 0–59, дата — существующий день "
                         f"({MSG_TIME_FORMATS})")
    raise UserError(f"не удалось разобрать время {s!r} ({MSG_TIME_FORMATS})")


def resolve_user_time(spec: str, ref, end, upper=False):
    """Время пользователя -> datetime, одно для всех хостов: ref/end — самый ранний и самый поздний снимок среди
    выбранных хостов. Только время суток берётся на дату ref; если оно раньше ref, а данные переходят через полночь,
    — на следующий день (момент и нижняя граница — только если перенесённое время не позже end; верхняя граница —
    всегда). Только дата для верхней границы (upper) — конец этого дня. Если время суток встречается в данных
    в разные сутки, в stderr — WARN с выбранной датой."""
    dt = parse_user_time(spec, ref)
    kind = user_time_kind(spec)
    if kind == "date":
        return dt + timedelta(days=1) - timedelta(microseconds=1) if upper else dt
    if kind != "time" or ref is None or end is None:
        return dt
    if dt < ref and end.date() > ref.date():
        nd = dt + timedelta(days=1)
        if upper or nd <= end:
            dt = nd
    days = [ref.date() + timedelta(days=k) for k in range((end.date() - ref.date()).days + 1)]
    if sum(1 for d in days if ref <= datetime.combine(d, dt.time()) <= end) > 1:
        warn(f"время {spec.strip()!r} без даты: взята дата {dt.date()}; это время есть в данных и в другие сутки "
             f"(период {ts(ref)} .. {ts(end)}) — укажите дату явно")
    return dt


def parse_duration(s: str) -> float:
    """'10m', '90s', '2h', '1d', '300' (секунды) -> секунды."""
    s = str(s).strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", s)
    if not m:
        raise UserError(f"не удалось разобрать длительность: {s!r} (пример: 10m, 90s, 2h)")
    v = float(m.group(1))
    mult = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return v * mult


# --------------------------------------------------------------------------
# Модель данных
# --------------------------------------------------------------------------


class Proc:
    """Строка секции TOP за один снимок."""
    __slots__ = ("pid", "cmd", "cpu", "usr", "sys", "size", "rss", "text", "data",
                 "shlib", "minflt", "majflt", "threads", "iowait")

    def __init__(self, pid, cmd, cpu, usr, sys_, size, rss, text, data, shlib,
                 minflt, majflt, threads, iowait):
        self.pid = pid
        self.cmd = cmd
        self.cpu = cpu
        self.usr = usr
        self.sys = sys_
        self.size = size
        self.rss = rss
        self.text = text
        self.data = data
        self.shlib = shlib
        self.minflt = minflt
        self.majflt = majflt
        self.threads = threads
        self.iowait = iowait


class EpochPid(int):
    """PID процесса после перезагрузки ОС внутри данных хоста (вторая и следующие эпохи загрузки): равен только PID
    той же эпохи, поэтому тот же номер после перезагрузки — другой процесс (JAVA_RESTART, отдельные жизнь и
    статистика). В тексте — 'pid@HH:MM' (время загрузки), в JSON — число."""

    def __new__(cls, pid, epoch, boot):
        obj = super().__new__(cls, pid)
        obj.epoch = epoch
        obj.boot = boot
        return obj

    def __eq__(self, other):
        if isinstance(other, EpochPid):
            return int(self) == int(other) and self.epoch == other.epoch
        return False if isinstance(other, int) else NotImplemented

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    def __hash__(self):
        return hash((int(self), self.epoch))

    def __str__(self):
        return f"{int(self)}@{self.boot.strftime('%H:%M') if self.boot else self.epoch + 1}"

    __repr__ = __str__

    def __format__(self, spec):
        return str(self) if not spec else format(int(self), spec)


class RawSection:
    """Секция файла nmon с временными строками: колонки + значения по снимкам."""
    __slots__ = ("name", "columns", "rows", "title", "run_cols", "base_width")

    def __init__(self, name):
        self.name = name
        self.columns = []
        self.title = ""
        self.rows = {}  # Tnnnn -> list[float]
        self.run_cols = {}  # номер запуска (>= 1) -> его заголовок, если он отличается от заголовка первого запуска
        self.base_width = None  # при run_cols: число колонок заголовка первого запуска (columns — объединение)


class NmonFile:
    """Разобранный файл nmon."""

    def __init__(self, path):
        self.path = path
        self.meta = {}
        self.bbbp = {}
        self.bbbp_order = []
        self.sections = {}
        self.zzzz = {}
        self.top = defaultdict(list)
        self.top_columns = []
        self.uarg = defaultdict(list)  # T -> [(pid, prog, cmdline)]
        self.uarg_columns = []
        self.line_count = 0
        self.bad_lines = 0
        self.time_backwards = 0  # переходов ZZZZ, где время меньше предыдущего (в порядке файла)
        self.warnings = []
        self.runs = {}        # номер запуска (>= 1) -> строки AAA этого запуска (boottime, date, time, OS, cpus ...)
        self.bbbp_runs = {}   # номер запуска (>= 1) -> BBBP этого запуска (в общий bbbp не попадает)
        self.truncated = False        # последняя строка оборвана или сжатый поток не завершён
        self.sorted_file = False      # строки данных встречаются раньше первой ZZZZ (файл пропущен через sort)
        self.sorted_multirun = False  # отсортированный файл с несколькими запусками nmon: разделить нельзя
        self.zzzz_estimated = 0       # снимков без ZZZZ, время которых оценено по интервалу
        self.untimed = 0              # снимков без ZZZZ, время которых оценить нельзя (не используются)
        self.incomplete = set()       # ключи последних снимков, записанных не полностью (нет части секций/TOP)
        self.merge_note = ""          # объединение с другими файлами этого AAA,host отключено (разные машины) — причина
        self.split_note = ""          # файл из нескольких запусков разных хостов разделён по запускам — причина
        self.tz_shift = timedelta(0)  # --tz-shift: на сколько сдвинуты метки zzzz (AAA date/time в meta — как в файле)

    @property
    def host(self) -> str:
        h = self.meta.get("host") or self.meta.get("runname")
        if not h:
            h = os.path.splitext(os.path.basename(self.path))[0]
        return h.strip()

    @property
    def interval(self) -> float:
        try:
            return float(self.meta.get("interval", "0"))
        except ValueError:
            return 0.0

    def run_interval(self, r=0) -> float:
        """AAA,interval запуска r nmon в файле (у запусков #N — свой AAA), с; 0 — нет или не разобрать."""
        try:
            v = float((self.meta if r == 0 else self.runs.get(r, {})).get("interval", "0"))
        except ValueError:
            return 0.0
        return v if v > 0 else 0.0

    def snapshot_ids(self):
        ids = set(self.zzzz.keys())
        for sec in self.sections.values():
            ids.update(sec.rows.keys())
        ids.update(self.top.keys())
        return sorted(ids)

    def start_datetime(self):
        return _meta_start(self.meta)

    def run_start(self, r=0):
        """Старт запуска r nmon (AAA date/time запуска) в шкале меток zzzz — со сдвигом --tz-shift; None, если не разобрать."""
        st = _meta_start(self.meta if r == 0 else self.runs.get(r, {}))
        return st + self.tz_shift if st is not None else None

    def first_value(self, section, column):
        """Значение колонки в первом снимке первого запуска (NaN, если секции/колонки нет)."""
        sec = self.sections.get(section)
        if sec is None or column not in sec.columns:
            return NAN
        keys = [k for k in sec.rows if _run_of(k) == 0]
        if not keys:
            return NAN
        vals = sec.rows[min(keys, key=_tnum)]
        i = sec.columns.index(column)
        return vals[i] if i < len(vals) else NAN


def _meta_start(meta):
    """Время старта nmon по AAA,date и AAA,time; None, если не разобрать."""
    d = parse_nmon_date(meta.get("date", ""))
    t = parse_nmon_time(meta.get("time", ""))
    if d and t:
        return datetime(d.year, d.month, d.day, *t)
    return None


def parse_boottime(s):
    """AAA,boottime ('09:15 AM 01-Mar-2026' или '21:15 01-Mar-2026') -> datetime; None, если не разобрать."""
    m = re.match(r"^(\d{1,2}):(\d{2})\s*(AM|PM)?\s+(\d{1,2}-[A-Za-z]{3}-\d{4})$", (s or "").strip(), re.I)
    if not m:
        return None
    d = parse_nmon_date(m.group(4))
    hh = int(m.group(1))
    if m.group(3):
        hh = hh % 12 + (12 if m.group(3).upper() == "PM" else 0)
    if not d or hh > 23 or int(m.group(2)) > 59:
        return None
    return datetime(d.year, d.month, d.day, hh, int(m.group(2)))


def _uptime_seconds(lines):
    """Аптайм из строк BBBP uptime ('up 1 day, 21:22' / 'up 3:04' / 'up 5 min'), с; None, если не разобрать."""
    for line in lines:
        m = re.search(r"up\s+(.*?),\s+\d+ users?", line)
        if not m:
            continue
        s = m.group(1)
        secs = 0
        d = re.search(r"(\d+)\s+day", s)
        if d:
            secs += int(d.group(1)) * 86400
        hm = re.search(r"(\d+):(\d+)", s)
        if hm:
            secs += int(hm.group(1)) * 3600 + int(hm.group(2)) * 60
        mi = re.search(r"(\d+)\s+min", s)
        if mi:
            secs += int(mi.group(1)) * 60
        return secs
    return None


def _boot_of(meta, bbbp):
    """Время загрузки ОС для запуска nmon: (datetime | None, источник 'AAA' | 'uptime' | '').
    AAA,boottime; если его нет — AAA date/time минус uptime из BBBP этого запуска."""
    boot = parse_boottime(meta.get("boottime", ""))
    if boot is not None:
        return boot, "AAA"
    up = _uptime_seconds(bbbp.get("uptime", []))
    st = _meta_start(meta)
    if up is not None and st is not None:
        return st - timedelta(seconds=up), "uptime"
    return None, ""


def _run_of(t: str) -> int:
    """Номер запуска nmon в файле по ключу снимка: 'T0012' -> 0, 'T0012#2' -> 2 (единственный разбор суффикса '#N')."""
    return int(t[t.find("#") + 1:]) if "#" in t else 0


def _meminfo_kb(lines):
    """/proc/meminfo из строк BBBP: ключ -> kB (int); повтор ключа не перетирает первое значение."""
    out = {}
    for line in lines:
        m = re.match(r"^(\S+):\s+(\d+)(?:\s+kB)?\s*$", line)
        if m and m.group(1) not in out:
            out[m.group(1)] = int(m.group(2))
    return out


def _compact_sections(names):
    """Список секций для сообщений: CPU001..CPU064 сворачиваются в диапазон."""
    cpus = sorted((s for s in names if re.match(r"^CPU\d+$", s)), key=lambda s: int(s[3:]))
    other = [s for s in names if not re.match(r"^CPU\d+$", s)]
    head = [f"{cpus[0]}..{cpus[-1]} ({len(cpus)})"] if len(cpus) > 1 else cpus
    return ", ".join(head + other)


MSG_SORTED_MULTIRUN = ("файл отсортирован и содержит несколько запусков nmon: строки разных запусков перемешаны, "
                       "разделить их невозможно; используйте исходные несортированные файлы")
MSG_TOP_HEADER_ONLY = ("заголовок TOP в файле есть, а строк TOP нет: TOP пишется начиная со второго снимка, "
                       "в файле только первый снимок")
MSG_T1_KEPT = ("T0001 не исключён: кроме первых снимков файлов/запусков в выборке нет других — значения за неполный "
               "интервал ненадёжны")


MSG_IV_DIFFER = ("интервалы nmon различаются по файлам/запускам — объёмы, длительности и разрывы считаются по "
                 "интервалу каждого снимка")


def _iv_list(ivd):
    """[(файл, запуск, интервал)] из Host.intervals_differ -> 'a.nmon: 60 с; b.nmon #2: 10 с'."""
    return "; ".join(f"{f}{f' #{r}' if r > 1 else ''}: {iv:g} с" for f, r, iv in ivd[:8]) + (" …" if len(ivd) > 8 else "")


def _t1_note(hx, note):
    """Примечание о первых снимках к статистике по hx = host.without_first(): note («без первых снимков…»), если они
    исключены или их нет в выборке; если исключить их нельзя (других снимков нет) — MSG_T1_KEPT."""
    return MSG_T1_KEPT if hx.firsts_kept else note


def _split_bbbp(line: str):
    # BBBP,seq,cmd,"text"  (text может содержать запятые)
    parts = line.split(",", 3)
    if len(parts) < 3:
        return None
    text = parts[3] if len(parts) > 3 else None
    if text is not None:
        text = text.rstrip("\r\n")
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            text = text[1:-1]
    return parts[1], parts[2], text


TOP_DEFAULT_COLUMNS = ["PID", "Time", "%CPU", "%Usr", "%Sys", "Size", "ResSet",
                       "ResText", "ResData", "ShdLib", "MinorFault", "MajorFault",
                       "Command", "Threads", "IOwaitTime"]
# колонки TOP в порядке числовых полей Proc (после pid и cmd)
TOP_PROC_FIELDS = ("%CPU", "%Usr", "%Sys", "Size", "ResSet", "ResText", "ResData", "ShdLib",
                   "MinorFault", "MajorFault", "Threads", "IOwaitTime")
TOP_NUM_CACHE_MAX = 200000  # кэш «строка -> float» разбора TOP: одинаковые значения — один объект float


def _tnum(t: str) -> int:
    """Номер снимка из 'T0012' или 'T0012#2' (второй запуск в том же файле)."""
    m = re.match(r"^T(\d+)", t)
    return int(m.group(1)) if m else 0


def _read_lines(fh, nf):
    """Строки открытого файла; обрезанный или повреждённый .gz (nmon ещё писал, файл не докопирован)
    читается до места обрыва — с предупреждением в nf.warnings."""
    try:
        yield from fh
    except EOFError:
        nf.truncated = True
        nf.warnings.append(f"файл обрезан (сжатый поток не завершён): разобрано {nf.line_count} строк")
    except zlib.error as e:
        nf.truncated = True
        nf.warnings.append(f"файл повреждён (ошибка распаковки: {e}): разобрано {nf.line_count} строк")


def parse_nmon_file(path: str) -> NmonFile:
    """Потоковый разбор одного файла nmon. Если в файле несколько запусков nmon подряд (повтор AAA,progname
    или ZZZZ с уже встречавшимся Tnnnn), снимки последующих запусков получают суффикс '#N', чтобы не
    смешивать данные разных запусков (AAA и BBBP этих запусков — в nf.runs / nf.bbbp_runs).
    Обрезанный конец файла (nmon ещё писал файл, узел упал, .gz не дописан): последняя строка без перевода
    строки отбрасывается, сжатый поток читается до места обрыва, неполный последний снимок помечается
    в nf.warnings, снимок из одной строки ZZZZ отбрасывается."""
    nf = NmonFile(path)
    top_cmd_idx = None
    top_n_head = 0
    top_fidx = ()   # индексы колонок TOP_PROC_FIELDS в строке TOP (-1 — колонки нет); считаются по заголовку
    top_num = {}    # строка значения -> float: строк TOP миллионы, значения (Size, ResSet, 0 ...) повторяются
    top_pid = {}    # строка PID -> int
    run = 0
    seen_data = False
    zzzz_seen = False  # для распознавания отсортированного файла: данные раньше первой ZZZZ
    last_zzzz = None
    last_run = 0

    seen_top = set()  # (снимок, PID) строк TOP/UARG — для отсортированного файла: первое вхождение
    bbbp_seq = {}     # (запуск, блок) -> [(номер строки BBBP, текст)] — в отсортированном файле порядок восстанавливается

    def tkey(t):
        return f"{t}#{run}" if run else t
    # utf-8-sig: BOM в начале файла (правка или копирование в Windows-редакторе) не становится частью первой секции
    if path.lower().endswith(".gz"):
        import gzip
        opener = gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline=None)
    else:
        opener = open(path, "r", encoding="utf-8-sig", errors="replace", newline=None)
    with opener as fh:
        for raw in _read_lines(fh, nf):
            nf.line_count += 1
            if not raw.endswith("\n"):
                # последняя физическая строка без перевода строки: запись оборвана, последнее поле может быть
                # обрезанным числом (123.4 -> 12) — строку не используем
                if raw.strip():
                    nf.bad_lines += 1
                    nf.truncated = True
                    nf.warnings.append("последняя строка без перевода строки (вероятно, обрезана: nmon ещё писал файл "
                                       "или узел упал) — отброшена")
                continue
            line = raw.rstrip("\r\n")
            if not line:
                continue
            comma = line.find(",")
            if comma <= 0:
                nf.bad_lines += 1
                continue
            tag = line[:comma]
            if tag == "AAA":
                parts = line.split(",", 2)
                key = parts[1].strip() if len(parts) >= 2 else ""
                if key == "progname" and seen_data:
                    run += 1  # новый запуск nmon, дописанный в тот же файл
                    nf.warnings.append(f"обнаружен повторный запуск nmon в том же файле (запуск #{run + 1}); снимки помечены суффиксом #{run}")
                if len(parts) >= 3:
                    if key not in nf.meta or run == 0:
                        nf.meta[key] = parts[2].strip()
                    if run:
                        nf.runs.setdefault(run, {})[key] = parts[2].strip()
                elif len(parts) == 2:
                    nf.meta.setdefault(key, "")
                continue
            if tag == "BBBP":
                r = _split_bbbp(line)
                if r:
                    _seq, cmd, text = r
                    cmd = cmd.strip()
                    # BBBP следующих запусков — отдельно: иначе он дописывается к блокам первого запуска
                    dst = nf.bbbp_runs.setdefault(run, {}) if run else nf.bbbp
                    if cmd not in dst:
                        dst[cmd] = []
                        if not run:
                            nf.bbbp_order.append(cmd)
                    if text is not None:
                        dst[cmd].append(text)
                    s = _seq.strip()
                    bbbp_seq.setdefault((run, cmd), []).append((int(s) if s.isdigit() else math.inf, text))
                continue
            if tag == "ZZZZ":
                parts = line.split(",")
                seen_data = True
                zzzz_seen = True
                tid = parts[1].strip() if len(parts) > 1 else ""
                if tkey(tid) in nf.zzzz and RE_TSNAP.match(tid):
                    if nf.sorted_file:
                        # в отсортированном файле строки разных запусков перемешаны: оставляем первое вхождение
                        nf.sorted_multirun = True
                        continue
                    run += 1  # повтор Tnnnn — новый запуск nmon в том же файле
                    nf.warnings.append(f"повтор снимка {tid} — новый запуск nmon в том же файле (запуск #{run + 1}); снимки помечены суффиксом #{run}")
                if len(parts) >= 4:
                    t = parse_nmon_time(parts[2])
                    d = parse_nmon_date(parts[3])
                    if t and d:
                        dt = datetime(d.year, d.month, d.day, *t)
                        if last_zzzz is not None and dt < last_zzzz and run == last_run:
                            nf.time_backwards += 1
                        last_zzzz, last_run = dt, run
                        nf.zzzz[tkey(tid)] = dt
                    else:
                        nf.bad_lines += 1
                elif len(parts) == 3:
                    t = parse_nmon_time(parts[2])
                    d = parse_nmon_date(nf.meta.get("date", ""))
                    if t and d:
                        nf.zzzz[tkey(tid)] = datetime(d.year, d.month, d.day, *t)
                    else:
                        nf.bad_lines += 1
                continue
            if tag == "TOP":
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                if parts[1].startswith("+"):
                    cols = [c.strip() for c in parts[1:]]
                    cols[0] = cols[0].lstrip("+")
                    nf.top_columns = cols
                    top_map = {c: i for i, c in enumerate(cols)}
                    top_cmd_idx = top_map.get("Command")
                    top_n_head = len(cols)
                    top_fidx = tuple(top_map.get(c, -1) for c in TOP_PROC_FIELDS)
                    continue
                if not RE_TSNAP.match(parts[2].strip()):
                    continue  # "TOP,%CPU Utilisation" и т.п.
                vals = parts[1:]
                if top_cmd_idx is None:
                    nf.top_columns = list(TOP_DEFAULT_COLUMNS)
                    top_map = {c: i for i, c in enumerate(nf.top_columns)}
                    top_cmd_idx = top_map["Command"]
                    top_n_head = len(nf.top_columns)
                    top_fidx = tuple(top_map.get(c, -1) for c in TOP_PROC_FIELDS)
                extra = len(vals) - top_n_head
                if extra > 0:
                    cmd = ",".join(vals[top_cmd_idx:top_cmd_idx + extra + 1])
                    vals = vals[:top_cmd_idx] + [cmd] + vals[top_cmd_idx + extra + 1:]
                if top_cmd_idx >= len(vals) or not vals[top_cmd_idx].strip():
                    nf.bad_lines += 1  # обрезанная строка TOP без имени команды
                    continue
                pid = top_pid.get(vals[0])
                if pid is None:
                    try:
                        pid = top_pid[vals[0]] = int(vals[0])
                    except ValueError:
                        continue
                seen_data = True
                snap = tkey(vals[1].strip())
                if nf.sorted_file:
                    # в отсортированном файле строки TOP разных запусков с тем же снимком и PID стоят рядом: первое вхождение
                    k = (snap, pid)
                    if k in seen_top:
                        nf.sorted_multirun = True
                        continue
                    seen_top.add(k)
                nv = len(vals)
                nums = []
                for i in top_fidx:
                    s = vals[i] if 0 <= i < nv else ""
                    v = top_num.get(s)
                    if v is None:
                        if len(top_num) >= TOP_NUM_CACHE_MAX:
                            top_num.clear()
                        v = top_num[s] = to_float(s)
                    nums.append(v)
                nf.top[snap].append(Proc(pid, sys.intern(vals[top_cmd_idx].strip()), *nums))
                continue
            if tag == "UARG":
                parts = line.split(",")
                if len(parts) >= 2 and parts[1].startswith("+"):
                    nf.uarg_columns = [c.lstrip("+").strip() for c in parts[1:]]
                    continue
                if len(parts) < 4 or not RE_TSNAP.match(parts[1].strip()):
                    continue
                cols = nf.uarg_columns or ["Time", "PID", "ProgName", "FullCommand"]
                cmap = {c: i for i, c in enumerate(cols)}
                vals = parts[1:]
                fc_idx = cmap.get("FullCommand", len(cols) - 1)
                full = ",".join(vals[fc_idx:]) if fc_idx < len(vals) else ""
                pid_idx = cmap.get("PID", 1)
                prog_idx = cmap.get("ProgName", cmap.get("COMM", 2))
                try:
                    pid = int(vals[pid_idx])
                except (ValueError, IndexError):
                    pid = -1
                prog = vals[prog_idx].strip() if prog_idx < len(vals) else ""
                snap = tkey(vals[0].strip())
                if nf.sorted_file and pid >= 0:
                    if ("UARG", snap, pid) in seen_top:
                        nf.sorted_multirun = True
                        continue
                    seen_top.add(("UARG", snap, pid))
                nf.uarg[snap].append((pid, prog, full.strip()))
                continue
            # Обычная секция: TAG,Tnnnn,v1,v2,...  или заголовок TAG,title,col1,col2,...
            parts = line.split(",")
            if len(parts) < 2:
                nf.bad_lines += 1
                continue
            second = parts[1].strip()
            sec = nf.sections.get(tag)
            if sec is None:
                sec = RawSection(tag)
                nf.sections[tag] = sec
            if RE_TSNAP.match(second):
                seen_data = True
                if not zzzz_seen:
                    nf.sorted_file = True  # строки данных раньше первой ZZZZ: файл пропущен через sort
                key = tkey(second)
                if key in sec.rows:
                    if nf.sorted_file:
                        nf.sorted_multirun = True
                    continue  # дубликат снимка — оставляем первый
                sec.rows[key] = [to_float(x) for x in parts[2:]]
            else:
                if not sec.columns:
                    sec.title = second
                    sec.columns = [c.strip() for c in parts[2:]]
                elif run and run not in sec.run_cols:
                    # заголовок следующего запуска: после перезагрузки набор дисков, интерфейсов и ФС мог измениться —
                    # строки этого запуска раскладываются по его собственному заголовку
                    cols = [c.strip() for c in parts[2:]]
                    if cols != sec.columns:
                        sec.run_cols[run] = cols
    if nf.sorted_multirun:
        nf.warnings.append(MSG_SORTED_MULTIRUN)
    if nf.sorted_file and bbbp_seq:
        # отсортированный файл: строки BBBP идут в лексикографическом порядке номера (BBBP,1000 раньше BBBP,101) —
        # порядок строк внутри блоков и самих блоков восстанавливается по номеру строки (нечисловой — в конец)
        for (r, cmd), lst in bbbp_seq.items():
            dst = nf.bbbp_runs.get(r, {}) if r else nf.bbbp
            dst[cmd] = [t for _s, t in sorted(lst, key=lambda x: x[0]) if t is not None]
        first_seq = {cmd: min(s for s, _t in lst) for (r, cmd), lst in bbbp_seq.items() if not r}
        nf.bbbp_order.sort(key=lambda c: first_seq.get(c, math.inf))
    # Снимки по запускам (по возрастанию номера): последний снимок запуска может быть записан не полностью
    by_run = defaultdict(list)
    for t in nf.snapshot_ids():
        by_run[_run_of(t)].append(t)
    for keys in by_run.values():
        keys.sort(key=_tnum)
    last_keys = {keys[-1] for keys in by_run.values()}
    if nf.truncated and by_run:
        nf.incomplete.add(by_run[max(by_run)][-1])  # оборван конец файла: последний снимок мог потерять часть TOP
    # Согласованность: длина строк vs колонки (каждая строка — по заголовку своего запуска)
    changed_cols = defaultdict(list)  # (запуск, +колонки, −колонки) -> секции
    for sec in list(nf.sections.values()):
        if not sec.rows and not sec.columns:
            del nf.sections[sec.name]
            continue
        synthetic = not sec.columns
        if synthetic:
            width = max((len(v) for v in sec.rows.values()), default=0)
            sec.columns = [f"col{i + 1}" for i in range(width)]
            nf.warnings.append(f"секция {sec.name}: заголовок не найден, колонки названы col1..col{width}")
        ncol = len(sec.columns)
        widths = {r: len(h) for r, h in sec.run_cols.items()}
        short_other = full_other = 0
        for key, vals in sec.rows.items():
            if key not in last_keys:
                if len(vals) < widths.get(_run_of(key), ncol):
                    short_other += 1
                else:
                    full_other += 1
        short = 0
        for key, vals in sec.rows.items():
            w = widths.get(_run_of(key), ncol)
            if len(vals) < w:
                if key in last_keys and not synthetic and full_other and not short_other:
                    # строка последнего снимка короче заголовка, а все остальные строки секции полные — запись
                    # оборвана: значения не используем. Если короче и другие строки — расхождение заголовка и данных
                    # (колонка в конце заголовка лишняя): строка дополняется пустыми значениями, как остальные
                    vals[:] = [NAN] * w
                    nf.warnings.append(f"обрезанная строка {sec.name} в {key} — значения снимка не используются")
                else:
                    vals.extend([NAN] * (w - len(vals)))
                    short += 1
            elif len(vals) > w:
                del vals[w:]
        if short and not synthetic:
            nf.warnings.append(f"секция {sec.name}: строк короче заголовка: {short} — недостающие значения пустые")
        if sec.run_cols:
            # общий список колонок секции: заголовок первого запуска + новые колонки следующих; строки запусков со своим
            # заголовком раскладываются по именам, недостающие значения — пустые
            base = list(sec.columns)
            sec.base_width = len(base)
            for r in sorted(sec.run_cols):
                hdr = sec.run_cols[r]
                sec.columns.extend(c for c in hdr if c not in sec.columns)
                changed_cols[(r, tuple(c for c in hdr if c not in base), tuple(c for c in base if c not in hdr))].append(sec.name)
            pos = {}
            for i, c in enumerate(sec.columns):
                pos.setdefault(c, i)
            for key, vals in sec.rows.items():
                hdr = sec.run_cols.get(_run_of(key))
                if hdr is None:
                    vals.extend([NAN] * (len(sec.columns) - len(vals)))
                else:
                    row = [NAN] * len(sec.columns)
                    for c, v in zip(hdr, vals):
                        row[pos[c]] = v
                    vals[:] = row
    for (r, added, removed), names in sorted(changed_cols.items()):
        lst = lambda xs: ", ".join(xs[:6]) + (f" … +{len(xs) - 6}" if len(xs) > 6 else "")  # noqa: E731
        diff = (f"; новые колонки: {lst(added)}" if added else "") + (f"; исчезли: {lst(removed)}" if removed else "")
        nf.warnings.append(f"запуск #{r + 1}: заголовок секций {_compact_sections(names)} отличается от первого запуска"
                           + (diff or "; другой порядок колонок") + " — строки запуска разложены по его заголовку")
    # Последний снимок каждого запуска: только ZZZZ без данных — отбрасываем; нет части секций — предупреждаем;
    # у разбитой секции (DISKBUSY + DISKBUSY1 ...) нет продолжения — отбрасываем её строки этого снимка,
    # чтобы суммы по дискам не считались по части устройств
    for keys in by_run.values():
        last = keys[-1]
        if not any(last in sec.rows for sec in nf.sections.values()) and not nf.top.get(last) and not nf.uarg.get(last):
            if last in nf.zzzz:
                del nf.zzzz[last]
                nf.warnings.append(f"последний снимок {last} без данных (в файле только строка ZZZZ) — отброшен")
            continue
        if len(keys) < 2:
            continue
        prev = keys[-2]
        missing = [name for name, sec in nf.sections.items() if prev in sec.rows and last not in sec.rows]
        # файл оборван ровно перед строками TOP последнего снимка (числовые секции целы): тоже неполный снимок
        no_top = bool(nf.top.get(prev)) and not nf.top.get(last)
        if not missing and not no_top:
            continue
        split = {Host._base_name(m) for m in missing if Host._base_name(m) in SPLITTABLE}
        dropped = []
        for name, sec in nf.sections.items():
            if Host._base_name(name) in split and last in sec.rows:
                del sec.rows[last]
                dropped.append(name)
        nf.incomplete.add(last)
        what = ([f"нет секций {_compact_sections(missing)}"] if missing else []) + (["нет строк TOP"] if no_top else [])
        msg = f"последний снимок {last} неполный (запись оборвана?): {'; '.join(what)}"
        if dropped:
            msg += f"; строки {', '.join(dropped)} этого снимка отброшены (нет продолжения разбитой секции)"
        nf.warnings.append(msg)
    # Восстановление отсутствующих ZZZZ по интервалу: от известной метки своего запуска, а без них — от AAA date/time
    # этого запуска (у запусков #N — свои AAA в nf.runs)
    ids = nf.snapshot_ids()
    if ids:
        missing = [t for t in ids if t not in nf.zzzz]
        if missing:
            interval = nf.interval or 60.0
            known_of = defaultdict(list)
            for k, dt in nf.zzzz.items():
                known_of[_run_of(k)].append((_tnum(k), dt))
            for t in missing:
                n = _tnum(t)
                r = _run_of(t)
                iv = interval
                if r:
                    try:
                        iv = float(nf.runs.get(r, {}).get("interval", "")) or interval
                    except ValueError:
                        pass
                known = known_of.get(r)
                est = None
                if known:
                    k = min(known, key=lambda kv: (abs(kv[0] - n), kv[0]))
                    est = k[1] + timedelta(seconds=(n - k[0]) * iv)
                else:
                    start = nf.start_datetime() if r == 0 else _meta_start(nf.runs.get(r, {}))
                    if start is not None:
                        est = start + timedelta(seconds=(n - 1) * iv)
                if est is not None:
                    nf.zzzz[t] = est
                    nf.zzzz_estimated += 1
                else:
                    nf.untimed += 1
            if nf.zzzz_estimated:
                nf.warnings.append(f"{nf.zzzz_estimated} снимков без строки ZZZZ — время оценено по интервалу {interval:.0f}s")
            if nf.untimed:
                nf.warnings.append(f"{nf.untimed} снимков без времени (нет ZZZZ, а AAA date/time нет или не разбираются) — не используются")
    return nf


# --------------------------------------------------------------------------
# Хост: объединение файлов, выровненные по времени ряды
# --------------------------------------------------------------------------


def _bbbp_dev(s: str) -> str:
    """Имя устройства из BBBP: nmon пишет '/dev/…' как 'ddev/…' (mount, df, fstab) — возвращаем '/dev/…'."""
    return "/dev/" + s[5:] if s.startswith("ddev/") else s


class Host:
    """Все данные по одному хосту: объединённые файлы, ряды, выровненные по времени."""

    def __init__(self, name: str):
        self.name = name
        self.files = []
        self.times = []
        self.snap_ids = []
        self.snap_src = []
        self.snap_iv = []     # по снимкам: номинальный интервал его файла/запуска nmon, с (iv(i))
        self.run_ivs = {}     # (индекс файла, номер запуска) -> номинальный интервал, с
        self.series = {}      # section -> column -> array('d')
        self.columns = {}     # section -> [columns]
        self.top = []         # по индексу снимка: list[Proc]
        self.uarg = []
        self.meta = {}
        self.bbbp = {}
        self.bbbp_order = []
        self.bbbp_src = {}     # блок BBBP -> индекс файла, из которого он взят
        self.interval = 0.0
        self.warnings = []
        self.duplicates_dropped = 0
        self.dup_by_file = []  # по индексу файла: сколько его снимков отброшено как дубликаты при объединении
        self.dup_same_file = []  # по индексу файла: из них — с тем же временем, что другой снимок этого же файла
        self.file_info = []    # по файлам и запускам nmon в них: период, boottime, OS, cpus, MemTotal (см. _file_info)
        self.cpu_cores = []
        self.unfiltered = None  # хост до фильтра --from/--to/--around (полный ряд); None — фильтра не было
        self.slice_of = None    # исходный (полный) хост среза: роли сети и состав bond — по нему
        # результат without_first(): сколько первых снимков файлов/запусков (T0001) исключено и сколько оставлено,
        # потому что кроме них в выборке ничего нет (тогда статистика по T0001 ненадёжна — см. _t1_note)
        self.firsts_dropped = 0
        self.firsts_kept = 0
        # калибровка avail по MemAvailable (считается один раз в build(), срезы её копируют): поправка, MB
        # (None — неизвестна), опорный снимок {file, snap, est, memavail} и причина, если поправки нет
        self._avail_off = None
        self._avail_ref = None
        self._avail_reason = ""

    # --- построение ---
    def build(self):
        self.files.sort(key=lambda f: (f.start_datetime() or datetime.min, f.path))
        self.meta = dict(self.files[0].meta)
        for fi, f in enumerate(self.files):
            for cmd in f.bbbp_order:
                if cmd not in self.bbbp:
                    self.bbbp[cmd] = list(f.bbbp[cmd])
                    self.bbbp_order.append(cmd)
                    self.bbbp_src[cmd] = fi
        intervals = [f.interval for f in self.files if f.interval > 0]
        self.interval = fmedian(intervals) if intervals else 60.0
        self.run_ivs = self._run_intervals()
        chosen = {}
        self.dup_by_file = [0] * len(self.files)
        self.dup_same_file = [0] * len(self.files)
        for fi, f in enumerate(self.files):
            for t, dt in f.zzzz.items():
                if dt in chosen:
                    self.duplicates_dropped += 1
                    self.dup_by_file[fi] += 1
                    if chosen[dt][0] == fi:
                        self.dup_same_file[fi] += 1  # часы переведены назад: метка совпала с более ранним снимком файла
                    continue
                chosen[dt] = (fi, t)
        # Перекрывающиеся файлы одного хоста: в отрезке, который покрывает запуск nmon более раннего файла (от первого до
        # последнего снимка запуска, ± полинтервала большего из двух интервалов), остаются только его снимки — иначе
        # снимки двух одновременно работавших nmon (другая фаза или другой интервал) чередовались бы и учитывались дважды
        if len(self.files) > 1:
            seg = {}
            for dt, (fi, t) in chosen.items():
                key = (fi, _run_of(t))
                lo, hi = seg.get(key, (dt, dt))
                seg[key] = (min(lo, dt), max(hi, dt))
            for dt in sorted(chosen):
                fi, t = chosen[dt]
                iv = self.run_ivs.get((fi, _run_of(t)), self.interval)
                for (fj, rj), (lo, hi) in seg.items():
                    if fj >= fi:
                        continue  # оставляем снимки файла с меньшим индексом (более ранний старт)
                    half = timedelta(seconds=0.5 * max(iv, self.run_ivs.get((fj, rj), self.interval)))
                    if lo - half < dt < hi + half:
                        self.dup_by_file[fi] += 1
                        self.duplicates_dropped += 1
                        del chosen[dt]
                        break
        self.times = sorted(chosen.keys())
        self.snap_src = [chosen[dt][0] for dt in self.times]
        self.snap_ids = [chosen[dt][1] for dt in self.times]
        self.snap_iv = [self.run_ivs.get((fi, _run_of(t)), self.interval) for fi, t in zip(self.snap_src, self.snap_ids)]
        if self.snap_iv and any(f.interval > 0 for f in self.files):
            # типичный интервал хоста (вывод, окна совпадения) — самый частый номинальный интервал оставшихся снимков
            # (при равенстве — больший), а не медиана по файлам: у файлов 60 с и 10 с медиана 35 с не существует
            cnt = defaultdict(int)
            for v in self.snap_iv:
                cnt[v] += 1
            self.interval = max(cnt, key=lambda v: (cnt[v], v))
        n = len(self.times)
        all_secs = {}
        for f in self.files:
            for name, sec in f.sections.items():
                base = self._base_name(name)
                if base not in all_secs:
                    all_secs[base] = []
                for c in sec.columns:
                    if c not in all_secs[base]:
                        all_secs[base].append(c)
        for base, cols in all_secs.items():
            self.columns[base] = cols
            self.series[base] = {c: array("d", [NAN]) * n for c in cols}
        for i, dt in enumerate(self.times):
            fi, t = chosen[dt]
            f = self.files[fi]
            for name, sec in f.sections.items():
                vals = sec.rows.get(t)
                if vals is None:
                    continue
                ser = self.series[self._base_name(name)]
                # DISKBUSY и DISKBUSY1 пишут в один ряд: строки запуска без колонки (устройство перешло в другую часть
                # секции) дополнены NaN — пустое значение не затирает записанное другой частью
                for c, v in zip(sec.columns, vals):
                    if v == v:
                        ser[c][i] = v
        self.top = [[] for _ in range(n)]
        self.uarg = [[] for _ in range(n)]
        for i, dt in enumerate(self.times):
            fi, t = chosen[dt]
            f = self.files[fi]
            self.top[i] = f.top.get(t, [])
            self.uarg[i] = f.uarg.get(t, [])
        for f in self.files:
            for w in f.warnings:
                self.warnings.append(f"{os.path.basename(f.path)}: {w}")
        self.cpu_cores = sorted([s for s in self.series if re.match(r"^CPU\d+$", s)],
                                key=lambda s: int(s[3:]))
        self.file_info = self._file_info()
        self._calc_avail_anchor()
        if n:
            # строки секций уже разложены по рядам хоста — освобождаем их (на длинных файлах это основная часть памяти
            # разбора); для first_value остаётся первая строка первого запуска
            for f in self.files:
                for sec in f.sections.values():
                    first = min((k for k in sec.rows if _run_of(k) == 0), key=_tnum, default=None)
                    sec.rows = {first: sec.rows[first]} if first is not None else {}

    def _run_intervals(self):
        """(индекс файла, номер запуска) -> номинальный интервал запуска nmon, с: AAA,interval этого запуска, без него —
        медиана шагов между соседними по номеру снимками запуска, иначе интервал хоста."""
        out = {}
        for fi, f in enumerate(self.files):
            by_run = defaultdict(list)
            for t, dt in f.zzzz.items():
                by_run[_run_of(t)].append((_tnum(t), dt))
            for r, z in by_run.items():
                iv = f.run_interval(r)
                if iv <= 0:
                    z.sort()
                    d = [(b[1] - a[1]).total_seconds() for a, b in zip(z, z[1:]) if b[0] == a[0] + 1 and b[1] > a[1]]
                    iv = fmedian(d) if d else 0.0
                out[(fi, r)] = iv if iv > 0 else self.interval
        return out

    def intervals_differ(self):
        """[(файл, запуск, интервал)] запусков nmon хоста, если номинальные интервалы различаются, иначе []."""
        ivs = {}
        for (fi, r), iv in self.run_ivs.items():
            if any(src == fi and _run_of(t) == r for src, t in zip(self.snap_src, self.snap_ids)):
                ivs[(fi, r)] = iv
        if len({round(v, 3) for v in ivs.values()}) < 2:
            return []
        return [(os.path.basename(self.files[fi].path), r + 1, iv) for (fi, r), iv in sorted(ivs.items())]

    def _file_info(self):
        """По каждому файлу и каждому запуску nmon в нём (по времени начала): период, число снимков, boottime
        (AAA,boottime или AAA date/time − uptime из BBBP этого запуска), OS, cpus, MemTotal (kB), uptime на старте."""
        out = []
        for fi, f in enumerate(self.files):
            by_run = defaultdict(list)
            for t, dt in f.zzzz.items():
                by_run[_run_of(t)].append(dt)
            for r in sorted(by_run):
                meta = f.meta if r == 0 else f.runs.get(r, {})
                bbbp = f.bbbp if r == 0 else f.bbbp_runs.get(r, {})
                boot, src = _boot_of(meta, bbbp)
                memtotal = _meminfo_kb(bbbp.get("/proc/meminfo", [])).get("MemTotal")
                uptime = ""
                for line in bbbp.get("uptime", []):
                    m = re.search(r"\bup\s+(.*?),\s+\d+ users?", line)
                    if m or line.strip():
                        uptime = f"up {m.group(1)}" if m else line.strip()
                        break
                out.append({"fi": fi, "file": os.path.basename(f.path), "run": r + 1, "start": min(by_run[r]), "end": max(by_run[r]),
                            "snapshots": len(by_run[r]), "boottime": boot, "boot_src": src, "OS": meta.get("OS", ""),
                            "cpus": meta.get("cpus", ""), "memtotal_kb": memtotal, "uptime": uptime})
        out.sort(key=lambda x: (x["start"], x["file"], x["run"]))
        return out

    def tag_boot_epochs(self):
        """Тот же PID после перезагрузки ОС — другой процесс: снимкам запусков nmon после смены boottime (> 120 с, по
        file_info) PID в TOP и UARG заменяются на EpochPid (эпоха загрузки + время загрузки). Вызывается один раз после
        --tz-shift (время загрузки в подписи — в той же шкале, что метки). Одна эпоха — ничего не меняется."""
        epoch, last, of_run = 0, None, {}
        for x in sorted(self.file_info, key=lambda x: (x["start"], x["fi"], x["run"])):
            b = x["boottime"]
            if b is not None:
                if last is not None and (b - last).total_seconds() > 120:
                    epoch += 1
                if last is None or b > last:
                    last = b
            of_run[(x["fi"], x["run"] - 1)] = (epoch, last)
        if not epoch:
            return
        for i, (fi, t) in enumerate(zip(self.snap_src, self.snap_ids)):
            e, boot = of_run.get((fi, _run_of(t)), (0, None))
            if not e:
                continue
            for p in self.top[i]:
                if not isinstance(p.pid, EpochPid):
                    p.pid = EpochPid(p.pid, e, boot)
            self.uarg[i] = [(pid if isinstance(pid, EpochPid) else EpochPid(pid, e, boot), prog, full)
                            for pid, prog, full in self.uarg[i]]

    @staticmethod
    def _base_name(name: str) -> str:
        """DISKBUSY1 -> DISKBUSY (продолжение секции при большом числе дисков)."""
        m = RE_SPLIT_DIGITS.match(name)
        if m and m.group(1) in SPLITTABLE:
            return m.group(1)
        return name

    # --- доступ ---
    def n(self) -> int:
        return len(self.times)

    def has(self, section: str) -> bool:
        return section in self.series and self.n() > 0

    def col(self, section: str, column: str):
        s = self.series.get(section)
        if s is None:
            return None
        return s.get(column)

    def cols(self, section: str):
        return self.columns.get(section, [])

    def start(self):
        return self.times[0] if self.times else None

    def end(self):
        return self.times[-1] if self.times else None

    def duration(self) -> float:
        if len(self.times) < 2:
            return 0.0
        return (self.times[-1] - self.times[0]).total_seconds()

    def actual_interval(self) -> float:
        """Медианный шаг между снимками, с."""
        if len(self.times) < 2:
            return self.interval
        deltas = [(self.times[i + 1] - self.times[i]).total_seconds() for i in range(len(self.times) - 1)]
        return fmedian(deltas)

    def step(self) -> float:
        """Типичный шаг хоста (с): интервал nmon (медиана по файлам) либо фактический — для вывода и окон совпадения;
        интегрирование и разрывы — по интервалу каждого снимка (iv)."""
        return self.interval if self.interval > 0 else (self.actual_interval() or 60.0)

    def iv(self, i) -> float:
        """Номинальный интервал nmon снимка i (AAA,interval его файла/запуска), с."""
        return self.snap_iv[i] if i < len(self.snap_iv) else self.step()

    def pair_iv(self, i) -> float:
        """Масштаб промежутка между снимками i и i+1: больший из их номинальных интервалов, с."""
        return max(self.iv(i), self.iv(i + 1)) if i + 1 < self.n() else self.iv(i)

    def gaps(self, factor=1.5):
        """Разрывы во времени: список (t_prev, t_next, seconds, интервал) — промежуток больше factor × интервал (больший
        из номинальных интервалов соседних снимков: у файлов/запусков с разным AAA,interval — свой)."""
        out = []
        for i in range(len(self.times) - 1):
            d = (self.times[i + 1] - self.times[i]).total_seconds()
            iv = self.pair_iv(i)
            if d > iv * factor:
                out.append((self.times[i], self.times[i + 1], d, iv))
        return out

    def split_gaps(self, factor=1.5):
        """Разрывы (как gaps), разделённые на (внутри запуска nmon, на границе файлов/запусков). На границе — если
        снимок до разрыва последний в ряду у своего файла и запуска или снимок после разрыва — первый у своего:
        там nmon не работал (остановлен, перезапущен, перезагрузка ОС), а внутри запуска разрыв — заморозка хоста
        или задержка nmon."""
        first, last = {}, {}
        for i, (src, t) in enumerate(zip(self.snap_src, self.snap_ids)):
            key = (src, _run_of(t))
            first.setdefault(key, i)
            last[key] = i
        inner, edge = [], []
        pos = {t: i for i, t in enumerate(self.times)}
        for g in self.gaps(factor):
            i, j = pos[g[0]], pos[g[1]]
            ki, kj = (self.snap_src[i], _run_of(self.snap_ids[i])), (self.snap_src[j], _run_of(self.snap_ids[j]))
            (edge if last[ki] == i or first[kj] == j else inner).append(g)
        return inner, edge

    def slice(self, mask) -> "Host":
        """Новый Host с подмножеством снимков (фильтр по времени). Кэши, не зависящие от окна (роли сети и состав
        bond, размер страницы, точки монтирования), берутся у исходного хоста."""
        h = Host(self.name)
        h.files = self.files
        h.meta = self.meta
        h.bbbp = self.bbbp
        h.bbbp_order = self.bbbp_order
        h.bbbp_src = self.bbbp_src
        h._avail_off, h._avail_ref, h._avail_reason = self._avail_off, self._avail_ref, self._avail_reason
        h.interval = self.interval
        h.warnings = self.warnings
        h.duplicates_dropped = self.duplicates_dropped
        h.dup_by_file = self.dup_by_file
        h.dup_same_file = self.dup_same_file
        h.file_info = self.file_info
        h.unfiltered = self.unfiltered
        h.slice_of = self.slice_of or self
        h.firsts_dropped = self.firsts_dropped  # исключённые раньше (--skip-first) первые снимки остаются исключёнными
        for attr in ("_net_roles", "_bond_map", "_bond_src", "_bond_unresolved", "_page_info", "_mount_info"):
            if getattr(self, attr, None) is not None:
                setattr(h, attr, getattr(self, attr))
        idx = [i for i, m in enumerate(mask) if m]
        h.times = [self.times[i] for i in idx]
        h.snap_ids = [self.snap_ids[i] for i in idx]
        h.snap_src = [self.snap_src[i] for i in idx]
        h.snap_iv = [self.snap_iv[i] for i in idx] if self.snap_iv else []
        h.run_ivs = self.run_ivs
        h.columns = self.columns
        h.series = {}
        for sec, cols in self.series.items():
            h.series[sec] = {c: array("d", [arr[i] for i in idx]) for c, arr in cols.items()}
        h.top = [self.top[i] for i in idx]
        h.uarg = [self.uarg[i] for i in idx]
        h.cpu_cores = self.cpu_cores
        return h

    # --- производные ряды ---
    def cpu_busy(self):
        """Busy% = User% + Sys% по CPU_ALL; None если секции нет."""
        u = self.col("CPU_ALL", "User%")
        s = self.col("CPU_ALL", "Sys%")
        if u is None or s is None:
            return None
        return [a + b if (a == a and b == b) else NAN for a, b in zip(u, s)]

    def ncpus(self) -> int:
        c = self.col("CPU_ALL", "CPUs")
        if c is not None:
            v = fmax(c)
            if v == v and v >= 1:
                return int(v)
        s = self.meta.get("cpus", "").strip()
        return (int(s) if s.isdigit() else 0) or len(self.cpu_cores)  # без AAA,cpus и CPU_ALL CPUs — по секциям CPUnnn

    def _file_cols(self, section, names):
        """По индексу файла: какие из колонок names есть в секции section этого файла (множество)."""
        out = []
        for f in self.files:
            sec = f.sections.get(section)
            cols = set(sec.columns) if sec is not None else set()
            out.append({c for c in names if c in cols})
        return out

    @staticmethod
    def _mem_part(v, present):
        """Слагаемое MEM для used/avail: колонки нет в файле снимка или метка nmon «не поддерживается»
        (−1, −0.0) — 0; колонка есть, а значения нет (строка снимка оборвана) — NaN."""
        if v != v:
            return NAN if present else 0.0
        return v if v >= 0 else 0.0

    def mem_used(self):
        """Использовано (MB) = memtotal - memfree - cached - buffers (как 'used' у free). Пустое cached/buffers при
        колонке, которая есть в MEM файла этого снимка (оборванная строка), даёт NaN, а не «cached = 0»;
        значение вне [0, memtotal] — NaN."""
        t = self.col("MEM", "memtotal")
        f = self.col("MEM", "memfree")
        c = self.col("MEM", "cached")
        b = self.col("MEM", "buffers")
        if t is None or f is None:
            return None
        has = self._file_cols("MEM", ("cached", "buffers"))
        part = self._mem_part
        out = []
        for i in range(self.n()):
            fh = has[self.snap_src[i]]
            v = t[i] - f[i] - part(c[i] if c is not None else NAN, "cached" in fh) \
                - part(b[i] if b is not None else NAN, "buffers" in fh)
            out.append(v if 0 <= v <= t[i] else NAN)  # NaN не проходит сравнение
        return out

    def mem_avail(self):
        """Приближение MemAvailable (MB): memfree + buffers + (cached − memshared) + slab reclaimable.
        memshared (Shmem/tmpfs) входит в cached, но не вытесняется; slab reclaimable берётся из VM.
        Неполный снимок: пустое cached/buffers/memshared при колонке, которая есть в MEM файла этого снимка,
        даёт NaN (а не «cached = 0» и ложный провал avail); пустой slab (нет строки VM в снимке) заменяется
        последним значением slab того же файла (медленно меняющийся gauge), без него — NaN.
        Значение вне [0, memtotal] — NaN."""
        f = self.col("MEM", "memfree")
        if f is None:
            return None
        t = self.col("MEM", "memtotal")
        c = self.col("MEM", "cached")
        b = self.col("MEM", "buffers")
        s = self.col("MEM", "memshared")
        slab = self.col("VM", "nr_slab_reclaimable")
        has = self._file_cols("MEM", ("cached", "buffers", "memshared"))
        has_slab = [bool(x) for x in self._file_cols("VM", ("nr_slab_reclaimable",))]
        pk = self.page_kb()
        part = self._mem_part
        last_slab = {}  # индекс файла -> последнее значение slab
        out = []
        for i in range(self.n()):
            fi = self.snap_src[i]
            fh = has[fi]
            cv = part(c[i] if c is not None else NAN, "cached" in fh)
            bv = part(b[i] if b is not None else NAN, "buffers" in fh)
            sv = part(s[i] if s is not None else NAN, "memshared" in fh)
            lv = slab[i] if slab is not None else NAN
            if lv == lv:
                last_slab[fi] = lv
            elif has_slab[fi]:
                lv = last_slab.get(fi, NAN)
                if lv != lv:
                    out.append(NAN)
                    continue
            lv = lv * pk / 1024.0 if lv == lv and lv >= 0 else 0.0
            if cv != cv or bv != bv or sv != sv:
                out.append(NAN)
                continue
            v = f[i] + bv + max(0.0, cv - sv) + lv
            tv = t[i] if t is not None else NAN
            out.append(NAN if tv == tv and not 0 <= v <= tv else v)
        return out

    def _calc_avail_anchor(self):
        """Калибровка avail по MemAvailable из BBBP (вызывается из build(): до --skip-first, --tz-shift и срезов
        по времени, которые её только копируют). Опорный снимок — первый снимок первого запуска nmon в файле,
        откуда взят BBBP /proc/meminfo (снят через 1–2 с после BBBP); если он вытеснен дедупликацией или avail в нём
        пустое — ближайший снимок того же файла и запуска в пределах 2 интервалов, а если снимки этого файла вытеснены
        дедупликацией — снимок другого файла хоста в тот же момент (±0.5 интервала: та же машина, файлы разных машин не
        объединяются). Поправка = max(0, оценка − MemAvailable); если её нет — None и причина в _avail_reason."""
        self._avail_off, self._avail_ref, self._avail_reason = None, None, ""
        ma = self.meminfo().get("MemAvailable")
        if ma is None:
            self._avail_reason = "нет MemAvailable в BBBP"
            return
        av = self.mem_avail()
        if av is None:
            self._avail_reason = "нет данных MEM (memfree)"
            return
        fi = self.bbbp_src.get("/proc/meminfo")
        z0 = [dt for t, dt in self.files[fi].zzzz.items() if _run_of(t) == 0] if fi is not None else []
        if not z0:
            self._avail_reason = "нет снимка рядом с BBBP"
            return
        dt0 = min(z0)
        lim = 2.0 * (self.files[fi].interval or self.step())
        best = None
        for i, (dt, src) in enumerate(zip(self.times, self.snap_src)):
            if src != fi or _run_of(self.snap_ids[i]) or av[i] != av[i]:
                continue
            d = abs((dt - dt0).total_seconds())
            if d <= lim and (best is None or d < best[0]):
                best = (d, i)
        if best is None:
            # снимки файла BBBP вытеснены дедупликацией: тот же момент в другом файле хоста
            half = 0.5 * (self.files[fi].interval or self.step())
            for i, dt in enumerate(self.times):
                d = abs((dt - dt0).total_seconds())
                if av[i] == av[i] and d <= half and (best is None or d < best[0]):
                    best = (d, i)
        if best is None:
            self._avail_reason = "нет снимка рядом с BBBP"
            return
        i = best[1]
        est, mam = av[i], ma / 1024.0
        self._avail_off = max(0.0, est - mam)
        self._avail_ref = {"file": self.snap_src[i], "snap": self.snap_ids[i], "est": est, "memavail": mam}
        if est <= mam:
            self._avail_reason = "оценка не выше MemAvailable — поправка 0"

    def mem_avail_anchor(self):
        """Опорный снимок калибровки avail: {file, snap, time, est (оценка avail, MB), memavail (MB)} или None."""
        r = self._avail_ref
        if r is None:
            return None
        return dict(r, time=self.files[r["file"]].zzzz.get(r["snap"]))

    def mem_avail_reason(self) -> str:
        """Почему поправки avail нет или она 0 ('' — поправка есть)."""
        return self._avail_reason

    def mem_avail_offset(self):
        """Поправка оценки avail по MemAvailable ядра (оценка − MemAvailable в снимке рядом с BBBP), MB; 0, если
        неизвестна. Вычисляется один раз в build() и не зависит от окна --from/--to/--around/--skip-first."""
        return self._avail_off or 0.0

    def mem_avail_calibrated(self):
        """avail с поправкой на MemAvailable ядра на старте (ближе к тому, что видит ядро)."""
        av = self.mem_avail()
        if av is None:
            return None
        off = self.mem_avail_offset()
        return [v - off if v == v else NAN for v in av]

    def getconf_pagesize(self):
        """Размер страницы из BBBP 'getconf PAGESIZE', байт (степень двойки 4096..1048576); None, если блока нет."""
        for line in self.bbbp.get("getconf PAGESIZE", []):
            s = line.strip()
            if s.isdigit():
                v = int(s)
                return v if 4096 <= v <= 1048576 and v & (v - 1) == 0 else None
        return None

    def page_size_info(self):
        """(размер страницы, KB; источник): getconf PAGESIZE из BBBP; без него — SReclaimable (meminfo) /
        nr_slab_reclaimable первого снимка, округлённое до 4/16/64 KB; иначе 4 KB."""
        if getattr(self, "_page_info", None) is not None:
            return self._page_info
        info = (4.0, "по умолчанию")
        gp = self.getconf_pagesize()
        if gp:
            info = (gp / 1024.0, "getconf PAGESIZE")
        else:
            sr = self.meminfo().get("SReclaimable")
            pages = self.files[0].first_value("VM", "nr_slab_reclaimable") if self.files else NAN
            if sr and pages == pages and pages > 0 and 2.0 <= sr / pages <= 128.0:
                kb = min((4.0, 16.0, 64.0), key=lambda k: abs(math.log(sr / pages / k)))
                info = (kb, "SReclaimable / nr_slab_reclaimable")
        self._page_info = info
        return info

    def page_kb(self) -> float:
        """Размер страницы памяти, KB (для перевода VM nr_* из страниц в MB)."""
        return self.page_size_info()[0]

    def top_in_files(self) -> bool:
        """Есть ли секция TOP в файлах хоста (в отличие от any(self.top) — с учётом снимков вне окна времени)."""
        return any(f.top for f in self.files)

    def boot_times(self):
        """Моменты загрузки ОС по файлам и запускам nmon (по возрастанию, без повторов)."""
        boots = sorted({x["boottime"] for x in self.file_info if x["boottime"] is not None})
        if not boots:
            b = parse_boottime(self.meta.get("boottime", ""))
            boots = [b] if b else []
        return boots

    def kernel_version(self):
        """(major, minor) из AAA,OS; (0, 0) если не разобрать."""
        m = re.search(r"\b(\d+)\.(\d+)\.\d+", self.meta.get("OS", ""))
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    def first_snapshot_indices(self):
        """Индексы снимков ряда, являющихся первым снимком своего файла или запуска в файле (наименьший номер Tnnnn
        запуска, обычно T0001: интервал неполный). Ищется по номеру снимка, а не по времени: если часы шли назад,
        самый ранний по времени снимок — не первый. Первый снимок, которого нет в ряду (окно времени, --skip-first,
        вытеснен дедупликацией), не учитывается."""
        pos = {(t, src): i for i, (t, src) in enumerate(zip(self.snap_ids, self.snap_src))}
        out = set()
        for fi, f in enumerate(self.files):
            by_run = {}
            for t in f.zzzz:
                r = _run_of(t)
                if r not in by_run or _tnum(t) < _tnum(by_run[r]):
                    by_run[r] = t
            for t in by_run.values():
                i = pos.get((t, fi))
                if i is not None:
                    out.add(i)
        return out

    def without_first(self):
        """Копия без первых снимков файлов и запусков (для статистик, чувствительных к неполному интервалу). Если в
        ряду нет других снимков — сам хост (статистике больше не на чем строиться). Итог — в атрибутах результата:
        firsts_dropped — сколько первых снимков исключено, firsts_kept — сколько оставлено из-за нехватки других
        снимков (тогда примечания «без первых снимков» неверны — см. _t1_note)."""
        firsts = self.first_snapshot_indices()
        if not firsts or self.n() <= len(firsts):
            self.firsts_kept = len(firsts)
            return self
        h = self.slice([i not in firsts for i in range(self.n())])
        h.firsts_dropped = self.firsts_dropped + len(firsts)
        return h

    def swap_used(self):
        t = self.col("MEM", "swaptotal")
        f = self.col("MEM", "swapfree")
        if t is None or f is None:
            return None
        return [a - b if (a == a and b == b) else NAN for a, b in zip(t, f)]

    def net_ifaces(self):
        names = []
        for c in self.cols("NET"):
            m = re.match(r"^(.*)-(read|write)-KB/s$", c)
            if m and m.group(1) not in names:
                names.append(m.group(1))
        return names

    def _net_sums(self, i):
        """(Σ rx, Σ tx) интерфейса по всем снимкам, KB/s·снимков (0, если колонки нет)."""
        sr, sw = fsum(self.col("NET", f"{i}-read-KB/s")), fsum(self.col("NET", f"{i}-write-KB/s"))
        return (sr if sr == sr else 0.0), (sw if sw == sw else 0.0)

    def net_roles(self):
        """Роль каждого интерфейса: lo | bond | bond-slave | bond-slave (по трафику) | vlan | bridge | virtual | nic.
        vlan (<parent>.<N> поверх интерфейса из NET, трафик не больше родительского), bridge (br<N>, bridge<N>, ovs-*
        при наличии NIC/bond с трафиком) и virtual (veth, docker, tap, tun, vxlan, cali… ) несут трафик нижележащего
        интерфейса и, как lo и слейвы, не входят в итог хоста. Слейвы — по флагам SLAVE/MASTER из ifconfig; bond без
        флагов (нет ifconfig, team<N>) получает слейвов по совпадению рядов rx/tx во времени (_match_bond).
        Роли и состав bond определяются по полному ряду хоста (до фильтра --from/--to)."""
        if getattr(self, "_net_roles", None) is not None:
            return self._net_roles
        base = self.unfiltered if self.unfiltered is not None else self.slice_of  # срез (окно, без T0001) — по полному ряду
        if base is not None and base is not self:
            self._net_roles = base.net_roles()
            self._bond_map, self._bond_src, self._bond_unresolved = base._bond_map, base._bond_src, base._bond_unresolved
            return self._net_roles
        roles = {}
        ifaces = self.net_ifaces()
        ifc = {x["name"]: x for x in self.ifconfig()}
        flags = {n: set(x["flags"].replace(" ", ",").split(",")) - {""} for n, x in ifc.items()}
        sums = {i: self._net_sums(i) for i in ifaces}
        bridges = []
        for i in ifaces:
            fl = flags.get(i, set())
            m = re.fullmatch(r"(.+)\.(\d+)", i)
            parent = m.group(1) if m and m.group(1) in sums else None
            if _is_loopback(i, fl):
                roles[i] = "lo"
            elif parent and sums[i][0] <= 1.05 * sums[parent][0] and sums[i][1] <= 1.05 * sums[parent][1]:
                # VLAN поверх интерфейса из NET; если трафик потомка больше родительского (дочерние разделы IPoIB
                # и т.п. — свои счётчики), интерфейс остаётся nic
                roles[i] = "vlan"
            elif re.match(r"^(veth|docker\d|br-|virbr|vnet|tap|tun|cali|flannel|cni|vxlan|weave|cilium|lxc|kube-)", i):
                roles[i] = "virtual"
            elif re.match(r"^((br|bridge)\d+|ovs-)", i):
                roles[i] = "bridge"
                bridges.append(i)
            elif "SLAVE" in fl:
                roles[i] = "bond-slave"
            elif "MASTER" in fl or (i.startswith("bond") and not m) or re.fullmatch(r"team\d+", i):
                roles[i] = "bond"
            else:
                roles[i] = "nic"
        # мост исключается из итога, только если его трафик есть на нижележащем интерфейсе
        if bridges and not any(roles[i] in ("nic", "bond", "bond-slave") and sum(sums[i]) > 0 for i in ifaces):
            for i in bridges:
                roles[i] = "nic"
        members, src, unresolved = {}, {}, []
        bonds = sorted([i for i in ifaces if roles[i] == "bond"], key=lambda b: -sum(sums[b]))
        fslaves = [i for i in ifaces if roles[i] == "bond-slave"]
        masters = [b for b in bonds if "MASTER" in flags.get(b, ())]
        if fslaves and bonds:
            owners = masters or bonds
            if len(owners) == 1:
                members[owners[0]], src[owners[0]] = list(fslaves), "ifconfig"
            else:
                # несколько bond: слейв принадлежит bond с тем же MAC; остальные (balance-tlb/alb, fail_over_mac) —
                # подбор по рядам среди оставшихся слейвов
                for b in owners:
                    mac = ifc.get(b, {}).get("mac")
                    ms = [s for s in fslaves if mac and ifc.get(s, {}).get("mac") == mac]
                    if ms:
                        members[b], src[b] = ms, "mac"
                rest = [s for s in fslaves if not any(s in v for v in members.values())]
                for b in owners:
                    if not rest:
                        break
                    sel, _err = self._match_bond(b, rest, fixed=members.get(b, []))
                    if sel:
                        members[b] = members.get(b, []) + sel
                        src[b] = "трафик"
                        rest = [s for s in rest if s not in sel]
        for b in bonds:
            if b in members or ("MASTER" in flags.get(b, ()) and fslaves):
                continue
            # нет флагов (нет ifconfig, team<N>, в ifconfig нет ни одного SLAVE): слейвы — NIC, ряды rx/tx которых
            # в сумме совпадают с рядами bond
            taken = {s for v in members.values() for s in v}
            cands = [i for i in ifaces if roles[i] == "nic" and sum(sums[i]) > 0 and i not in taken]
            sel, _err = self._match_bond(b, cands)
            if sel:
                members[b], src[b] = sel, "трафик"
                for s in sel:
                    roles[s] = "bond-slave (по трафику)"
            elif sum(sums[b]) > 0:
                unresolved.append(b)
        self._net_roles = roles
        self._bond_map, self._bond_src, self._bond_unresolved = members, src, unresolved
        return roles

    def _match_bond(self, bond, cands, fixed=()):
        """Слейвы bond по совпадению рядов: подмножество S кандидатов с минимальной ошибкой
        E = Σ_t(|b_rd − Σ_S rd| + |b_wr − Σ_S wr|) / Σ_t(|b_rd| + |b_wr|) (fixed входят в сумму всегда; снимки с NaN
        пропускаются). Кандидат не может превышать bond: i(t) ≤ 1.02·b(t) + 1 KB/s в ≥ 95 % снимков по rx и tx.
        До 8 кандидатов — полный перебор (при почти равной ошибке, ±0.01, — меньшее подмножество), больше — жадно.
        Возвращает (S, E); S = [], если min E > 0.10."""
        brd, bwr = self.col("NET", f"{bond}-read-KB/s"), self.col("NET", f"{bond}-write-KB/s")
        if brd is None or bwr is None:
            return [], NAN
        n = self.n()

        def ser(i):
            rd, wr = self.col("NET", f"{i}-read-KB/s"), self.col("NET", f"{i}-write-KB/s")
            return (list(rd) if rd is not None else [NAN] * n), (list(wr) if wr is not None else [NAN] * n)

        base_rd, base_wr = [0.0] * n, [0.0] * n
        for i in fixed:
            rd, wr = ser(i)
            base_rd = [a + b for a, b in zip(base_rd, rd)]
            base_wr = [a + b for a, b in zip(base_wr, wr)]
        pool = []
        for i in cands:
            rd, wr = ser(i)
            ok = tot = 0
            for k in range(n):
                if rd[k] == rd[k] and wr[k] == wr[k] and brd[k] == brd[k] and bwr[k] == bwr[k]:
                    tot += 1
                    ok += rd[k] <= 1.02 * brd[k] + 1 and wr[k] <= 1.02 * bwr[k] + 1
            if tot and ok >= 0.95 * tot:
                pool.append((i, rd, wr))

        def add(s, a):
            return [x + y for x, y in zip(s, a)]

        def err(srd, swr):
            num = den = 0.0
            for k in range(n):
                d = abs(brd[k] - srd[k]) + abs(bwr[k] - swr[k])
                if d == d:
                    num += d
                    den += abs(brd[k]) + abs(bwr[k])
            return num / den if den > 0 else NAN

        best = (err(base_rd, base_wr), [])
        if len(pool) <= 8:
            # суммы подмножеств по маске: сумма маски без младшего бита + этот кандидат
            sums = {0: (base_rd, base_wr)}
            tried = [best] if best[0] == best[0] else []
            for mask in range(1, 1 << len(pool)):
                j = (mask & -mask).bit_length() - 1
                prd, pwr = sums[mask & (mask - 1)]
                sums[mask] = (add(prd, pool[j][1]), add(pwr, pool[j][2]))
                e = err(*sums[mask])
                if e == e:
                    tried.append((e, [pool[q] for q in range(len(pool)) if mask >> q & 1]))
            if tried:
                e_min = min(t[0] for t in tried)
                best = min((t for t in tried if t[0] <= e_min + 0.01), key=lambda t: (len(t[1]), t[0]))
        else:
            cur, crd, cwr = [], base_rd, base_wr
            while True:
                used = {c[0] for c in cur}
                opts = [(err(add(crd, p[1]), add(cwr, p[2])), p) for p in pool if p[0] not in used]
                opts = [o for o in opts if o[0] == o[0]]
                if not opts:
                    break
                e, p = min(opts, key=lambda x: x[0])
                if best[0] != best[0] or e < best[0] - 1e-9:
                    cur, crd, cwr = cur + [p], add(crd, p[1]), add(cwr, p[2])
                    best = (e, list(cur))
                else:
                    break
        e, sel = best
        if e != e or e > 0.10:
            return [], e
        return [p[0] for p in sel], e

    def _bond_members(self):
        """bond -> список его слейвов (см. net_roles): по флагам SLAVE (один bond), по общему MAC (несколько bond),
        иначе — по совпадению рядов. Источник состава — self._bond_src[bond]: 'ifconfig' | 'mac' | 'трафик';
        self._bond_unresolved — bond с трафиком, у которых слейвы по рядам не определены."""
        self.net_roles()
        return self._bond_map

    def bond_of(self, slave):
        """Bond, которому принадлежит слейв: по _bond_members, а если bond на хосте один — он; иначе None."""
        for b, ms in self._bond_members().items():
            if slave in ms:
                return b
        bonds = [i for i, r in self.net_roles().items() if r == "bond"]
        return bonds[0] if len(bonds) == 1 else None

    def net_primary_ifaces(self):
        """Интерфейсы без lo, слейвов bond, VLAN, мостов и виртуальных (чтобы не считать трафик дважды)."""
        roles = self.net_roles()
        return [i for i in self.net_ifaces() if roles.get(i) in ("bond", "nic")]

    def net_counters(self):
        """Накопительные счётчики интерфейсов на старте: из ifconfig, а если его нет — из /proc/net/dev (BBBP).
        Кроме packets/bytes/errors/dropped — overruns (fifo), frame, carrier, collisions (только для показа)."""
        out = {i["name"]: i for i in self.ifconfig()}
        for line in self.bbbp.get("/proc/net/dev", []):
            m = re.match(r"^\s*(\S+?):\s*(.*)$", line)
            if not m or m.group(1) in ("face", "Inter-|"):
                continue
            p = m.group(2).split()
            if len(p) < 16:
                continue
            try:
                vals = [int(x) for x in p[:16]]
            except ValueError:
                continue
            name = m.group(1)
            if name in out:
                continue
            out[name] = {"name": name, "flags": "", "mtu": NAN, "inet": "", "mac": "",
                         "rx_packets": vals[1], "rx_bytes": vals[0], "tx_packets": vals[9], "tx_bytes": vals[8],
                         "rx_errors": vals[2], "rx_dropped": vals[3], "tx_errors": vals[10], "tx_dropped": vals[11],
                         "rx_overruns": vals[4], "rx_frame": vals[5], "tx_overruns": vals[12],
                         "tx_collisions": vals[13], "tx_carrier": vals[14], "source": "/proc/net/dev"}
        return out

    def net_total(self, direction: str, packets=False):
        """Сумма по основным интерфейсам (read|write): KB/s из NET, при packets=True — pkt/s из NETPACKET.
        Снимок без данных остаётся NaN; NaN и тогда, когда у основного интерфейса нет значения в снимке, а в других
        снимках того же файла значения есть (короткая строка) — иначе в итог попал бы ложный ноль. Интерфейс без
        единого значения в файле (колонка есть, данных нет) в итог по снимкам этого файла не входит и его не обнуляет."""
        sec, suffix = ("NETPACKET", "/s") if packets else ("NET", "-KB/s")
        out = array("d", [NAN]) * self.n()
        holes = [False] * self.n()
        anyd = False
        for i in self.net_primary_ifaces():
            col = f"{i}-{direction}{suffix}"
            arr = self.col(sec, col)
            if arr is None:
                continue
            anyd = True
            with_data = {self.snap_src[k] for k, v in enumerate(arr) if v == v}  # файлы, где у колонки есть значения
            for k, v in enumerate(arr):
                if v == v:
                    out[k] = (out[k] if out[k] == out[k] else 0.0) + v
                elif self.snap_src[k] in with_data:
                    holes[k] = True
        for k, h in enumerate(holes):
            if h:
                out[k] = NAN
        return out if anyd else None

    def net_pkt_size(self, direction: str, ifaces=None):
        """Средний размер пакета по снимкам, байт: Σ KB/s × 1024 / Σ pkt/s (по основным интерфейсам или ifaces);
        NaN, если пакетов 0 или NETPACKET нет."""
        if ifaces is None:
            kb, pk = self.net_total(direction), self.net_total(direction, packets=True)
        else:
            kb = _sum_cols(self, "NET", [f"{i}-{direction}-KB/s" for i in ifaces])
            pk = _sum_cols(self, "NETPACKET", [f"{i}-{direction}/s" for i in ifaces])
        if kb is None or pk is None or not clean(pk):
            return None
        return [a * 1024.0 / b if a == a and b == b and b > 0 else NAN for a, b in zip(kb, pk)]

    def disk_devices(self):
        for s in DISK_SECTIONS:
            if s in self.columns:
                return list(self.columns[s])
        return []

    def physical_disks(self):
        """Устройства верхнего уровня: без разделов и без dm-*/md*/loop* (дублируют физические)."""
        devs = self.disk_devices()
        names = set(devs)
        out = []
        for d in devs:
            if re.match(r"^(dm-\d+|md\d+(p\d+)?|loop\d+(p\d+)?|sr\d+|fd\d+|ram\d+|zram\d+)$", d):
                continue
            # раздел: имя = имя другого устройства + 'p<N>' (nvme0n1p1, mmcblk0p1, cciss/c0d0p1) или + '<N>' (sda1)
            base_p = re.sub(r"p\d+$", "", d)
            base_n = re.sub(r"\d+$", "", d)
            if base_p != d and base_p in names:
                continue
            if base_n != d and base_n in names and not re.match(r"^nvme\d+n$", base_n):
                continue
            out.append(d)
        return out

    def disk_total(self, section: str, devices=None):
        """Сумма по устройствам (по умолчанию — физические, без двойного счёта)."""
        if section not in self.series:
            return None
        devs = devices if devices is not None else self.physical_disks()
        out = array("d", [NAN]) * self.n()
        anyd = False
        for d in devs:
            arr = self.series[section].get(d)
            if arr is None:
                continue
            anyd = True
            for k, v in enumerate(arr):
                if v == v:
                    out[k] = (out[k] if out[k] == out[k] else 0.0) + v
        return out if anyd else None

    def disk_max_busy(self):
        """Максимальная занятость среди физических дисков (physical_disks: без разделов, dm-*, md*; если их не выделить —
        среди всех устройств) в каждом снимке + имя устройства. Разделы и dm-* дублируют свой диск, а busy раздела в
        nmon бывает выше, чем у самого диска — область та же, что у правил DISK_BUSY*."""
        if "DISKBUSY" not in self.series:
            return None, None
        n = self.n()
        best = array("d", [NAN]) * n
        who = [""] * n
        ser = self.series["DISKBUSY"]
        devs = [d for d in self.physical_disks() if d in ser] or list(ser)
        for d in devs:
            arr = ser[d]
            for k, v in enumerate(arr):
                if v == v and (best[k] != best[k] or v > best[k]):
                    best[k] = v
                    who[k] = d
        return best, who

    def dm_map(self):
        """dm-N -> имя LV (по ls -l /dev/mapper из BBBP)."""
        out = {}
        for line in self.bbbp.get("/dev/mapper", []):
            m = re.search(r"\s(\S+)\s+->\s+\.\./(dm-\d+)\s*$", line)
            if m:
                out[m.group(2)] = m.group(1)
        return out

    def mounts(self):
        """Точки монтирования из /bin/mount (BBBP)."""
        out = []
        for line in self.bbbp.get("/bin/mount", []):
            m = re.match(r"^(\S+) on (\S+) type (\S+) \((.*)\)\s*$", line)
            if m:
                out.append({"device": _bbbp_dev(m.group(1)), "mount": m.group(2), "fstype": m.group(3), "options": m.group(4)})
        return out

    def mount_info(self):
        """Точка монтирования -> (тип ФС, опции) по /bin/mount; при повторном монтировании — последнее. Кэшируется."""
        if getattr(self, "_mount_info", None) is None:
            self._mount_info = {m["mount"]: (m["fstype"], m["options"]) for m in self.mounts()}
        return self._mount_info

    def df(self):
        """df -m из BBBP. Длинное имя устройства старый df (без -P) переносит на отдельную строку — собираем запись из двух."""
        out = []
        pending = None
        for line in self.bbbp.get("/bin/df-m", []):
            m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S+)\s*$", line)
            if m:
                dev, nums = m.group(1), m.groups()[1:]
            else:
                m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S+)\s*$", line) if pending else None
                if not m:
                    m1 = re.match(r"^(\S+)\s*$", line)
                    pending = m1.group(1) if m1 and m1.group(1) != "Filesystem" else None
                    continue
                dev, nums = pending, m.groups()
            pending = None
            out.append({"filesystem": _bbbp_dev(dev), "size_mb": int(nums[0]), "used_mb": int(nums[1]),
                        "avail_mb": int(nums[2]), "use_pct": int(nums[3]), "mount": nums[4]})
        return out

    def lsblk(self):
        """lsblk из BBBP: name, major, minor, size, type, mount, parent, root (физический диск) — по дереву отступов."""
        out = []
        stack = []  # (depth, name)
        for line in self.bbbp.get("lsblk", []):
            if line.startswith("NAME"):
                continue
            m = re.match(r"^([^A-Za-z0-9]*)(\S+)\s+(\d+):(\d+)\s+\d+\s+(\S+)\s+\d+\s+(\S+)\s*(\S*)\s*$", line)
            if not m:
                continue
            depth = len(m.group(1)) // 2
            name = m.group(2)
            while stack and stack[-1][0] >= depth:
                stack.pop()
            parent = stack[-1][1] if stack else ""
            root = stack[0][1] if stack else name
            stack.append((depth, name))
            out.append({"name": name, "major": int(m.group(3)), "minor": int(m.group(4)),
                        "size": m.group(5), "type": m.group(6), "mount": m.group(7) or "",
                        "parent": parent, "root": root})
        return out

    def partitions(self):
        """/proc/partitions: name -> (major, minor, blocks_kb)."""
        out = {}
        for line in self.bbbp.get("/proc/partitions", []):
            m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$", line)
            if m:
                out[m.group(4)] = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return out

    def device_map(self):
        """Карта: устройство nmon -> dm/LV -> точка монтирования -> fs -> размер. LV/RAID/multipath поверх нескольких
        дисков стоит в дереве lsblk под каждым из них: phys/parent — все корни/родители через запятую, phys_list — списком."""
        dm = self.dm_map()
        lsb = self.lsblk()
        lsb_by_name = defaultdict(list)
        lsb_by_majmin = defaultdict(list)
        for r in lsb:
            lsb_by_name[r["name"]].append(r)
            lsb_by_majmin[(r["major"], r["minor"])].append(r)
        mount_by_dev = {}
        for m in self.mounts():
            mount_by_dev[m["device"]] = m
            mount_by_dev[os.path.basename(m["device"])] = m
        dfrows = {r["mount"]: r for r in self.df()}
        parts = self.partitions()
        result = []
        for dev in self.disk_devices():
            lv = dm.get(dev, "")
            entry = {"device": dev, "lv": lv, "mount": "", "fstype": "", "size": "", "type": "", "parent": "", "phys": "",
                     "phys_list": []}
            mm = parts.get(dev)
            rows = []
            if mm:
                rows = lsb_by_majmin.get((mm[0], mm[1]), [])
                entry["size_mb"] = round(mm[2] / 1024.0)
            if not rows:
                rows = lsb_by_name.get(lv) or lsb_by_name.get(dev) or []
            if rows:
                row = rows[0]
                entry["size"] = row["size"]
                entry["type"] = row["type"]
                if "size_mb" not in entry:  # без /proc/partitions — из размера lsblk (например 1.5T, 200M)
                    smb = _parse_size_mb(row["size"])
                    if smb == smb:
                        entry["size_mb"] = round(smb)
                roots = list(dict.fromkeys(r["root"] for r in rows if r["root"] != r["name"] or r["type"] == "disk"))
                entry["phys_list"] = roots
                entry["phys"] = ", ".join(roots)
                entry["parent"] = ", ".join(dict.fromkeys(r["parent"] for r in rows if r["parent"]))
                mount = next((r["mount"] for r in rows if r["mount"]), "")
                if mount:
                    entry["mount"] = mount
            mnt = None
            for key in ([lv, "/dev/mapper/" + lv] if lv else []) + [dev, "/dev/" + dev]:
                if key in mount_by_dev:
                    mnt = mount_by_dev[key]
                    break
            if mnt:
                entry["mount"] = mnt["mount"]
                entry["fstype"] = mnt["fstype"]
                entry["options"] = mnt["options"]
            if entry["mount"] in dfrows:
                d = dfrows[entry["mount"]]
                entry["fs_size_mb"] = d["size_mb"]
                entry["fs_use_pct_start"] = d["use_pct"]
            result.append(entry)
        # Для физических дисков без собственной точки монтирования — точки монтирования потомков (LVM/разделы)
        by_phys = defaultdict(list)
        for r in lsb:
            if r["mount"] and r.get("root") and r["root"] != r["name"] and r["mount"] not in by_phys[r["root"]]:
                by_phys[r["root"]].append(r["mount"])
        for e in result:
            if not e["mount"] and e["device"] in by_phys:
                e["child_mounts"] = by_phys[e["device"]]
        return result

    def procs_by_pid(self, pred=None):
        """pid -> список (индекс снимка, Proc)."""
        out = defaultdict(list)
        for i, procs in enumerate(self.top):
            for p in procs:
                if pred is None or pred(p):
                    out[p.pid].append((i, p))
        return out

    def java_procs(self):
        return self.procs_by_pid(lambda p: p.cmd == "java" or p.cmd.startswith("java"))

    def uarg_cmdlines(self):
        """pid -> (prog, cmdline, first_seen)."""
        out = {}
        for i, rows in enumerate(self.uarg):
            for pid, prog, full in rows:
                if pid not in out:
                    out[pid] = (prog, full, self.times[i])
        return out

    def meminfo(self):
        """/proc/meminfo из BBBP: ключ -> kB (int). Повтор ключа (блок дописан ещё раз, отсортированный файл) не
        перетирает первое значение — оно соответствует старту nmon."""
        return _meminfo_kb(self.bbbp.get("/proc/meminfo", []))

    def mem_format_issue(self) -> str:
        """Почему правила памяти неприменимы: секция MEM есть, но без колонок memtotal/memfree (не Linux-формат,
        например AIX) — текст сообщения; '' — формат Linux или секции MEM нет."""
        if "MEM" in self.series and not ({"memtotal", "memfree"} <= set(self.cols("MEM"))):
            return ("секция MEM без колонок memtotal/memfree (не Linux-формат, вероятно AIX) — анализ памяти и правила "
                    "по ряду MEM не применялись; сырые значения — export --section MEM")
        return ""

    def lscpu(self):
        out = {}
        for line in self.bbbp.get("lscpu", []):
            m = re.match(r"^([^:]+):\s+(.*)$", line)
            if m:
                out[m.group(1).strip()] = m.group(2).strip()
        return out

    def numa_map(self):
        """NUMA node -> список номеров CPU (0-based) из lscpu 'NUMA nodeN CPU(s): 0-7,16-23'."""
        out = {}
        for k, v in self.lscpu().items():
            m = re.match(r"^NUMA node(\d+) CPU\(s\)$", k)
            if m:
                out[int(m.group(1))] = _parse_cpu_list(v)
        return out

    def cpuinfo_topology(self):
        """processor(0-based) -> (physical id, core id) из /proc/cpuinfo."""
        out = {}
        cur = {}
        for line in self.bbbp.get("/proc/cpuinfo", []):
            m = re.match(r"^(processor|physical id|core id)\s*:\s*(\d+)", line)
            if m:
                cur[m.group(1)] = int(m.group(2))
                if m.group(1) == "processor":
                    cur = {"processor": int(m.group(2))}
                    out[cur["processor"]] = cur
        return {p: (d.get("physical id", 0), d.get("core id", p)) for p, d in out.items()}

    def diskstats(self):
        """/proc/diskstats (накопительно с загрузки): name -> dict полей."""
        out = {}
        for line in self.bbbp.get("/proc/diskstats", []):
            p = line.split()
            if len(p) < 14:
                continue
            try:
                vals = [int(x) for x in p[3:14]]
            except ValueError:
                continue
            out[p[2]] = {"reads": vals[0], "reads_merged": vals[1], "sectors_read": vals[2], "ms_reading": vals[3],
                         "writes": vals[4], "writes_merged": vals[5], "sectors_written": vals[6], "ms_writing": vals[7],
                         "in_flight": vals[8], "io_ticks": vals[9], "time_in_queue": vals[10]}
        return out

    def uptime_seconds(self):
        """Аптайм на старте nmon из BBBP uptime ('up 1 day, 21:22' / 'up 3:04' / 'up 5 min')."""
        return _uptime_seconds(self.bbbp.get("uptime", []))

    def load_average(self):
        """Load average 1/5/15 мин на старте nmon из BBBP uptime (десятичная точка или запятая); None, если строки нет."""
        for line in self.bbbp.get("uptime", []):
            m = re.search(r"load averages?:\s*(\d+(?:[.,]\d+)?),?\s+(\d+(?:[.,]\d+)?),?\s+(\d+(?:[.,]\d+)?)", line)
            if m:
                return tuple(float(x.replace(",", ".")) for x in m.groups())
        return None

    def proc_stat(self):
        """/proc/stat из BBBP (накопительно с загрузки ОС до старта nmon): {"cpu": поля суммарной строки,
        "cpus": {номер CPU ОС: поля}, "ctxt", "processes"}; поля user, nice, system, idle, iowait, irq, softirq, steal
        в тиках (недостающие у старых ядер = 0); None, если блока или строк cpu нет."""
        names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
        out = {"cpu": None, "cpus": {}, "ctxt": None, "processes": None}
        for line in self.bbbp.get("/proc/stat", []):
            p = line.split()
            if len(p) < 2:
                continue
            m = re.match(r"^cpu(\d*)$", p[0])
            if m:
                try:
                    vals = [int(x) for x in p[1:1 + len(names)]]
                except ValueError:
                    continue
                d = dict(zip(names, vals + [0] * (len(names) - len(vals))))
                if m.group(1):
                    out["cpus"][int(m.group(1))] = d
                else:
                    out["cpu"] = d
            elif p[0] in ("ctxt", "processes") and p[1].isdigit():
                out[p[0]] = int(p[1])
        return out if out["cpu"] is not None or out["cpus"] else None

    def ifconfig(self):
        """ifconfig из BBBP: список интерфейсов с флагами, mtu, inet, MAC, счётчиками (packets, bytes, errors, dropped,
        overruns, frame, carrier, collisions). Форматы: 'eth0: flags=4163<UP,...>  mtu 1500' (net-tools ≥ 2.0; флаги
        могут быть шестнадцатеричными, как в AIX) и старый 'eth0  Link encap:Ethernet  HWaddr …' со строкой флагов
        'UP BROADCAST RUNNING SLAVE MULTICAST  MTU:1500'. Флаги — строка через запятую; mtu без данных — NaN."""
        out = []
        cur = None
        keys = {"rx": ("packets", "bytes", "errors", "dropped", "overruns", "frame"),
                "tx": ("packets", "bytes", "errors", "dropped", "overruns", "carrier", "collisions")}
        for line in self.bbbp.get("ifconfig", []):
            m = re.match(r"^(\S+): flags=[0-9A-Fa-fx,]+<([^>]*)>(?:\s+mtu\s+(\d+))?", line)
            m_old = None if m else re.match(r"^(\S+)\s+Link encap:", line)
            if m or m_old:
                cur = {"name": (m or m_old).group(1), "flags": m.group(2) if m else "",
                       "mtu": int(m.group(3)) if m and m.group(3) else NAN, "inet": "", "mac": ""}
                for d, ks in keys.items():
                    for k in ks:
                        cur[f"{d}_{k}"] = None
                out.append(cur)
                mm = re.search(r"\bHWaddr\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", line)
                if mm:
                    cur["mac"] = mm.group(1).lower()
                continue
            if cur is None:
                continue
            m = re.match(r"^\s*inet\s+(?:addr:)?(\S+)", line)
            if m:
                cur["inet"] = m.group(1)
            m = re.match(r"^\s*ether\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", line)
            if m:
                cur["mac"] = m.group(1).lower()
            m = re.match(r"^\s+((?:[A-Z][A-Z0-9_]*\s)+)\s*MTU:(\d+)", line)
            if m:  # старый формат: строка флагов
                cur["flags"] = ",".join(m.group(1).split())
                cur["mtu"] = int(m.group(2))
            # 'RX packets 123  bytes 456', 'RX errors 0  dropped 0  overruns 0  frame 0' и старые 'RX packets:123 errors:0
            # dropped:0 overruns:0 frame:0', 'RX bytes:1 (1 B)  TX bytes:2 (2 B)'; 'collisions:0' — отдельной строкой
            for seg in re.finditer(r"\b(RX|TX)\b(.*?)(?=\bTX\b|$)", line):
                d = seg.group(1).lower()
                for k, v in re.findall(r"\b(packets|bytes|errors|dropped|overruns|frame|carrier|collisions)[:\s]\s*(\d+)", seg.group(2)):
                    if k in keys[d]:
                        cur[f"{d}_{k}"] = int(v)
            m = re.match(r"^\s*collisions:(\d+)", line)
            if m:
                cur["tx_collisions"] = int(m.group(1))
        return out


def _parse_cpu_list(s):
    """'0-7,16-23' -> [0..7, 16..23]."""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                pass
        else:
            try:
                out.append(int(part))
            except ValueError:
                pass
    return out


# --------------------------------------------------------------------------
# Загрузка набора файлов
# --------------------------------------------------------------------------


def expand_paths(paths):
    """Файлы, каталоги (рекурсивно *.nmon*), маски (glob)."""
    out = []
    seen = set()
    for p in paths:
        cands = []
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()  # порядок обхода (и суффиксы #k одинаковых имён) не зависит от ФС
                for fn in sorted(files):
                    if re.search(r"\.nmon(\.gz|\.txt|\.csv)?$", fn, re.I):
                        cands.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            cands.append(p)
        else:
            g = sorted(glob.glob(p, recursive=True))
            if not g:
                warn(f"путь не найден: {p}")
            for x in g:
                if os.path.isdir(x):
                    cands.extend(expand_paths([x]))
                else:
                    cands.append(x)
        for c in cands:
            key = os.path.abspath(c)
            if key not in seen:
                seen.add(key)
                out.append(c)
    return out


def _machine_fingerprint(nf):
    """Отпечаток машины по BBBP файла: MAC и IPv4 из ifconfig; без ifconfig — интерфейсы /proc/net/dev,
    MemTotal, модель и число CPU (lscpu). Кэшируется в файле."""
    if getattr(nf, "_fingerprint", None) is not None:
        return nf._fingerprint
    macs, inets = set(), set()
    for line in nf.bbbp.get("ifconfig", []):
        m = re.search(r"(?:^\s*ether|\bHWaddr)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b", line)
        if m and m.group(1) != "00:00:00:00:00:00":
            macs.add(m.group(1).lower())
        m = re.match(r"^\s*inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
        if m and not m.group(1).startswith("127."):
            inets.add(m.group(1))
    ifaces = set()
    for line in nf.bbbp.get("/proc/net/dev", []):
        m = re.match(r"^\s*([^\s:|]+):", line)
        if m:
            ifaces.add(m.group(1))
    memtotal = _meminfo_kb(nf.bbbp.get("/proc/meminfo", [])).get("MemTotal")
    cpu = {}
    for line in nf.bbbp.get("lscpu", []):
        m = re.match(r"^(Model name|CPU\(s\)):\s+(.*)$", line)
        if m:
            cpu.setdefault(m.group(1), m.group(2).strip())
    nf._fingerprint = {"macs": macs, "inets": inets, "ifaces": ifaces, "memtotal": memtotal,
                       "model": cpu.get("Model name"), "cpus": cpu.get("CPU(s)")}
    return nf._fingerprint


def _same_machine(a, b):
    """Отпечаток подтверждает одну машину: в ifconfig обоих файлов есть общие MAC (без MAC — общие IPv4)."""
    fa, fb = _machine_fingerprint(a), _machine_fingerprint(b)
    if fa["macs"] and fb["macs"]:
        return bool(fa["macs"] & fb["macs"])
    return bool(fa["inets"] and fb["inets"] and fa["inets"] & fb["inets"])


def _different_machines(a, b):
    """Причина считать два файла с одинаковым AAA,host снятыми на разных машинах ('' — различий не видно).
    Вызывается для файлов с перекрывающимися периодами: на одной машине одновременно работающие nmon
    видят одни и те же интерфейсы, память и boottime."""
    fa, fb = _machine_fingerprint(a), _machine_fingerprint(b)
    if fa["macs"] and fb["macs"]:
        if not fa["macs"] & fb["macs"]:
            return "нет общих MAC-адресов в ifconfig"
    elif fa["inets"] and fb["inets"]:
        if not fa["inets"] & fb["inets"]:
            return "нет общих IP-адресов в ifconfig"
    else:
        for key, label in (("memtotal", "MemTotal"), ("model", "модель CPU"), ("cpus", "число CPU")):
            if fa[key] and fb[key] and fa[key] != fb[key]:
                return f"различается {label} (BBBP)"
        # набор интерфейсов на одной машине может меняться (veth контейнеров), поэтому — только без общих имён
        ia, ib = fa["ifaces"] - {"lo"}, fb["ifaces"] - {"lo"}
        if ia and ib and not ia & ib:
            return "нет общих интерфейсов в /proc/net/dev"
    ba, bb = _boot_of(a.meta, a.bbbp)[0], _boot_of(b.meta, b.bbbp)[0]
    if ba and bb and abs((ba - bb).total_seconds()) > 120:
        return f"разный boottime: {ts(ba)} и {ts(bb)}"
    return ""


def _machine_groups(files):
    """Файлы одного AAA,host -> группы по машинам: [{"files": [...], "why": причина отличия от первой группы}].
    Файлы перебираются по времени начала; файл входит в первую группу, ни с одним файлом которой не конфликтует
    (перекрытие периодов > 2 интервалов при различающемся отпечатке машины, _different_machines), а если таких групп
    несколько — в ту, где отпечаток подтверждает ту же машину (_same_machine). Последовательные файлы одной машины
    поэтому объединяются, даже если рядом есть файлы другой машины с тем же именем."""
    periods = {id(nf): (min(nf.zzzz.values()), max(nf.zzzz.values())) for nf in files if nf.zzzz}

    def conflict(a, b):
        if id(a) not in periods or id(b) not in periods:
            return ""
        (sa, ea), (sb, eb) = periods[id(a)], periods[id(b)]
        if (min(ea, eb) - max(sa, sb)).total_seconds() <= 2 * max(a.interval, b.interval, 1.0):
            return ""
        return _different_machines(a, b)

    groups = []
    for nf in sorted(files, key=lambda f: (periods.get(id(f), (datetime.min,))[0], f.path)):
        ok, why = [], ""
        for g in groups:
            w = next((x for x in (conflict(nf, m) for m in g["files"]) if x), "")
            if w:
                why = why or w
            else:
                ok.append(g)
        if ok:
            g = ok[0] if len(ok) == 1 else next((g for g in ok if any(_same_machine(nf, m) for m in g["files"])), ok[0])
            g["files"].append(nf)
        else:
            groups.append({"files": [nf], "why": why})
    return groups


def _looks_like_nmon(nf) -> bool:
    """Похоже ли содержимое на файл nmon: есть строки AAA, ZZZZ, TOP/UARG или хотя бы одна известная секция
    (иначе — двоичный мусор или посторонний CSV)."""
    return bool(nf.meta or nf.zzzz or nf.top or nf.uarg or any(
        s in SECTION_INFO or re.match(r"^CPU\d+$", s) or Host._base_name(s) in SECTION_INFO or s in AIX_SECTIONS
        for s in nf.sections))


RUN_DETECT_PREFIXES = ("обнаружен повторный запуск nmon", "повтор снимка", "запуск #")  # предупреждения о запусках #N


def _split_runs(nf):
    """Файл из нескольких запусков nmon разных хостов (AAA,host различается, например cat a.nmon b.nmon разных
    узлов) -> по файлу на запуск: путь «файл#N», свои AAA и BBBP, ключи снимков без суффикса '#N', колонки секций —
    по заголовку своего запуска. Файл, все запуски которого сняты с одного хоста, возвращается как есть."""
    runs = sorted({0} | {_run_of(t) for t in nf.snapshot_ids()} | set(nf.runs))
    meta_of = {r: (nf.meta if r == 0 else nf.runs.get(r, {})) for r in runs}
    names = {r: meta_of[r].get("host", "").strip() for r in runs}
    known = {h for h in names.values() if h}
    if len(runs) < 2 or len(known) < 2:
        return [nf]
    base = os.path.basename(nf.path)
    msg = (f"в файле {base} запуски nmon разных хостов ({', '.join(sorted(known))}): файл разделён по запускам "
           f"({base}#1 … {base}#{len(runs)}), каждый анализируется как файл своего хоста")
    out = []
    for r in runs:
        v = NmonFile(f"{nf.path}#{r + 1}")
        v.meta = dict(meta_of[r])
        v.bbbp = nf.bbbp if r == 0 else nf.bbbp_runs.get(r, {})
        v.bbbp_order = list(nf.bbbp_order) if r == 0 else list(v.bbbp)
        key = lambda t: t.split("#", 1)[0]  # noqa: E731
        for name, sec in nf.sections.items():
            hdr = sec.run_cols.get(r) or (sec.columns[:sec.base_width] if sec.base_width else sec.columns)
            idx = [sec.columns.index(c) for c in hdr]
            rows = {key(t): [vals[i] for i in idx] for t, vals in sec.rows.items() if _run_of(t) == r}
            if rows or (r == 0 and not sec.rows):
                s = RawSection(name)
                s.title, s.columns, s.rows = sec.title, list(hdr), rows
                v.sections[name] = s
        v.zzzz = {key(t): dt for t, dt in nf.zzzz.items() if _run_of(t) == r}
        v.top = defaultdict(list, {key(t): p for t, p in nf.top.items() if _run_of(t) == r})
        v.uarg = defaultdict(list, {key(t): u for t, u in nf.uarg.items() if _run_of(t) == r})
        v.top_columns, v.uarg_columns = nf.top_columns, nf.uarg_columns
        v.incomplete = {key(t) for t in nf.incomplete if _run_of(t) == r}
        v.sorted_file = nf.sorted_file
        v.truncated = nf.truncated and r == runs[-1]
        if r == 0:
            v.line_count, v.bad_lines, v.time_backwards = nf.line_count, nf.bad_lines, nf.time_backwards
            v.zzzz_estimated, v.untimed = nf.zzzz_estimated, nf.untimed
            v.warnings = [w for w in nf.warnings if not w.startswith(RUN_DETECT_PREFIXES)]
        v.warnings.append(msg)
        v.split_note = msg
        out.append(v)
    return out


def load_hosts(paths, host_filter=None, no_merge=False, verbose=False, skip_first=False, tz_shift=None):
    """Файлы -> хосты. Файлы группируются по AAA,host и объединяются (по машинам — _machine_groups; --no-merge —
    каждый файл отдельно как host:имя_файла, при одинаковом имени — с суффиксом #k). Фильтр --host сопоставляется с
    итоговым именем хоста (как в выводе, в том числе host:имя_файла) и с AAA,host."""
    files = expand_paths(paths)
    if not files:
        raise SystemExit("ERROR: не найдено ни одного файла nmon")
    by_name = {}
    pending = []  # (файлы, сообщение): WARN печатается, только если файл попал в выбранные --host хосты
    for path in files:
        try:
            nf = parse_nmon_file(path)
        except OSError as e:
            warn(f"не удалось прочитать {path}: {e}")
            continue
        if not _looks_like_nmon(nf):
            warn(f"{path}: не похоже на файл nmon (нет строк AAA/ZZZZ и известных секций) — пропущен")
            continue
        parts = _split_runs(nf)
        if nf.sorted_multirun:
            pending.append((parts, f"{path}: {MSG_SORTED_MULTIRUN}"))
        if len(parts) > 1:
            pending.append((parts, parts[0].split_note))
        if verbose:
            sys.stderr.write(f"parsed {path}: host={nf.host} snapshots={len(nf.zzzz)} "
                             f"sections={len(nf.sections)} bad_lines={nf.bad_lines}\n")
        for p in parts:
            by_name.setdefault(p.host, []).append(p)
    hosts = {}
    aaa_of = {}  # итоговое имя -> AAA,host

    def register(nn, aaa, group):
        b, k = nn, 2
        while nn in hosts:
            nn = f"{b}#{k}"
            k += 1
        hosts[nn] = Host(nn)
        hosts[nn].files.extend(group)
        aaa_of[nn] = aaa
        return nn

    for name, fl in by_name.items():
        if no_merge:
            for nf in fl:
                register(f"{name}:{os.path.basename(nf.path)}", name, [nf])
            continue
        # Одинаковый AAA,host у разных машин (hostname не задан, клоны ВМ, контейнеры): перекрывающиеся файлы
        # с разными MAC/IP/памятью/boottime не объединяем — иначе данные второй машины ушли бы в «дубликаты»
        groups = _machine_groups(fl) if len(fl) > 1 else [{"files": fl, "why": ""}]
        if len(groups) == 1:
            register(name, name, fl)
            continue
        named = [(register(f"{name}:{os.path.basename(g['files'][0].path)}", name, g["files"]), g) for g in groups]
        why = next((g["why"] for g in groups if g["why"]), "")
        msg = (f"файлы с одинаковым AAA,host ({name}) относятся к разным машинам ({why}); объединение между машинами "
               f"отключено — хосты: " + "; ".join(f"{nn} ({', '.join(os.path.basename(f.path) for f in g['files'])})"
                                                 for nn, g in named))
        pending.append((fl, msg))
        for g in groups:
            for nf in g["files"]:
                nf.warnings.append(msg)
                nf.merge_note = msg
    if host_filter:
        hosts = {nn: h for nn, h in hosts.items()
                 if any(re.search(hf, nn) or re.search(hf, aaa_of[nn]) for hf in host_filter)}
    kept = {id(f) for h in hosts.values() for f in h.files}
    for fl, msg in pending:
        if any(id(f) in kept for f in fl):
            warn(msg)
    if not hosts:
        if host_filter:
            raise SystemExit("ERROR: после фильтра --host не осталось хостов")
        raise SystemExit("ERROR: ни один из файлов не удалось разобрать как nmon")
    result = []
    empty_files = 0
    for h in hosts.values():
        h.build()
        if h.n() == 0:
            if not any(f.snapshot_ids() for f in h.files):
                empty_files += 1
                warn(f"{h.name}: в файле нет ни одного снимка (только AAA/BBBP и заголовки секций — nmon остановлен сразу "
                     f"после старта или файл обрезан) — хост пропущен")
            else:
                warn(f"{h.name}: не удалось определить время ни одного снимка (нет ZZZZ, а AAA date/time нет или не разбираются) — хост пропущен")
            continue
        if skip_first:
            # первый снимок (T0001) каждого файла/запуска: интервал неполный, дельты VM/TOP искажены. Отбрасывается,
            # только если именно он попал в объединённый ряд (не вытеснен дедупликацией) и в ряду есть другие снимки
            h = h.without_first()
            h.slice_of = None  # с --skip-first полный ряд хоста — этот; исходный (с T0001) не держим в памяти
        if tz_shift:
            delta = timedelta(seconds=tz_shift)
            h.times = [t + delta for t in h.times]
            for f in h.files:  # чтобы first_snapshot_indices() и далее сравнивали одинаково сдвинутые времена
                f.zzzz = {t: dt + delta for t, dt in f.zzzz.items()}
                f.tz_shift = delta  # старт запуска (AAA date/time) сравнивается с метками в той же шкале (_snap_dt)
            for x in h.file_info:  # boottime — тоже локальное время хоста
                x["start"] += delta
                x["end"] += delta
                if x["boottime"] is not None:
                    x["boottime"] += delta
        h.tag_boot_epochs()
        result.append(h)
    result.sort(key=lambda h: h.name)
    if not result:
        if empty_files == len(hosts):
            raise SystemExit("ERROR: ни в одном файле нет снимков nmon (только заголовок)")
        raise SystemExit("ERROR: ни в одном файле нет снимков с временем (нет ZZZZ, а AAA date/time нет или не разбираются)")
    return result


def parse_tz_shift(s):
    """'+3h', '-02:00', '+90m', '3600' -> секунды (со знаком)."""
    if s is None:
        return None
    s = s.strip()
    sign = -1 if s.startswith("-") else 1
    body = s.lstrip("+-")
    m = re.match(r"^(\d{1,2}):(\d{2})$", body)
    if m:
        return sign * (int(m.group(1)) * 3600 + int(m.group(2)) * 60)
    return sign * parse_duration(body)


def resolve_cli_times(args, hosts):
    """Один раз для всех хостов разрешает --from/--to/--around (а также --time команды at и --a/--b команды compare)
    в абсолютные datetime: время суток без даты — от самого раннего снимка среди хостов (args.time_ref) с учётом
    перехода через полночь до самого позднего (args.time_end), см. resolve_user_time; --to без даты при заданном
    --from — на дату --from (как конец окна в _parse_window). Возвращает (from, to) для apply_time_filter (None —
    граница не задана); ошибки — SystemExit('ERROR: …')."""
    starts = [h.times[0] for h in hosts if h.times]
    ref = min(starts) if starts else None
    end = max(h.times[-1] for h in hosts if h.times) if starts else None
    args.time_ref, args.time_end = ref, end

    def res(opt, spec, upper=False):
        try:
            return resolve_user_time(spec, ref, end, upper=upper)
        except UserError as e:
            raise SystemExit(f"ERROR: {opt}: {e}")

    f = res("--from", args.t_from) if args.t_from else None
    t = None
    if args.t_to:
        # --to без даты при заданном --from — на дату --from, а если он раньше --from и данные продолжаются в
        # следующие сутки — на следующий день (как конец окна compare); дату задаёт --from, WARN о неоднозначности
        # не нужен. Иначе (--to с датой или без --from) — resolve_user_time с переносом верхней границы
        try:
            to_tod = f is not None and user_time_kind(args.t_to) == "time"
            if to_tod:
                t = parse_user_time(args.t_to, f)
                if t < f and end is not None and end.date() > f.date():
                    t += timedelta(days=1)
        except UserError as e:
            raise SystemExit(f"ERROR: --to: {e}")
        if not to_tod:
            t = res("--to", args.t_to, upper=True)
    if args.around:
        if args.t_from or args.t_to:
            warn("--around перекрывает --from/--to")
        a = res("--around", args.around)
        try:
            w = parse_duration(args.window) if args.window else 600.0
        except UserError as e:
            raise SystemExit(f"ERROR: --window: {e}")
        f, t = a - timedelta(seconds=w), a + timedelta(seconds=w)
    if f is not None and t is not None and f > t:
        raise SystemExit(f"ERROR: окно: --from ({ts(f)}) позже --to ({ts(t)})")
    if f is not None or t is not None:
        sys.stderr.write(f"окно времени: {ts(f) if f else 'начало данных'} .. {ts(t) if t else 'конец данных'}\n")
    if getattr(args, "time", None):
        args.time_dt = res("--time", args.time)
    if getattr(args, "command", None) == "compare" and not (getattr(args, "a", None) and getattr(args, "b", None)):
        raise SystemExit("ERROR: compare: укажите оба окна: --a 'HH:MM-HH:MM' и --b 'HH:MM-HH:MM' "
                         "(или 'YYYY-MM-DD HH:MM..YYYY-MM-DD HH:MM')")
    for opt in ("a", "b"):
        spec = getattr(args, opt, None)
        if spec:
            try:
                setattr(args, f"window_{opt}", _parse_window(spec, None, ref, end))
            except UserError as e:
                raise SystemExit(f"ERROR: --{opt}: {e}")
    return f, t


def apply_time_filter(hosts, t_from=None, t_to=None):
    """Срез хостов по окну [t_from, t_to] (готовые datetime, см. resolve_cli_times; None — без границы).
    У среза unfiltered = исходный хост (полный ряд — для фона, который нельзя считать по окну)."""
    if t_from is None and t_to is None:
        return list(hosts)
    out = []
    for h in hosts:
        if not h.times:
            out.append(h)
            continue
        mask = [(t_from is None or x >= t_from) and (t_to is None or x <= t_to) for x in h.times]
        sl = h.slice(mask)
        sl.unfiltered = h  # полный ряд (после --tz-shift/--skip-first) — для фона, который нельзя считать по окну
        out.append(sl)
    return out


# --------------------------------------------------------------------------
# Вывод: отчёты, таблицы, форматы (text | md | json | csv)
# --------------------------------------------------------------------------

SEV_ORDER = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
PREC_UNITS = {"kb": "KB", "mb": "MB", "dur": "s"}  # спец-форматы prec -> единица числа в JSON (поле units)


class Finding:
    """Результат проверки: severity, код правила, доказательства, подсказка."""
    __slots__ = ("severity", "code", "host", "time", "metric", "value", "threshold", "evidence", "hint", "extra")

    def __init__(self, severity, code, host, metric, value, threshold, evidence, hint="", time=None, extra=None):
        self.severity = severity
        self.code = code
        self.host = host
        self.time = time
        self.metric = metric
        self.value = value
        self.threshold = threshold
        self.evidence = evidence
        self.hint = hint
        self.extra = extra or {}  # дополнительные числовые поля замечания в JSON (CLUSTER_SYNC, CLUSTER_OUTLIER)

    def to_dict(self):
        d = {"severity": self.severity, "code": self.code, "host": self.host,
             "time": ts(self.time) if self.time else None, "metric": self.metric,
             "value": _jsonable(self.value), "threshold": _jsonable(self.threshold),
             "evidence": self.evidence, "hint": self.hint}
        for k, v in self.extra.items():
            d.setdefault(k, _jsonable(v))
        return d


def _jsonable(v):
    if isinstance(v, float):
        if v != v or v in (math.inf, -math.inf):
            return None
        return round(v, 3)
    if isinstance(v, datetime):
        return ts(v)
    if isinstance(v, array):
        return [_jsonable(x) for x in v]
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, Finding):
        return v.to_dict()
    return v


class Report:
    """Отчёт = заголовок + последовательность блоков (kv, table, text, findings)."""

    def __init__(self, title, host=None):
        self.title = title
        self.host = host
        self.blocks = []
        self.error = False  # данных для отчёта нет (export: секция/колонки/метрики не найдены)
        self.worst = 0  # код возврата health/report/cluster по ВСЕМ замечаниям (2 — CRIT, 1 — WARN), до фильтра вывода

    def kv(self, title, items, note=None, prec=None):
        """items: список (ключ, значение); prec: dict ключ -> 'mb'|'kb'|'dur'|число знаков для text/md (JSON хранит число)."""
        self.blocks.append({"type": "kv", "title": title, "items": list(items), "note": note, "prec": prec or {}})
        return self

    def table(self, title, columns, rows, note=None, prec=None, total=None):
        """columns: список имён; rows: список списков; prec: dict колонка->знаков после запятой или спец-формат
        ('mb'|'kb'|'dur'|'list' — список имён: в text/md первые 12 и «+K», в JSON — весь список)."""
        self.blocks.append({"type": "table", "title": title, "columns": list(columns),
                            "rows": [list(r) for r in rows], "note": note, "prec": prec or {},
                            "total": total})
        return self

    def text(self, title, text):
        self.blocks.append({"type": "text", "title": title, "text": text})
        return self

    def findings(self, title, items, note=None):
        # severity, хост, затем время (без времени — в конце), код: кластерные события (host «*») идут по времени
        items = sorted(items, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.host or "", f.time is None,
                                             f.time or datetime.min, f.code))
        self.blocks.append({"type": "findings", "title": title, "items": items, "note": note})
        return self

    @staticmethod
    def _units(prec, names):
        """Единицы колонок/ключей для JSON по спец-форматам prec: 'kb' -> KB, 'mb' -> MB, 'dur' -> s."""
        names = {str(x) for x in names}
        return {str(k): PREC_UNITS[p] for k, p in prec.items() if isinstance(p, str) and p in PREC_UNITS and str(k) in names}

    def to_dict(self):
        out = {"title": self.title, "host": self.host, "blocks": []}
        for b in self.blocks:
            if b["type"] == "kv":
                out["blocks"].append({"type": "kv", "title": b["title"],
                                      "items": {str(k): _jsonable(v) for k, v in b["items"]},
                                      "units": self._units(b["prec"], (k for k, _ in b["items"])),
                                      "note": b["note"]})
            elif b["type"] == "table":
                cols = b["columns"]
                out["blocks"].append({"type": "table", "title": b["title"], "columns": cols,
                                      "rows": [{c: _jsonable(v) for c, v in zip(cols, r)} for r in b["rows"]],
                                      "units": self._units(b["prec"], cols),
                                      "note": b["note"], "total_rows": b["total"]})
            elif b["type"] == "text":
                out["blocks"].append({"type": "text", "title": b["title"], "text": b["text"]})
            elif b["type"] == "findings":
                out["blocks"].append({"type": "findings", "title": b["title"],
                                      "items": [f.to_dict() for f in b["items"]], "note": b["note"]})
        return out


LIST_CELL_MAX = 12  # сколько имён списка показывать в ячейке text/md (prec 'list')


def _cell(v, prec=1):
    """Ячейка для text/md. prec: число знаков либо спец-формат 'mb' (MB -> GB/TB), 'kb', 'dur' (секунды),
    'list' (список имён: первые LIST_CELL_MAX и «+K»)."""
    if isinstance(v, datetime):
        return ts(v)
    if isinstance(v, (list, tuple)):
        names = [str(x) for x in v]
        if prec == "list" and len(names) > LIST_CELL_MAX:
            return ", ".join(names[:LIST_CELL_MAX]) + f" … +{len(names) - LIST_CELL_MAX}"
        return ", ".join(names)
    if isinstance(prec, str) and isinstance(v, (int, float)) and not isinstance(v, bool):
        if prec == "mb":
            return fmt_mb(v)
        if prec == "kb":
            return fmt_bytes_kb(v)
        if prec == "dur":
            return fmt_dur(v)
        prec = 1
    if isinstance(v, float):
        if v != v:
            return "-"
        if abs(v) >= 10000:
            return fmt_num(v, 0)
        return fmt_num(v, prec)
    return fmt_num(v)


def _finding_num(v):
    """Значение или порог замечания для text/md: дробное число — с точностью, по которой его можно сравнить с
    порогом (|v| < 1 — 3 знака, < 10 — 2, иначе 1; ≥ 10000 — целое): 0.923, а не 0.9 при пороге ≥ 0.92."""
    if isinstance(v, float) and v == v and v not in (math.inf, -math.inf) and not v.is_integer() and abs(v) < 10000:
        return fmt_num(v, 3 if abs(v) < 1 else (2 if abs(v) < 10 else 1))
    return _cell(v)


def _md_inline(s):
    """Текст для одной строки Markdown (пункт списка): переводы строк -> <br>."""
    return str(s).replace("\r", "").replace("\n", "<br>")


def _md_cell(s):
    """Ячейка таблицы Markdown: «|» экранируется, переводы строк -> <br>."""
    return _md_inline(s).replace("|", "\\|")


def _render_table_text(columns, rows, prec, md=False):
    cells = []
    for r in rows:
        cells.append([_cell(v, prec.get(c, 1)) for c, v in zip(columns, r)])
    # колонки со спец-форматом (mb/kb/dur) выравниваем по правому краю как числа
    fmt_cols = {c for c, p in prec.items() if isinstance(p, str) and p != "list"}
    widths = [len(c) for c in columns]
    for r in cells:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(v))
    numeric = []
    for i, c in enumerate(columns):
        numeric.append((c in fmt_cols or all(isinstance(r[i], (int, float)) and not isinstance(r[i], bool)
                                             for r in rows if i < len(r))) and bool(rows))
    lines = []
    if md:
        lines.append("| " + " | ".join(_md_cell(c) for c in columns) + " |")
        lines.append("|" + "|".join(("---:" if numeric[i] else ":---") for i in range(len(columns))) + "|")
        for r in cells:
            lines.append("| " + " | ".join(_md_cell(v) for v in r) + " |")
    else:
        hdr = "  ".join((c.rjust(widths[i]) if numeric[i] else c.ljust(widths[i])) for i, c in enumerate(columns))
        lines.append(hdr.rstrip())
        lines.append("  ".join("-" * w for w in widths))
        for r in cells:
            lines.append("  ".join((v.rjust(widths[i]) if numeric[i] else v.ljust(widths[i]))
                                   for i, v in enumerate(r)).rstrip())
    return lines


def render_text(reports, md=False):
    out = []
    for rep in reports:
        if md:
            out.append(f"# {rep.title}" + (f" — {rep.host}" if rep.host else ""))
        else:
            out.append("=" * 78)
            out.append(f"{rep.title}" + (f"  [{rep.host}]" if rep.host else ""))
            out.append("=" * 78)
        for b in rep.blocks:
            title = b.get("title")
            if title:
                out.append("")
                out.append(f"## {_md_inline(title)}" if md else f"--- {title} ---")
            elif md:
                out.append("")  # без пустой строки таблица/список «прилипнет» к предыдущему блоку
            if b["type"] == "kv":
                w = max((len(str(k)) for k, _ in b["items"]), default=0)
                pr = b.get("prec") or {}
                for k, v in b["items"]:
                    cell = _cell(v, pr.get(k, 1))
                    if md:
                        out.append(f"- **{_md_inline(k)}**: {_md_inline(cell)}")
                    else:
                        out.append(f"{str(k).ljust(w)} : {cell}")
            elif b["type"] == "table":
                if not b["rows"]:
                    out.append("(нет данных)")
                else:
                    out.extend(_render_table_text(b["columns"], b["rows"], b["prec"], md))
                    if b["total"] is not None and b["total"] > len(b["rows"]):
                        if md:
                            out.append("")  # иначе GFM считает строку продолжением таблицы
                        out.append(f"(показано {len(b['rows'])} из {b['total']})")
            elif b["type"] == "text":
                out.extend(["```", b["text"], "```"] if md else [b["text"]])
            elif b["type"] == "findings":
                items = b["items"]
                if not items:
                    out.append("- (нет замечаний)" if md else "(нет замечаний)")
                for f in items:
                    when = f" @ {ts(f.time)}" if f.time else ""
                    hostp = f" [{f.host}]" if f.host and not rep.host else ""
                    val = _finding_num(f.value) if not isinstance(f.value, str) else f.value
                    thr = f" (порог {_finding_num(f.threshold) if not isinstance(f.threshold, str) else f.threshold})" \
                        if f.threshold is not None and f.threshold != "" else ""
                    if md:
                        out.append(_md_inline(f"- **[{f.severity}] {f.code}**{hostp}{when}: {f.metric} = {val}{thr}"))
                        if f.evidence:
                            out.append(_md_inline(f"  - факты: {f.evidence}"))
                        if f.hint:
                            out.append(_md_inline(f"  - подсказка: {f.hint}"))
                        continue
                    out.append(f"[{f.severity}] {f.code}{hostp}{when}: {f.metric} = {val}{thr}")
                    if f.evidence:
                        out.append(f"    факты: {f.evidence}")
                    if f.hint:
                        out.append(f"    подсказка: {f.hint}")
            if b.get("note"):
                if md:
                    out.extend(["", f"_{_md_inline(b['note'])}_"])  # пустая строка: примечание — не строка таблицы/пункт списка
                else:
                    out.append(f"({b['note']})")
        out.append("")
    return "\n".join(out)


CSV_FINDING_COLUMNS = ["host", "severity", "code", "time", "metric", "value", "threshold", "evidence", "hint"]
CSV_KV_COLUMNS = ["host", "block", "key", "value"]


def _csv_name(name, units):
    """Имя колонки или ключа kv для CSV: с единицей спец-формата prec (KB, MB, s) в скобках — в CSV нет поля units."""
    u = units.get(str(name))
    if not u or re.search(rf"(?<![^\W\d_]){re.escape(u)}(?![^\W\d_])", str(name)):  # единица уже есть в имени («Δ, MB»)
        return name
    return f"{name} ({u})"


def render_csv(reports):
    """CSV: таблицы, замечания и kv-блоки (text-блоки пропускаются). У таблиц отчётов по хосту первая колонка —
    host; замечания — таблица CSV_FINDING_COLUMNS, kv — CSV_KV_COLUMNS. Колонки и ключи со спец-форматом prec
    (kb/mb/dur) получают единицу в имени: «записано всего (KB)». Блоки разделяются пустой строкой; если
    блоков больше одного, перед каждым — строка «# <host> | <отчёт> | <блок>» (у кластерного отчёта host = *)."""
    import csv
    import io
    tables = []  # (rep, title, header, rows)
    for rep in reports:
        host = rep.host or ""
        for b in rep.blocks:
            if b["type"] == "table":
                u = Report._units(b["prec"], b["columns"])
                cols = [_csv_name(c, u) for c in b["columns"]]
                if rep.host and not any(str(c).lower() in ("host", "хост") for c in cols):
                    tables.append((rep, b["title"], ["host"] + cols, [[rep.host] + list(r) for r in b["rows"]]))
                else:
                    tables.append((rep, b["title"], cols, b["rows"]))
            elif b["type"] == "findings":
                rows = [[f.host or host, f.severity, f.code, f.time, f.metric, f.value, f.threshold, f.evidence, f.hint]
                        for f in b["items"]]
                tables.append((rep, b["title"], CSV_FINDING_COLUMNS, rows))
            elif b["type"] == "kv":
                u = Report._units(b.get("prec") or {}, (k for k, _ in b["items"]))
                tables.append((rep, b["title"], CSV_KV_COLUMNS,
                               [[host, b["title"] or "", _csv_name(k, u), v] for k, v in b["items"]]))
    if not tables:
        if not all(rep.error for rep in reports):  # у отчётов с error причина уже напечатана в WARN
            warn("в отчёте нет табличных данных для csv — используйте --format json")
        return ""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    for k, (rep, title, header, rows) in enumerate(tables):
        if k:
            buf.write("\n")
        if len(tables) > 1:
            label = " | ".join([rep.host or "*", rep.title, title or ""]).rstrip(" |")
            buf.write("# " + label.replace("\r", "").replace("\n", " ") + "\n")
        w.writerow(header)
        for r in rows:
            w.writerow([_csv_cell(v) for v in r])
    return buf.getvalue()


def _csv_cell(v):
    """Значение для CSV: float без шума суммирования (6 знаков), NaN/inf — пусто, списки — через запятую."""
    if isinstance(v, float):
        if v != v or v in (math.inf, -math.inf):
            return ""
        return repr(round(v, 6))
    if isinstance(v, datetime):
        return ts(v)
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return v


def render(reports, fmt):
    if fmt == "json":
        return json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=1)
    if fmt == "csv":
        return render_csv(reports)
    return render_text(reports, md=(fmt == "md"))


def emit(reports, args):
    text = render(reports, args.format)
    if getattr(args, "output", None):
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
                if text and not text.endswith("\n"):
                    fh.write("\n")
        except OSError as e:
            raise SystemExit(f"ERROR: не удалось записать --output {args.output}: {e}")
        sys.stderr.write(f"записано: {args.output}\n")
    else:
        try:
            try:
                sys.stdout.write(text)
                if text and not text.endswith("\n"):
                    sys.stdout.write("\n")
            except UnicodeEncodeError:
                sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
            sys.stdout.flush()
        except BrokenPipeError:
            # читатель закрыл pipe (| head): остаток вывода не нужен; stdout — на /dev/null, чтобы финальный flush
            # интерпретатора не печатал ошибку, а код возврата остался кодом результата
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


# --------------------------------------------------------------------------
# Статистика по рядам
# --------------------------------------------------------------------------


def series_stats(arr, times):
    """Сводка по ряду: n, mean, median, p95, max(+время), min(+время), last."""
    c = clean(arr)
    if not c or arr is None:
        return {"n": 0, "mean": NAN, "median": NAN, "p95": NAN, "max": NAN, "max_time": None,
                "min": NAN, "min_time": None, "last": NAN, "first": NAN, "stdev": NAN}
    imax, imin = argmax(arr), argmin(arr)
    firsts = [v for v in arr if v == v]
    return {"n": len(c), "mean": sum(c) / len(c), "median": fmedian(c), "p95": percentile(c, 95),
            "max": arr[imax], "max_time": times[imax] if imax >= 0 else None,
            "min": arr[imin], "min_time": times[imin] if imin >= 0 else None,
            "last": firsts[-1], "first": firsts[0], "stdev": fstdev(c)}


def _extreme_time(s, which="max"):
    """Время максимума ('max') или минимума ('min') из series_stats для колонок «время max/min»; у постоянного ряда
    (max = min, например steal = 0 или swap used = 0) это просто первый снимок — None (печатается «-»)."""
    return s[f"{which}_time"] if s["max"] != s["min"] else None


def time_above(arr, thr, step):
    """Суммарное время (с), когда значение > thr: step — длительности снимков (_snap_dt, по снимку) или один шаг."""
    if isinstance(step, (int, float)):
        return count_above(arr, thr) * step
    return sum(dt for v, dt in zip(arr, step) if v == v and v > thr)


def top_peaks(arr, times, n=5, min_gap=1):
    """n наибольших значений, разнесённых минимум на min_gap снимков (локальные пики)."""
    idx = [i for i, v in enumerate(arr) if v == v]
    idx.sort(key=lambda i: -arr[i])
    chosen = []
    for i in idx:
        if all(abs(i - j) > min_gap for j in chosen):
            chosen.append(i)
        if len(chosen) >= n:
            break
    chosen.sort()
    return [(times[i], arr[i]) for i in chosen]


def rolling_base(arr, i, window=15):
    """Скользящий фон точки i (как в rolling_spikes): (медиана, масштаб) по ±window//2 соседним конечным значениям без
    самой точки; масштаб = 1.4826·MAD, при MAD = 0 — σ, на плоском фоне 0. Меньше 4 соседей — None."""
    n = len(arr)
    half = max(2, window // 2)
    lo, hi = max(0, i - half), min(n, i + half + 1)
    win = [arr[j] for j in range(lo, hi) if j != i and arr[j] == arr[j]]
    if len(win) < 4:
        return None
    med = fmedian(win)
    m = mad(win, med)
    if m > 0:
        return med, 1.4826 * m
    sd = fstdev(win)
    return med, (sd if sd == sd else 0.0)


def rolling_spikes(arr, times, window=15, z_thr=4.0, min_abs=None, direction="up", rel_floor=None):
    """Выбросы по скользящей медиане/MAD (окно центрированное, rolling_base). Возвращает [(time, value, baseline, z)].
    direction: 'up' | 'down' | 'both'; min_abs — минимальное абсолютное отклонение от фона (EventMinAbs с drop_rel —
    для значения ниже фона достаточно min(min_abs, drop_rel·|фон|), если |фон| ≥ EVENT_DROP_FLOOR·min_abs);
    rel_floor — минимальное относительное отклонение (доля |фона|; при фоне 0 — 0). На плоском фоне (MAD и σ = 0)
    z = ±inf со знаком отклонения: выброс — любое отклонение, прошедшее min_abs и rel_floor."""
    n = len(arr)
    out = []
    if n < 5:
        return out
    drop_rel = getattr(min_abs, "drop_rel", None)
    for i in range(n):
        v = arr[i]
        if v != v:
            continue
        b = rolling_base(arr, i, window)
        if b is None:
            continue
        med, scale = b
        dev = abs(v - med)
        lim = min_abs
        if drop_rel and v < med and abs(med) >= EVENT_DROP_FLOOR * min_abs:
            lim = min(min_abs, drop_rel * abs(med))  # провал до доли фона виден и при фоне ниже min_abs
        if scale <= 0:
            # плоский фон: любой отход — выброс (порогами ниже отсекаются отклонения меньше min_abs и rel_floor·|фон|,
            # в том числе на нулевом фоне); знак z — знак отклонения, иначе провал выглядел бы ростом
            if dev == 0:
                continue
            z = math.copysign(math.inf, v - med)
        else:
            z = (v - med) / scale
        if direction == "up" and z < z_thr:
            continue
        if direction == "down" and z > -z_thr:
            continue
        if direction == "both" and abs(z) < z_thr:
            continue
        if lim is not None and dev < lim:
            continue
        if rel_floor is not None and dev < rel_floor * abs(med):
            continue
        out.append((times[i], v, med, z))
    return out


def trailing_shifts(arr, window=15, z_thr=4.0, min_abs=None, direction="up", rel_floor=None, min_len=1, max_len=None):
    """Сдвиги уровня по «хвостовому» фону — плато длиннее ≈ window/2 снимков, которых центрированный rolling_spikes не
    видит (внутри плато медиана окна сама становится уровнем плато). Фон точки — медиана и масштаб (1.4826·MAD, при
    MAD = 0 — σ) последних window конечных значений до неё, не входящих в найденные эпизоды (нужно ≥ max(5, window//2)).
    Начало эпизода — отклонение с |z| ≥ z_thr в направлении direction и не меньше min_abs/rel_floor (как в
    rolling_spikes, с порогом провала EventMinAbs.drop_rel). Эпизод продолжается (гистерезис), пока значение отклонено
    от фона начала в ту же сторону хотя бы на половину начального отклонения (NaN эпизод не рвут), но не дольше
    max_len снимков (по умолчанию 4·window): затем фон перестраивается по последним значениям эпизода — устойчивый
    новый уровень. Возвращает (эпизоды [(начало, конец, фон, знак ±1)] не короче min_len снимков, множество индексов
    всех найденных эпизодов, включая короткие — их нет в фоне)."""
    n = len(arr)
    out, excl = [], set()
    if n < 5:
        return out, excl
    hist = deque(maxlen=window)
    need = max(5, window // 2)
    max_len = max_len or 4 * window
    drop_rel = getattr(min_abs, "drop_rel", None)
    i = 0
    while i < n:
        v = arr[i]
        if v != v:
            i += 1
            continue
        if len(hist) >= need:
            win = list(hist)
            med = fmedian(win)
            m = mad(win, med)
            scale = 1.4826 * m if m > 0 else fstdev(win)
            scale = scale if scale == scale else 0.0
            dev = v - med
            z = dev / scale if scale > 0 else (math.copysign(math.inf, dev) if dev else 0.0)
            lim = min_abs
            if drop_rel and v < med and abs(med) >= EVENT_DROP_FLOOR * min_abs:
                lim = min(min_abs, drop_rel * abs(med))
            ok = (z >= z_thr if direction == "up" else z <= -z_thr if direction == "down" else abs(z) >= z_thr) \
                and (lim is None or abs(dev) >= lim) and (rel_floor is None or abs(dev) >= rel_floor * abs(med))
            if ok:
                sgn = 1 if dev > 0 else -1
                last, k = i, i + 1
                while k < n and k - i < max_len:
                    u = arr[k]
                    if u == u:
                        if sgn * (u - med) < 0.5 * abs(dev):
                            break
                        last = k
                    k += 1
                excl.update(range(i, last + 1))
                if sum(1 for q in range(i, last + 1) if arr[q] == arr[q]) >= min_len:
                    out.append((i, last, med, sgn))
                if last - i + 1 >= max_len:
                    hist.clear()
                    hist.extend(arr[q] for q in range(max(i, last + 1 - window), last + 1) if arr[q] == arr[q])
                i = last + 1
                continue
        hist.append(v)
        i += 1
    return out, excl


def runs_above(arr, thr, min_len=1):
    """Непрерывные отрезки индексов, где значение > thr: [(start_idx, end_idx, max)]."""
    out = []
    start = None
    mx = NAN
    for i, v in enumerate(list(arr) + [NAN]):
        ok = v == v and v > thr
        if ok:
            if start is None:
                start, mx = i, v
            elif v > mx:
                mx = v
        else:
            if start is not None:
                if i - start >= min_len:
                    out.append((start, i - 1, mx))
                start = None
    return out


def trend(arr, times):
    """Линейный тренд: slope в единицах/час, r2, изменение за период (last-first)."""
    if not times or arr is None:
        return {"slope_per_h": NAN, "r2": NAN, "delta": NAN, "n": 0, "intercept": NAN}
    t0 = times[0]
    xs = [(t - t0).total_seconds() / 3600.0 for t in times]
    slope, intercept, n, r2 = linreg(xs, arr)
    c = [v for v in arr if v == v]
    delta = (c[-1] - c[0]) if len(c) >= 2 else NAN
    return {"slope_per_h": slope, "r2": r2, "delta": delta, "n": n, "intercept": intercept}


TREND_R2_MIN = 0.7   # «надёжный» линейный тренд — r² не меньше (mem, fs, правила *_GROWTH, сжатие page cache)
FS_SLOPE_MIN = 0.05  # рост JFSFILE, п.п./ч, с которого он экстраполируется (разрешение JFSFILE 0.1 %)


def _reliable_trend(tr, slope_min=None):
    """Надёжный тренд — одно определение для mem, fs и health: r² ≥ TREND_R2_MIN, а при slope_min — ещё и наклон
    ≥ slope_min (в единицах ряда в час)."""
    if tr["r2"] != tr["r2"] or tr["r2"] < TREND_R2_MIN:
        return False
    return slope_min is None or (tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] >= slope_min)


def time_to_limit(current, slope_per_h, limit):
    """Часы до достижения limit при текущем наклоне (NaN если не растёт)."""
    if slope_per_h != slope_per_h or slope_per_h <= 0 or current != current:
        return NAN
    if current >= limit:
        return 0.0
    return (limit - current) / slope_per_h


def periodicity(arr, times, step, min_period=60.0):
    """Оценка периода всплесков по локальным пикам выше p90.
    Возвращает dict: period (медиана интервалов, с), npeaks, ngaps, regular (bool), spread (MAD/медиана),
    share_within (доля интервалов в пределах max(±25%, ±1 шаг) от медианы). Период считается надёжным
    (regular), если интервалов ≥ 8, период ≥ 3 шагов и ≥ 60% интервалов лежат в допуске."""
    out = {"period": NAN, "npeaks": 0, "ngaps": 0, "regular": False, "spread": NAN, "share_within": NAN}
    c = clean(arr)
    if len(c) < 10:
        return out
    thr = percentile(c, 90)
    base = fmedian(c)
    if thr <= base * 1.2 + 1e-9:
        return out
    peaks = []
    n = len(arr)
    for i in range(1, n - 1):
        v = arr[i]
        if v == v and v >= thr and v >= (arr[i - 1] if arr[i - 1] == arr[i - 1] else -1) \
                and v > (arr[i + 1] if arr[i + 1] == arr[i + 1] else -1):
            peaks.append(i)
    out["npeaks"] = len(peaks)
    if len(peaks) < 3:
        return out
    gaps = [(times[peaks[k + 1]] - times[peaks[k]]).total_seconds() for k in range(len(peaks) - 1)]
    gaps = [g for g in gaps if g >= min_period]
    out["ngaps"] = len(gaps)
    if len(gaps) < 2:
        return out
    med = fmedian(gaps)
    out["period"] = med
    out["spread"] = mad(gaps, med) / med if med > 0 else NAN
    tol = max(0.25 * med, step)  # допуск не меньше шага дискретизации
    out["share_within"] = sum(1 for g in gaps if abs(g - med) <= tol) / len(gaps)
    # надёжно: ≥ 8 интервалов, период ≥ 3 шага, ≥ 60% интервалов в допуске
    out["regular"] = len(gaps) >= 8 and med >= 3 * step and out["share_within"] >= 0.6
    return out


BUCKET_EPOCH = datetime(2000, 1, 1)  # фиксированная полночь: границы корзин кратны шагу от неё


def bucket_start(t, step_sec):
    """Начало корзины для момента t: границы кратны step от фиксированной полуночи BUCKET_EPOCH (для шагов, делящих
    сутки, — от полуночи каждого дня; шаг ≥ суток не вырождается в сутки)."""
    k = math.floor((t - BUCKET_EPOCH).total_seconds() / step_sec)
    return BUCKET_EPOCH + timedelta(seconds=k * step_sec)


def downsample(times, arr, step_sec, agg="mean", counts=False):
    """Агрегация по временным корзинам step_sec (границы — bucket_start): (times, values), а с counts=True —
    (times, values, число конечных значений в корзине)."""
    if not times or step_sec <= 0:
        if counts:
            return list(times), list(arr), [1 if v == v else 0 for v in arr]
        return list(times), list(arr)
    buckets = {}
    order = []
    for t, v in zip(times, arr):
        k = bucket_start(t, step_sec)
        if k not in buckets:
            buckets[k] = []
            order.append(k)
        if v == v:
            buckets[k].append(v)
    out_t, out_v = [], []
    for k in order:
        vals = buckets[k]
        out_t.append(k)
        if not vals:
            out_v.append(NAN)
        elif agg == "max":
            out_v.append(max(vals))
        elif agg == "min":
            out_v.append(min(vals))
        elif agg == "sum":
            out_v.append(sum(vals))
        elif agg == "last":
            out_v.append(vals[-1])
        else:
            out_v.append(sum(vals) / len(vals))
    if counts:
        return out_t, out_v, [len(buckets[k]) for k in order]
    return out_t, out_v


def sum_unit(unit):
    """Смысл --agg sum для единицы метрики: ('rate', подпись) — скорость (/s): значения умножаются на фактический
    шаг снимка (_snap_dt) и дают количество за корзину; ('interval', подпись) — приращение за интервал: складывается как есть;
    ('level', unit) — уровень (%, MB, count …): сумма не имеет смысла."""
    u = (unit or "").strip()
    if u.endswith("/s"):
        b = u[:-2].strip()
        return "rate", f"{b if b and b != 'count' else 'шт.'} за корзину"
    m = re.match(r"^(.*?)/(?:int|interval)$", u)
    if m:
        b = m.group(1).strip()
        return "interval", f"{b if b and b != 'count' else 'шт.'} за корзину"
    return "level", u


def aggregate_series(host, named, step_s, agg):
    """--step/--agg для timeline и export: [(имя, единица, значения)] -> (времена корзин, ряды, снимков в корзине,
    единицы, примечание или None). При sum скорости (/s) умножаются на фактический шаг снимка (_snap_dt: после
    разрыва — его длительность, первый снимок запуска — от старта nmon) и дают количество за корзину, приращения за
    интервал складываются как есть, для уровней — WARN (сумма бессмысленна); единица — подпись sum_unit."""
    sdt = _snap_dt(host) if agg == "sum" else None
    series, units, rated, summed, levels = [], [], [], False, []
    for name, unit, vals in named:
        if len(vals) != host.n():
            vals = [NAN] * host.n()  # vm.* без секции VM — пустой ряд
        u = unit
        if agg == "sum":
            kind, u = sum_unit(unit)
            if kind == "rate":
                vals = [v * dt if v == v else NAN for v, dt in zip(vals, sdt)]
                rated.append(name)
            elif kind == "interval":
                summed = True
            else:
                levels.append(f"{name} [{unit}]" if unit else name)
        series.append(downsample(host.times, vals, step_s, agg)[1])
        units.append(u)
    tt, _v, counts = downsample(host.times, [1.0] * host.n(), step_s, "sum", counts=True)
    if levels:
        warn(f"{host.name}: --agg sum для уровней ({', '.join(levels[:8])}{' …' if len(levels) > 8 else ''}) бессмыслен — "
             f"используйте mean/max/min/last")
    notes = []
    if rated:
        notes.append(f"sum: скорости (/s) умножены на фактический шаг снимка (интервал nmon {fmt_dur(host.step())}; после "
                     f"разрыва — его длительность; первый снимок файла/запуска — от старта nmon) — значения = количество "
                     f"за корзину (KB, шт., pkt): {', '.join(rated[:8])}{' …' if len(rated) > 8 else ''}")
    if summed:
        notes.append("sum: приращения за интервал сложены как есть")
    return tt, series, counts, units, "; ".join(notes) or None


# --------------------------------------------------------------------------
# Реестр метрик (для timeline / events / correlate / export)
# --------------------------------------------------------------------------


def _snap_dt(host):
    """Фактическая длительность интервала каждого снимка, с: время от предыдущего снимка того же файла и запуска
    nmon (по номеру Tnnnn, независимо от среза и дедупликации) до этого. После разрыва (хост или nmon стоял) —
    длительность разрыва. Первый снимок файла/запуска (T0001) — от старта nmon (AAA date/time этого запуска, в шкале
    меток с учётом --tz-shift), если это от 0 до interval с; иначе, как и при шаге меньше половины interval (время шло
    назад), — interval. interval — номинальный интервал снимка (AAA,interval его файла/запуска: у файлов с разным
    interval у каждого снимка свой)."""
    prev_of = {}  # индекс файла -> {ключ снимка: время предыдущего снимка того же запуска или None}

    def prev_time(fi, t):
        if fi not in prev_of:
            runs = defaultdict(list)
            for k, dt in host.files[fi].zzzz.items():
                runs[_run_of(k)].append((_tnum(k), k, dt))
            m = {}
            for z in runs.values():
                z.sort()
                for j, (_n, k, _dt) in enumerate(z):
                    m[k] = z[j - 1][2] if j > 0 else None
            prev_of[fi] = m
        return prev_of[fi].get(t)

    out = []
    for i, (t, fi) in enumerate(zip(host.snap_ids, host.snap_src)):
        iv = host.iv(i)
        dt = iv
        cur = host.files[fi].zzzz.get(t)
        prev = prev_time(fi, t) if cur is not None else None
        if prev is not None:
            d = (cur - prev).total_seconds()
            if d >= 0.5 * iv:
                dt = d
        elif cur is not None:
            # первый снимок запуска: T0001 снят через ~1–2 с после старта nmon
            st = host.files[fi].run_start(_run_of(t))
            d = (cur - st).total_seconds() if st is not None else 0.0
            if 0 < d <= iv:
                dt = d
        out.append(dt)
    return out


def _integrate(host, arr, dts=None):
    """Количество за период по ряду скоростей (/s): Σ v × фактический шаг снимка (_snap_dt: после разрыва —
    длительность разрыва, первый снимок файла/запуска — от старта nmon). Один интегратор для «… за период» в disk, net,
    NETERROR, сверках check и TOP; dts — заранее посчитанный _snap_dt(host). NaN, если значений нет."""
    if arr is None:
        return NAN
    tot, ok = 0.0, False
    for v, dt in zip(arr, dts if dts is not None else _snap_dt(host)):
        if v == v:
            tot += v * dt
            ok = True
    return tot if ok else NAN


def _per_sec_dt(host, arr):
    """Приращения за интервал (VM pgpgin/pgfault …) -> в секунду по фактическому шагу снимка (_snap_dt): после
    разрыва приращение покрывает весь разрыв и делится на него, а не на interval. Колонки нет (None) — None:
    метрика отсутствует."""
    if arr is None:
        return None
    return [v / dt if v == v else NAN for v, dt in zip(arr, _snap_dt(host))]


def _pages_to_mb(arr, page_kb=4.0):
    if arr is None:
        return None  # колонки нет — метрика отсутствует
    return [v * page_kb / 1024.0 if v == v else NAN for v in arr]


def _kb_to_mb(arr):
    return [v / 1024.0 if v == v else NAN for v in arr]


def _core_busy_max(host):
    n = host.n()
    out = [NAN] * n
    for core in host.cpu_cores:
        u = host.col(core, "User%")
        s = host.col(core, "Sys%")
        if u is None or s is None:
            continue
        for i in range(n):
            if u[i] == u[i] and s[i] == s[i]:
                b = u[i] + s[i]
                if out[i] != out[i] or b > out[i]:
                    out[i] = b
    return out


def _core_busy_argmax(host):
    """По снимкам: максимум User%+Sys% среди ядер CPUnnn и имя этого ядра -> (значения, имена); NaN/None без данных."""
    n = host.n()
    vals, names = [NAN] * n, [None] * n
    for core in host.cpu_cores:
        u = host.col(core, "User%")
        s = host.col(core, "Sys%")
        if u is None or s is None:
            continue
        for i in range(n):
            if u[i] == u[i] and s[i] == s[i]:
                b = u[i] + s[i]
                if vals[i] != vals[i] or b > vals[i]:
                    vals[i], names[i] = b, core
    return vals, names


def _core_hot_count(host, thr=90.0):
    n = host.n()
    out = [0.0] * n
    for core in host.cpu_cores:
        u = host.col(core, "User%")
        s = host.col(core, "Sys%")
        if u is None or s is None:
            continue
        for i in range(n):
            if u[i] == u[i] and s[i] == s[i] and u[i] + s[i] > thr:
                out[i] += 1
    return out


TOP_ZERO_ABSENT = ("cpu", "usr", "sys", "minflt", "majflt")  # поля TOP, где «процесса нет в снимке» = 0


def _proc_series(host, pred, field, zero_absent=None):
    """Ряд по процессам TOP: сумма поля по процессам, удовлетворяющим pred.
    zero_absent (по умолчанию — для cpu/usr/sys/minflt/majflt): если процесс хоть раз виден (в любом снимке данных, в том
    числе вне окна времени), то в снимке с данными TOP без него значение 0 — в TOP не попадают процессы ниже порога
    CPU (≈ 0.1 % ядра) и несуществующие. Снимки без TOP (первый снимок файла, разрывы, nmon без -t) и поля
    rss/size/threads/iowait у отсутствующего процесса — NaN."""
    if zero_absent is None:
        zero_absent = field in TOP_ZERO_ABSENT
    n = host.n()
    out = [NAN] * n
    seen = False
    for i, procs in enumerate(host.top):
        acc = None
        hit = False
        for p in procs:
            if pred(p):
                hit = True
                v = getattr(p, field)
                if v == v:
                    acc = (acc or 0.0) + v
        seen = seen or hit
        if acc is not None:
            out[i] = acc
        elif zero_absent and procs and not hit:
            out[i] = 0.0
    if not seen and not _top_known(host, pred):
        return [NAN] * n
    return out


def _java_main_series(host, field):
    """Уровень основных JVM (rss/size — KB, threads, iowait) по снимкам host: сумма по основным JVM (_java_roles по полному
    ряду: host.unfiltered или исходный хост среза), без вспомогательных java (утилиты, клиенты) — иначе значение
    скачет, когда в TOP попадает другой java. Живой PID (между его первым и последним появлением), не попавший в TOP
    снимка (простой ниже порога TOP), — его последнее известное значение; в снимке, где видны старый (видимый
    последний раз) и новый (впервые) основные PID, — только новый (перезапуск, а не два JVM). Снимок без TOP — NaN;
    java нет ни в одном снимке — весь ряд NaN."""
    full = host.unfiltered or host.slice_of or host
    cache = getattr(full, "_java_main_cache", None)
    if cache is None:
        cache = full._java_main_cache = {}
    if field not in cache:
        life = _java_life(full)
        jp, roles = life["jp"], life["roles"]
        mains = [pid for pid in jp if roles.get(pid, True)] or list(jp)
        n = full.n()
        acc = [NAN if not full.top[i] else 0.0 for i in range(n)]
        got = [False] * n
        firsts = defaultdict(set)  # индекс -> основные PID, впервые видимые в этом снимке
        for pid in mains:
            firsts[jp[pid][0][0]].add(pid)
        for pid in mains:
            lst = jp[pid]
            first_i, last_i = lst[0][0], lst[-1][0]
            # старый PID в снимке, где впервые виден другой основной (и дальше его нет), — не складываем
            skip_last = any(q != pid for q in firsts.get(last_i, ())) and first_i < last_i
            vals = {i: getattr(p, field) for i, p in lst}
            cur = NAN
            for i in range(first_i, last_i + 1):
                v = vals.get(i, NAN)
                if v == v:
                    cur = v
                if i == last_i and skip_last:
                    break
                if full.top[i] and cur == cur:
                    acc[i] += cur
                    got[i] = True
        ser = [a if g else NAN for a, g in zip(acc, got)]
        if not jp and not _top_known(full, _is_java):
            ser = [NAN] * n
        cache[field] = ({t: v for t, v in zip(full.times, ser)}, ser)
    by_t, ser = cache[field]
    if host is full:
        return list(ser)
    return [by_t.get(t, NAN) for t in host.times]


def _top_known(host, pred):
    """Есть ли процесс (pred) в TOP хоть одного снимка — по всем данным файлов хоста, а не только по окну
    --from/--to или окну compare (файлы у срезов общие): процесс, существующий вне окна, в окне — 0 (вне TOP), а не NaN."""
    return any(pred(p) for f in host.files for procs in f.top.values() for p in procs)


def _top_sum_cpu(host):
    n = host.n()
    out = [NAN] * n
    for i, procs in enumerate(host.top):
        if procs:
            out[i] = sum(p.cpu for p in procs if p.cpu == p.cpu)
    return out


BASE_METRICS = {
    # имя: (описание, единица, функция(host) -> список)
    "cpu.busy": ("CPU busy (User+Sys), всего", "%", lambda h: h.cpu_busy()),
    "cpu.user": ("CPU User%", "%", lambda h: h.col("CPU_ALL", "User%")),
    "cpu.sys": ("CPU Sys%", "%", lambda h: h.col("CPU_ALL", "Sys%")),
    "cpu.wait": ("CPU Wait% (iowait)", "%", lambda h: h.col("CPU_ALL", "Wait%")),
    "cpu.idle": ("CPU Idle%", "%", lambda h: h.col("CPU_ALL", "Idle%")),
    "cpu.steal": ("CPU Steal%", "%", lambda h: h.col("CPU_ALL", "Steal%")),
    "cpu.core_max": ("Макс. busy среди ядер", "%", _core_busy_max),
    "cpu.hot_cores": ("Число ядер с busy > 90%", "cores", _core_hot_count),
    "proc.runq": ("Runnable (очередь на выполнение)", "count", lambda h: h.col("PROC", "Runnable")),
    "proc.blocked": ("Blocked (D-state, ждут I/O)", "count", lambda h: h.col("PROC", "Blocked")),
    "proc.pswitch": ("Переключений контекста", "/s", lambda h: h.col("PROC", "pswitch")),
    "proc.fork": ("fork", "/s", lambda h: h.col("PROC", "fork")),
    "mem.free": ("memfree", "MB", lambda h: h.col("MEM", "memfree")),
    "mem.used": ("used = total-free-cached-buffers", "MB", lambda h: h.mem_used()),
    "mem.cached": ("cached (page cache)", "MB", lambda h: h.col("MEM", "cached")),
    "mem.buffers": ("buffers", "MB", lambda h: h.col("MEM", "buffers")),
    "mem.avail": ("avail ≈ free+buffers+(cached−shmem)+slab (оценка MemAvailable)", "MB", lambda h: h.mem_avail()),
    "mem.avail_cal": ("avail с поправкой по MemAvailable на старте (если есть в BBBP)", "MB", lambda h: h.mem_avail_calibrated()),
    "mem.active": ("active", "MB", lambda h: h.col("MEM", "active")),
    "mem.inactive": ("inactive", "MB", lambda h: h.col("MEM", "inactive")),
    "mem.shared": ("memshared", "MB", lambda h: h.col("MEM", "memshared")),
    "mem.swap_used": ("swap used", "MB", lambda h: h.swap_used()),
    "mem.swapcached": ("swapcached", "MB", lambda h: h.col("MEM", "swapcached")),
    "vm.pgpgin": ("pgpgin (чтение с блочных устройств; /s по фактическому шагу)", "KB/s", lambda h: _per_sec_dt(h, h.col("VM", "pgpgin"))),
    "vm.pgpgout": ("pgpgout (запись на блочные устройства; /s по фактическому шагу)", "KB/s", lambda h: _per_sec_dt(h, h.col("VM", "pgpgout"))),
    "vm.pswpin": ("pswpin (страниц из swap за интервал)", "pages/int", lambda h: h.col("VM", "pswpin")),
    "vm.pswpout": ("pswpout (страниц в swap за интервал)", "pages/int", lambda h: h.col("VM", "pswpout")),
    "vm.pgfault": ("page faults (/s по фактическому шагу)", "/s", lambda h: _per_sec_dt(h, h.col("VM", "pgfault"))),
    "vm.pgmajfault": ("major page faults (/s по фактическому шагу)", "/s", lambda h: _per_sec_dt(h, h.col("VM", "pgmajfault"))),
    "vm.pgfree": ("pgfree (/s по фактическому шагу)", "/s", lambda h: _per_sec_dt(h, h.col("VM", "pgfree"))),
    "vm.kswapd_steal": ("kswapd_steal (страниц освобождено kswapd за интервал)", "pages/int", lambda h: h.col("VM", "kswapd_steal")),
    "vm.pgscan_kswapd": ("pgscan_kswapd_* (сканирование kswapd за интервал)", "pages/int",
                         lambda h: _sum_cols(h, "VM", ["pgscan_kswapd_high", "pgscan_kswapd_normal", "pgscan_kswapd_dma"])),
    "vm.pgscan_direct": ("pgscan_direct_* (прямой reclaim за интервал)", "pages/int",
                         lambda h: _sum_cols(h, "VM", ["pgscan_direct_high", "pgscan_direct_normal", "pgscan_direct_dma"])),
    "vm.pgsteal": ("pgsteal_* (освобождено reclaim за интервал)", "pages/int",
                   lambda h: _sum_cols(h, "VM", ["pgsteal_high", "pgsteal_normal", "pgsteal_dma"])),
    "vm.allocstall": ("allocstall (direct reclaim stalls за интервал; на современных ядрах всегда 0 — см. vm)", "count/int", lambda h: h.col("VM", "allocstall")),
    "vm.pageoutrun": ("pageoutrun (запуски kswapd за интервал)", "count/int", lambda h: h.col("VM", "pageoutrun")),
    "vm.slabs_scanned": ("slabs_scanned (сканирование slab при reclaim за интервал)", "count/int", lambda h: h.col("VM", "slabs_scanned")),
    "vm.pgdeactivate": ("pgdeactivate (страниц переведено в inactive за интервал)", "pages/int", lambda h: h.col("VM", "pgdeactivate")),
    "vm.pgactivate": ("pgactivate (страниц переведено в active за интервал)", "pages/int", lambda h: h.col("VM", "pgactivate")),
    "vm.nr_dirty": ("nr_dirty (грязные страницы)", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_dirty"), h.page_kb())),
    "vm.nr_writeback": ("nr_writeback (страницы в записи)", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_writeback"), h.page_kb())),
    "vm.nr_mapped": ("nr_mapped", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_mapped"), h.page_kb())),
    "vm.nr_slab": ("nr_slab_reclaimable", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_slab_reclaimable"), h.page_kb())),
    "vm.nr_page_table": ("nr_page_table_pages", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_page_table_pages"), h.page_kb())),
    "disk.busy_max": ("Макс. занятость среди физических дисков (без разделов, dm-*, md*)", "%", lambda h: h.disk_max_busy()[0]),
    "disk.read": ("Чтение, сумма по физическим дискам", "KB/s", lambda h: h.disk_total("DISKREAD")),
    "disk.write": ("Запись, сумма по физическим дискам", "KB/s", lambda h: h.disk_total("DISKWRITE")),
    "disk.iops": ("IOPS, сумма по физическим дискам", "/s", lambda h: h.disk_total("DISKXFER")),
    "net.read": ("Сеть приём, сумма без lo, слейвов bond, VLAN, мостов и виртуальных интерфейсов", "KB/s", lambda h: h.net_total("read")),
    "net.write": ("Сеть передача, сумма без lo, слейвов bond, VLAN, мостов и виртуальных интерфейсов", "KB/s", lambda h: h.net_total("write")),
    "net.rx_size": ("Средний размер принятого пакета по снимкам (Σ KB/s × 1024 / Σ pkt/s основных интерфейсов)", "B/pkt",
                    lambda h: h.net_pkt_size("read")),
    "net.tx_size": ("Средний размер отправленного пакета по снимкам (Σ KB/s × 1024 / Σ pkt/s основных интерфейсов)", "B/pkt",
                    lambda h: h.net_pkt_size("write")),
    "top.java.cpu": ("java: %CPU (сумма по java-процессам; 0 = ниже порога TOP или процесса нет)", "%", lambda h: _proc_series(h, _is_java, "cpu")),
    "top.java.usr": ("java: %Usr (0 = ниже порога TOP или процесса нет)", "%", lambda h: _proc_series(h, _is_java, "usr")),
    "top.java.sys": ("java: %Sys (0 = ниже порога TOP или процесса нет)", "%", lambda h: _proc_series(h, _is_java, "sys")),
    "top.java.rss": ("java: RSS, сумма по основным JVM (без вспомогательных java; PID вне TOP снимка — последнее значение)",
                     "MB", lambda h: _kb_to_mb(_java_main_series(h, "rss"))),
    "top.java.vsz": ("java: VSZ, сумма по основным JVM (как top.java.rss)", "MB", lambda h: _kb_to_mb(_java_main_series(h, "size"))),
    "top.java.threads": ("java: threads, сумма по основным JVM (как top.java.rss)", "count",
                         lambda h: _java_main_series(h, "threads")),
    "top.java.majflt": ("java: MajorFault из TOP (может включать faults после повтора, а не только чтения с диска — см. check; "
                        "0 = ниже порога TOP)", "/s", lambda h: _proc_series(h, _is_java, "majflt")),
    "top.java.minflt": ("java: minor faults (0 = ниже порога TOP или процесса нет)", "/s", lambda h: _proc_series(h, _is_java, "minflt")),
    "top.java.iowait": ("java: IOwaitTime (только главный поток), сумма по основным JVM (как top.java.rss)", "ticks",
                        lambda h: _java_main_series(h, "iowait")),
    "top.sum_cpu": ("Сумма %CPU всех процессов TOP", "%", _top_sum_cpu),
    "top.kswapd.cpu": ("kswapd*: %CPU, сумма по всем kswapdN (обычно один на NUMA-узел; 0 = ниже порога TOP)", "%", lambda h: _proc_series(h, lambda p: p.cmd.startswith("kswapd"), "cpu")),
}


def _is_java(p):
    return p.cmd == "java" or p.cmd.startswith("java")


def _sum_cols(host, section, cols):
    n = host.n()
    out = [NAN] * n
    for c in cols:
        arr = host.col(section, c)
        if arr is None:
            continue
        for i in range(n):
            if arr[i] == arr[i]:
                out[i] = (out[i] if out[i] == out[i] else 0.0) + arr[i]
    return out


def resolve_metrics(host, names, warn_missing=True):
    """[(name, (label, unit, values))] для известных метрик; о неизвестных и о рядах без единого значения предупреждает
    в stderr (warn_missing=False — для наборов по умолчанию, где часть метрик может отсутствовать в файле)."""
    out = []
    for m in names or []:
        r = resolve_metric(host, m)
        if r is None:
            if warn_missing:
                warn(f"{host.name}: метрика {m!r} неизвестна или отсутствует в данных (список: команда metrics)")
        else:
            if warn_missing and not clean(r[2]):
                warn(f"{host.name}: метрика {m!r}: нет значений в данных (все снимки пусты)")
            out.append((m, r))
    return out


def resolve_metric(host, name):
    """Имя метрики -> (label, unit, values) или None.
    Кроме BASE_METRICS поддерживаются:
      disk.<dev>.busy|read|write|iops|xfer|bsize|rserv|wserv
      net.<if>.read|write|pkt_in|pkt_out|rx_size|tx_size
      fs.<mount>.pct|inode
      cpu.core<N>.busy|user|sys|wait|idle|steal   (N — номер CPU как в nmon, с 1)
      top.<cmd>.cpu|usr|sys|rss|vsz|threads|majflt|minflt|iowait   (<cmd> — префикс имени: top.kworker — все kworker;
                                                             группа со «*» из top/java — по cmd_group: top.kworker/*-writeback)
      top.pid<PID>.cpu|rss|threads|...
      raw.<SECTION>.<column>
    Для cpu/usr/sys/majflt/minflt снимок TOP без процесса = 0 (ниже порога TOP), см. _proc_series; процесс, которого
    нет ни в одном снимке данных, — None (метрика отсутствует).
    """
    if name in BASE_METRICS:
        desc, unit, fn = BASE_METRICS[name]
        vals = fn(host)
        if vals is None:
            return None
        return desc, unit, list(vals)
    parts = name.split(".")
    if len(parts) >= 3 and parts[0] == "disk":
        dev, what = ".".join(parts[1:-1]), parts[-1]
        secmap = {"busy": ("DISKBUSY", "%"), "read": ("DISKREAD", "KB/s"), "write": ("DISKWRITE", "KB/s"),
                  "iops": ("DISKXFER", "/s"), "xfer": ("DISKXFER", "/s"), "bsize": ("DISKBSIZE", "KB"),
                  "rserv": ("DISKREADSERV", "ms"), "wserv": ("DISKWRITESERV", "ms")}
        if what in secmap:
            sec, unit = secmap[what]
            arr = host.col(sec, dev)
            if arr is None:
                return None
            return f"{dev} {sec}", unit, list(arr)
    if len(parts) >= 3 and parts[0] == "net":
        iface, what = ".".join(parts[1:-1]), parts[-1]
        colmap = {"read": ("NET", f"{iface}-read-KB/s", "KB/s"), "write": ("NET", f"{iface}-write-KB/s", "KB/s"),
                  "pkt_in": ("NETPACKET", f"{iface}-read/s", "pkt/s"), "pkt_out": ("NETPACKET", f"{iface}-write/s", "pkt/s")}
        if what in ("rx_size", "tx_size"):
            if iface not in host.net_ifaces():
                return None
            vals = host.net_pkt_size("read" if what == "rx_size" else "write", ifaces=[iface])
            return (f"{iface} {what}", "B/pkt", vals) if vals is not None else None
        if what in colmap:
            sec, col, unit = colmap[what]
            arr = host.col(sec, col)
            if arr is None:
                return None
            return f"{iface} {what}", unit, list(arr)
    if len(parts) >= 3 and parts[0] == "fs" and parts[-1] in ("pct", "inode"):
        mount = ".".join(parts[1:-1])
        sec = "JFSFILE" if parts[-1] == "pct" else "JFSINODE"
        arr = host.col(sec, mount)
        if arr is None:
            return None
        return f"{mount} {sec}", "%", list(arr)
    if len(parts) == 3 and parts[0] == "cpu" and parts[1].startswith("core"):
        try:
            k = int(parts[1][4:])
        except ValueError:
            return None
        sec = f"CPU{k:03d}"
        what = parts[2]
        if what == "busy":
            u, s = host.col(sec, "User%"), host.col(sec, "Sys%")
            if u is None or s is None:
                return None
            return f"{sec} busy", "%", [a + b if (a == a and b == b) else NAN for a, b in zip(u, s)]
        colmap = {"user": "User%", "sys": "Sys%", "wait": "Wait%", "idle": "Idle%", "steal": "Steal%"}
        if what in colmap:
            arr = host.col(sec, colmap[what])
            if arr is None:
                return None
            return f"{sec} {colmap[what]}", "%", list(arr)
    if len(parts) >= 3 and parts[0] == "top":
        target, what = ".".join(parts[1:-1]), parts[-1]
        field = {"cpu": "cpu", "usr": "usr", "sys": "sys", "rss": "rss", "vsz": "size", "threads": "threads",
                 "majflt": "majflt", "minflt": "minflt", "iowait": "iowait"}.get(what)
        if field is None:
            return None
        if target.startswith("pid"):
            try:
                pid = int(target[3:])
            except ValueError:
                return None
            pred = lambda p, pid=pid: int(p.pid) == pid  # noqa: E731  (номер PID — во всех эпохах загрузки)
        elif "*" in target:
            pred = lambda p, t=target: cmd_group(p.cmd) == t  # noqa: E731
        else:
            pred = lambda p, t=target: p.cmd == t or p.cmd.startswith(t)  # noqa: E731
        if not _top_known(host, pred):
            return None  # процесса нет ни в одном снимке данных (опечатка в имени/PID) — метрика отсутствует
        vals = _proc_series(host, pred, field)
        unit = {"cpu": "%", "usr": "%", "sys": "%", "rss": "MB", "size": "MB", "threads": "count",
                "majflt": "/s", "minflt": "/s", "iowait": "ticks"}.get(field, "count")
        if field in ("rss", "size"):
            vals = _kb_to_mb(vals)
        return f"{target} {what}" + (" (0 = ниже порога TOP или процесса нет)" if field in TOP_ZERO_ABSENT else ""), unit, vals
    if len(parts) >= 3 and parts[0] == "raw":
        sec, col = Host._base_name(parts[1]), ".".join(parts[2:])
        arr = host.col(sec, col)
        if arr is None:
            return None
        # единица — по колонке, как в export --section (VM: pages/приращения; PROC: Runnable/Blocked — уровни, count)
        return f"{sec} {col}", _export_col_unit(sec, col), list(arr)
    return None


def _section_info(name):
    """(описание, единица) секции из SECTION_INFO: CPU001 -> CPUnnn, DISKBUSY1 -> DISKBUSY; неизвестная — ('', '')."""
    if re.match(r"^CPU\d+$", name):
        return SECTION_INFO["CPUnnn"]
    return SECTION_INFO.get(name) or SECTION_INFO.get(Host._base_name(name), ("", ""))


def list_metrics(host):
    """Все доступные имена метрик для данного хоста."""
    names = [m for m in BASE_METRICS if resolve_metric(host, m) is not None]
    for dev in host.disk_devices():
        for what in ("busy", "read", "write", "iops", "bsize"):
            names.append(f"disk.{dev}.{what}")
        if host.has("DISKREADSERV"):
            names.append(f"disk.{dev}.rserv")
            names.append(f"disk.{dev}.wserv")
    for i in host.net_ifaces():
        for what in ("read", "write", "pkt_in", "pkt_out") + (("rx_size", "tx_size") if host.has("NETPACKET") else ()):
            names.append(f"net.{i}.{what}")
    for m in host.cols("JFSFILE"):
        names.append(f"fs.{m}.pct")
    for s in host.cpu_cores:  # по фактическим секциям: нумерация CPU может быть с разрывами (offline)
        names.append(f"cpu.core{int(s[3:])}.busy")
    cmds = set()
    for procs in host.top:
        for p in procs:
            # ядерные потоки вида kworker/8:0-events, ksoftirqd/3, migration/12 — одно имя по префиксу до '/'
            # (top.<cmd> сопоставляется по префиксу, поэтому top.kworker.cpu — сумма по всем kworker)
            cmds.add(p.cmd.split("/", 1)[0] or p.cmd)
    for c in sorted(cmds):
        names.append(f"top.{c}.cpu")
    return list(dict.fromkeys(names))


DEFAULT_TIMELINE = ["cpu.busy", "cpu.user", "cpu.sys", "cpu.wait", "cpu.steal", "proc.runq", "proc.blocked",
                    "mem.free", "mem.cached", "mem.swap_used", "disk.busy_max", "disk.read", "disk.write",
                    "disk.iops", "net.read", "net.write", "top.java.cpu", "top.java.rss", "top.java.threads"]


# --------------------------------------------------------------------------
# Анализы по одному хосту
# --------------------------------------------------------------------------


def _opt(args, name, default=None):
    return getattr(args, name, default) if args is not None else default


def analyze_info(host, args=None):
    rep = Report("Сведения о файле(ах) nmon и хосте", host.name)
    m = host.meta
    items = [
        ("host", host.name),
        ("файлы", "; ".join(os.path.basename(f.path) for f in host.files)),
        ("nmon версия", m.get("version", "-")),
        ("команда nmon", m.get("command", "-")),
        ("OS", m.get("OS", "-")),
    ]
    fi0 = host.file_info[0] if host.file_info else {}
    if _opt(args, "tz_shift", None) and fi0.get("boot_src") == "AAA" and fi0.get("boottime"):
        # --tz-shift сдвигает все метки, и boottime тоже: исходная строка AAA — отдельно, с пометкой
        items += [("boottime (из AAA, со сдвигом --tz-shift)", fi0["boottime"]),
                  ("boottime в AAA (как в файле, без --tz-shift)", m.get("boottime", "-"))]
    else:
        items.append(("boottime (из AAA)", m.get("boottime", "-")))
    items += [
        ("interval, с (AAA)", host.interval),
    ]
    ivd = host.intervals_differ()
    if ivd:
        items.append(("интервалы файлов/запусков (различаются)", _iv_list(ivd)))
    items += [
        ("фактический шаг, с (медиана)", host.actual_interval()),
        ("снимков", host.n()),
        ("начало", host.start()),
        ("конец", host.end()),
        ("длительность", host.duration()),
        ("CPU (логических)", host.ncpus()),
    ]
    mt = host.col("MEM", "memtotal")
    if mt is not None:
        items.append(("memtotal", fmax(mt)))
    st = host.col("MEM", "swaptotal")
    if st is not None:
        items.append(("swaptotal", fmax(st)))
    items.append(("дисков в DISK*", len(host.disk_devices())))
    items.append(("физических дисков", ", ".join(host.physical_disks()) or "-"))
    items.append(("сетевых интерфейсов", ", ".join(host.net_ifaces()) or "-"))
    items.append(("файловых систем (JFSFILE)", len(host.cols("JFSFILE"))))
    if any(host.top):
        items.append(("TOP (процессы)", "да"))
    elif host.top_in_files():
        items.append(("TOP (процессы)", "в выбранном окне нет снимков с данными TOP (TOP пишется начиная со второго "
                                        "снимка); расширьте окно"))
    elif any(f.top_columns for f in host.files):
        items.append(("TOP (процессы)", MSG_TOP_HEADER_ONLY))
    else:
        items.append(("TOP (процессы)", "нет (nmon без -t)"))
    items.append(("UARG (командные строки)", "да" if any(host.uarg) else "нет (nmon без -T)"))
    items.append(("дубликатов снимков отброшено", host.duplicates_dropped))
    gaps = host.gaps()
    _inner, edge = host.split_gaps()
    items.append(("разрывов во времени (> 1.5×interval)", len(gaps)))
    # Планировалось vs собрано
    try:
        planned = int(m.get("snapshots", "0"))
        if 0 < planned < 9999999:
            items.append(("снимков запланировано (-c)", planned))
    except ValueError:
        pass
    rep.kv("Метаданные", items, prec={"memtotal": "mb", "swaptotal": "mb", "длительность": "dur"})
    if len(host.file_info) > 1:
        rep.table("Файлы хоста и запуски nmon в них",
                  ["файл", "запуск", "начало", "конец", "снимков", "boottime", "uptime на старте", "CPU", "MemTotal", "OS"],
                  [[x["file"], x["run"], x["start"], x["end"], x["snapshots"], x["boottime"], x["uptime"] or "-",
                    x["cpus"] or "-", x["memtotal_kb"], x["OS"] or "-"] for x in host.file_info],
                  prec={"MemTotal": "kb"},
                  note="boottime — из AAA,boottime, а без него — AAA date/time минус uptime из BBBP; "
                       "смена boottime между файлами/запусками = перезагрузка ОС (см. check, health BOOT_RECENT)")
    if gaps:
        edge_set = set(edge)
        rep.table("Разрывы во времени (возможная заморозка хоста или остановка nmon)",
                  ["от", "до", "длительность", "где"],
                  [[a, b, d, "между файлами/запусками nmon" if (a, b, d, iv) in edge_set else "внутри запуска nmon"]
                   for a, b, d, iv in gaps[:50]], total=len(gaps), prec={"длительность": "dur"},
                  note="внутри запуска — хост был заморожен или nmon не успевал; между файлами/запусками — nmon не работал")
    # Аппаратная конфигурация из BBBP
    lscpu = host.lscpu()
    mi = host.meminfo()
    hw = []
    hw_prec = {}
    for k in ("Model name", "Socket(s)", "Core(s) per socket", "Thread(s) per core", "NUMA node(s)",
              "CPU MHz", "CPU max MHz", "L3 cache", "Hypervisor vendor", "Virtualization type"):
        if k in lscpu:
            hw.append((k, lscpu[k]))
    if mi:
        for k in ("MemTotal", "MemAvailable", "SwapTotal", "HugePages_Total", "Hugepagesize",
                  "AnonHugePages", "Committed_AS", "CommitLimit", "Shmem", "Dirty"):
            if k in mi:
                hw.append((k, mi[k]))  # KB (число); HugePages_Total — штук
                if k != "HugePages_Total":
                    hw_prec[k] = "kb"
    for line in host.bbbp.get("uptime", []):
        if line.strip():
            hw.append(("uptime на старте", line.strip()))
    rel = [x for x in host.bbbp.get("/etc/release", []) if x.startswith("PRETTY_NAME=")]
    if rel:
        hw.append(("дистрибутив", rel[0].split("=", 1)[1].strip('"Q')))
    if hw:
        rep.kv("Конфигурация (BBBP)", hw, prec=hw_prec)
    secs = sorted(host.series.keys(), key=lambda s: (not s.startswith("CPU"), s))
    compact = [s for s in secs if not re.match(r"^CPU\d+$", s)]
    if host.cpu_cores:
        compact.insert(0, f"{host.cpu_cores[0]}..{host.cpu_cores[-1]} (секций: {len(host.cpu_cores)})")
    rep.kv("Секции", [("присутствуют", ", ".join(compact))])
    warns = [[os.path.basename(f.path), w] for f in host.files for w in f.warnings]
    if warns:
        # таблица (а не текст): предупреждения попадают и в csv
        rep.table("Предупреждения разбора", ["файл", "предупреждение"], warns[:20], total=len(warns))
    return rep


def analyze_sections(host, args=None):
    rep = Report("Секции и колонки", host.name)
    rows = []
    for name in sorted(host.series.keys(), key=lambda s: (re.match(r"^CPU\d+$", s) is not None, s)):
        if re.match(r"^CPU\d+$", name) and name != host.cpu_cores[0]:
            continue
        cols = host.columns.get(name, [])
        ser = host.series[name]
        nvals = 0
        for c in cols:
            nvals = max(nvals, len(clean(ser[c])))
        label = name if not re.match(r"^CPU\d+$", name) else \
            f"{host.cpu_cores[0]}..{host.cpu_cores[-1]} (секций: {len(host.cpu_cores)})"
        desc = _section_info(name)
        rows.append([label, len(cols), nvals, desc[1], list(cols), desc[0]])
    if any(host.top):
        # для TOP — имена колонок export --section TOP (--columns); имена nmon — в описании
        tcols = next((f.top_columns for f in host.files if f.top_columns), TOP_DEFAULT_COLUMNS)
        rows.append(["TOP", len(TOP_EXPORT_COLUMNS), sum(len(x) for x in host.top), SECTION_INFO["TOP"][1],
                     list(TOP_EXPORT_COLUMNS), f"{SECTION_INFO['TOP'][0]}; колонки в файле nmon: {', '.join(tcols)}"])
    if any(host.uarg):
        ucols = next((f.uarg_columns for f in host.files if f.uarg_columns), ["Time", "PID", "ProgName", "FullCommand"])
        rows.append(["UARG", len(ucols), sum(len(x) for x in host.uarg), "", list(ucols), SECTION_INFO["UARG"][0]])
    rep.table("Секции", ["секция", "колонок", "значений", "ед.", "колонки", "описание"], rows, prec={"колонки": "list"},
              note=f"в text/md показаны первые {LIST_CELL_MAX} колонок; полный список — в --format json "
                   f"(имена для raw.<SECTION>.<column> и export --columns; у TOP — имена export --section TOP, "
                   f"исходные имена nmon — в описании)")
    rep.table("BBBP (конфигурационные блоки)", ["блок", "строк"],
              [[c, len(host.bbbp[c])] for c in host.bbbp_order])
    return rep


def analyze_cpu(host, args=None):
    rep = Report("CPU", host.name)
    if not host.has("CPU_ALL"):
        rep.text("", "Секция CPU_ALL отсутствует")
        return rep
    # все статистики — без первых снимков файлов: T0001 охватывает неполный интервал (завышенные busy/wait, ложные 100% на ядре)
    hx = host.without_first()
    sdt = _snap_dt(hx)  # «время выше порога» — Σ фактических длительностей снимков (у файлов с разным interval — свои)
    busy = hx.cpu_busy()
    if busy is None:
        rep.text("", "В CPU_ALL нет колонок User%/Sys%: колонки: " + ", ".join(host.cols("CPU_ALL"))
                 + "; используйте export --section CPU_ALL")
        return rep
    top = _opt(args, "top", 5) or 5
    u, s_, wv = hx.col("CPU_ALL", "User%"), hx.col("CPU_ALL", "Sys%"), hx.col("CPU_ALL", "Wait%")
    rows = []
    for label, arr in (("busy (user+sys)", busy), ("user", u), ("sys", s_), ("wait (iowait)", wv),
                       ("idle", hx.col("CPU_ALL", "Idle%")), ("steal", hx.col("CPU_ALL", "Steal%"))):
        if arr is None:
            continue
        s = series_stats(arr, hx.times)
        rows.append([label, s["mean"], s["median"], s["p95"], s["max"], _extreme_time(s), s["min"]])
    rep.table("Сводка CPU_ALL, %", ["метрика", "avg", "median", "p95", "max", "время max", "min"], rows,
              note=_t1_note(hx, "все статистики — без первых снимков файлов (T0001, неполный интервал)")
                   + "; на Linux nmon включает в sys время irq и softirq (обработка прерываний, сеть)")
    ncpu = host.ncpus()
    thr_rows = []
    for thr in (50, 70, 80, 90, 95):
        thr_rows.append([f"busy > {thr}%", time_above(busy, thr, sdt), 100.0 * count_above(busy, thr) / max(1, len(clean(busy)))])
    if wv is not None:
        for thr in (5, 10, 25):
            thr_rows.append([f"wait > {thr}%", time_above(wv, thr, sdt), 100.0 * count_above(wv, thr) / max(1, len(clean(wv)))])
    rep.table("Время выше порогов", ["условие", "время", "% снимков"], thr_rows, prec={"время": "dur", "% снимков": 1})
    peaks = top_peaks(busy, hx.times, n=top, min_gap=2)
    peak_rows = []
    rq = hx.col("PROC", "Runnable")
    for t, v in peaks:
        i = hx.times.index(t)
        peak_rows.append([t, v, u[i] if u is not None else NAN, s_[i] if s_ is not None else NAN,
                          wv[i] if wv is not None else NAN, rq[i] if rq is not None else NAN,
                          _top_proc_at(hx, i)])
    rep.table("Пики busy", ["время", "busy%", "user%", "sys%", "wait%", "runq", "топ-процесс"], peak_rows)
    ep_cols = ["начало", "конец", "длительность", "max%", "avg%", "топ-процесс"]
    # пороги эпизодов — те же, что у events и CPU_SATURATION_RUN (WARN правил health с учётом --thr)
    lv = episode_levels(_opt(args, "thresholds", None), ncpu)
    ep = _episodes(hx, busy, lv["cpu.busy"][0], min_len=2)
    if ep:
        rep.table(f"Эпизоды насыщения: busy > {lv['cpu.busy'][0]:g}% (WARN CPU_SATURATION) два и более снимка подряд",
                  ep_cols, ep[:top], total=len(ep), prec={"длительность": "dur"})
    if wv is not None:
        epw = _episodes(hx, wv, lv["cpu.wait"][0], min_len=2)
        if epw:
            rep.table(f"Эпизоды iowait > {lv['cpu.wait'][0]:g}% (WARN CPU_WAIT) два и более снимка подряд", ep_cols,
                      epw[:top], total=len(epw), prec={"длительность": "dur"})
    # Ядра
    if hx.cpu_cores:
        core_max = _core_busy_max(hx)
        hot = _core_hot_count(hx)
        s = series_stats(core_max, hx.times)
        per_core = []
        for core in hx.cpu_cores:
            cu, cs = hx.col(core, "User%"), hx.col(core, "Sys%")
            cb = [a + b if (a == a and b == b) else NAN for a, b in zip(cu, cs)] if cu is not None and cs is not None else []
            per_core.append((core, fmean(cb), percentile(cb, 95), fmax(cb), time_above(cb, 90, sdt)))
        # ядра без данных (offline/hotplug, файлы с разным числом CPU): NaN в ключе сортировки ломает порядок
        nodata = [x[0] for x in per_core if x[1] != x[1]]
        per_core = [x for x in per_core if x[1] == x[1]]
        means = [x[1] for x in per_core]
        cv = fstdev(means) / fmean(means) if fmean(means) > 0 else NAN
        hot_low = [hx.times[i] for i in range(hx.n()) if hot[i] > 0 and busy[i] == busy[i] and busy[i] < 50]
        hep = _hot_core_episodes(hx)
        ncores = len(hx.cpu_cores)
        # каждое число — отдельным ключом (в JSON — число; составная строка «X / Y» была бы неразбираемой)
        kv = [("ядер (логических CPU)", ncores)]
        if nodata:
            kv.append(("ядер с данными", len(per_core)))
        kv += [("avg busy по ядрам, %", fmean(means)),
               ("разброс средних по ядрам (CV = stdev/avg)", cv),
               ("макс. busy одного ядра avg, %", s["mean"]),
               ("макс. busy одного ядра p95, %", s["p95"]),
               ("макс. busy одного ядра max, %", s["max"]),
               ("время max (макс. busy одного ядра)", s["max_time"]),
               ("снимков, где ≥1 ядро > 90% busy", count_above(hot, 0)),
               ("снимков всего (без T0001)", hx.n()),
               ("снимков, где ≥1 ядро > 90% при общем busy < 50%", len(hot_low))]
        if hot_low:
            kv.append(("первый снимок: ядро > 90% при busy < 50%", hot_low[0]))
        if hep:
            kv += [("эпизодов горячего ядра ≥ 2 снимков подряд", len(hep)),
                   ("самый длинный эпизод горячего ядра", hep[0]["dur"])]
        if nodata:
            kv.append(("нет данных (ядра без значений в периоде)", ", ".join(nodata)))
        rep.kv("Ядра", kv, prec={"разброс средних по ядрам (CV = stdev/avg)": 2, "самый длинный эпизод горячего ядра": "dur"},
               note=_t1_note(hx, "статистика без первых снимков файлов (T0001, неполный интервал)")
                    + "; одно «горячее» ядро при низкой общей загрузке = однопоточное узкое место (например, один поток "
                      "Ignite: checkpoint, exchange, GC-поток)")
        if hep:
            rep.table("Эпизоды горячего ядра: ядро > 90% при общем busy < 50% два и более снимка подряд",
                      ["начало", "конец", "длительность", "ядро", "max%", "user%", "sys%", "avg busy%", "топ-процесс"],
                      [[x["start"], x["end"], x["dur"], x["core"] + (f" (ядер: {x['ncores']})" if x["ncores"] > 1 else ""),
                        x["max"], x["user"], x["sys"], x["busy_avg"], x["top"]] for x in hep[:top]],
                      total=len(hep), prec={"длительность": "dur"},
                      note="самые длинные первыми; ядро — чаще всего горячее в эпизоде (поток может мигрировать между ядрами, "
                           "эпизод при этом не рвётся); max/user/sys — горячего ядра в точке максимума, avg busy — общий; "
                           "sys ≫ user — обработка прерываний/softirq (на Linux nmon включает irq/softirq в Sys%, "
                           "например сеть на ядрах IRQ affinity), user — поток приложения (Ignite, GC)")
        topn = sorted(per_core, key=lambda x: (-x[4], -(x[2] if x[2] == x[2] else -1)))[:top]
        rep.table("Самые загруженные ядра", ["ядро", "avg%", "p95%", "max%", "время > 90%"], [list(x) for x in topn],
                  prec={"время > 90%": "dur"}, note="сортировка: время > 90%, затем p95")
        wait_core = []
        for core in hx.cpu_cores:
            cw = hx.col(core, "Wait%")
            if cw is not None and fmean(cw) == fmean(cw):
                wait_core.append((core, fmean(cw), fmax(cw)))
        wc = sorted(wait_core, key=lambda x: -x[1])[:3]
        if wc and wc[0][1] > 1:
            rep.table("Ядра с наибольшим iowait", ["ядро", "avg wait%", "max wait%"], [list(x) for x in wc])
    if ncpu:
        rep.kv("Контекст", [("CPU (логических)", ncpu),
                            ("busy в «ядрах» (avg)", fmean(busy) / 100.0 * ncpu if ncpu else NAN),
                            ("busy в «ядрах» (p95)", percentile(busy, 95) / 100.0 * ncpu if ncpu else NAN)])
    return rep


def _top_proc_at(host, i):
    procs = host.top[i] if i < len(host.top) else []
    if not procs:
        return "-"
    p = max(procs, key=lambda p: p.cpu if p.cpu == p.cpu else -1)
    return f"{p.cmd}[{p.pid}] {p.cpu:.0f}%"


def analyze_cores(host, args=None):
    rep = Report("Загрузка по ядрам (логическим CPU)", host.name)
    if not host.cpu_cores:
        rep.text("", "Секции CPUnnn отсутствуют")
        return rep
    # все статистики — без первых снимков файлов (T0001, неполный интервал: ложные 100% на ядре)
    hx = host.without_first()
    sdt = _snap_dt(hx)
    rows = []
    core_busy = {}
    core_sys = {}
    for core in hx.cpu_cores:
        cu, cs, cw, cst = (hx.col(core, "User%"), hx.col(core, "Sys%"), hx.col(core, "Wait%"),
                           hx.col(core, "Steal%"))
        cb = [a + b if (a == a and b == b) else NAN for a, b in zip(cu, cs)] if cu is not None and cs is not None \
            else [NAN] * hx.n()
        core_busy[core] = cb
        core_sys[core] = cs
        rows.append([core, fmean(cb), percentile(cb, 95), fmax(cb), fmean(cu), fmean(cs),
                     fmean(cw) if cw is not None else NAN, fmax(cst) if cst is not None else NAN,
                     time_above(cb, 90, sdt)])
    sort = _opt(args, "sort", "p95") or "p95"
    key = {"avg": 1, "p95": 2, "max": 3, "sys": 5, "wait": 6}.get(sort, 2)
    rows.sort(key=lambda r: -(r[key] if r[key] == r[key] else -1))
    top = _opt(args, "top", None)
    total = len(rows)
    if top:
        rows = rows[:top]
    rep.table("Ядра", ["ядро", "avg busy%", "p95 busy%", "max busy%", "avg user%", "avg sys%",
                       "avg wait%", "max steal%", "время > 90%"], rows, total=total, prec={"время > 90%": "dur"},
              note="сортировка: " + sort + "; " + _t1_note(hx, "без первых снимков файлов (T0001, неполный интервал)")
                   + "; на Linux sys включает irq/softirq: ядра, обслуживающие прерывания сетевых карт, выше по sys")
    # Топология из lscpu: все NUMA-узлы, сколько их есть
    lscpu = host.lscpu()
    topo = [(k, lscpu[k]) for k in ("Socket(s)", "Core(s) per socket", "Thread(s) per core", "NUMA node(s)") if k in lscpu]
    topo += sorted([(k, v) for k, v in lscpu.items() if re.match(r"^NUMA node\d+ CPU\(s\)$", k)],
                   key=lambda kv: int(re.search(r"\d+", kv[0]).group()))
    if "On-line CPU(s) list" in lscpu:
        topo.append(("On-line CPU(s) list", lscpu["On-line CPU(s) list"]))
    if topo:
        rep.kv("Топология (lscpu)", topo)
    # Ядра, которые почти не используются (cpuset/isolcpus/IRQ-only), и разбивка по NUMA/сокетам
    core_avg = {c: fmean(cb) for c, cb in core_busy.items()}
    idle = [c for c, v in core_avg.items() if v == v and v < 1.0]
    if idle and len(idle) < len(hx.cpu_cores):
        rep.text("Почти неиспользуемые ядра (avg busy < 1%)", ", ".join(idle) +
                 " — возможны cpuset/isolcpus/taskset ограничения или IRQ-only ядра; эффективное число CPU меньше номинального")
    numa = host.numa_map()
    if len(numa) > 1:
        nrows = []
        for node, cpus in sorted(numa.items()):
            cores = [f"CPU{c + 1:03d}" for c in cpus if f"CPU{c + 1:03d}" in core_busy]
            if not cores:
                continue
            vals = [core_avg[c] for c in cores if core_avg[c] == core_avg[c]]
            per_snap = []
            for i in range(hx.n()):
                v = [core_busy[c][i] for c in cores if core_busy[c][i] == core_busy[c][i]]
                per_snap.append(sum(v) / len(v) if v else NAN)
            nrows.append([f"node{node}", len(cores), fmean(vals), percentile(per_snap, 95), fmax(per_snap),
                          fmean([fmean(core_sys[c]) for c in cores])])
        rep.table("Загрузка по NUMA-узлам (avg busy ядер узла)", ["NUMA", "ядер", "avg%", "p95%", "max%", "avg sys%"], nrows,
                  note="нумерация nmon CPUnnn = номер CPU ОС + 1; сильный перекос между узлами = проблемы affinity/IRQ/numactl; "
                       "avg sys% выше на узле, к которому привязаны прерывания сетевых карт (на Linux sys включает irq/softirq)")
    topo_ci = host.cpuinfo_topology()
    if topo_ci:
        phys = defaultdict(list)
        for p, (sock, coreid) in topo_ci.items():
            phys[(sock, coreid)].append(f"CPU{p + 1:03d}")
        both_busy = 0
        any_busy = 0
        for i in range(hx.n()):
            b2 = 0
            b1 = 0
            for sibs in phys.values():
                vals = [core_busy[c][i] for c in sibs if c in core_busy and core_busy[c][i] == core_busy[c][i]]
                if not vals:
                    continue
                if max(vals) > 80:
                    b1 += 1
                if len(vals) > 1 and min(vals) > 80:
                    b2 += 1
            both_busy = max(both_busy, b2)
            any_busy = max(any_busy, b1)
        rep.kv("Физические ядра (по /proc/cpuinfo)", [
            ("физических ядер", len(phys)), ("логических CPU", len(topo_ci)),
            ("макс. физических ядер с хотя бы одним потоком > 80%", any_busy),
            ("макс. физических ядер с обоими HT-потоками > 80%", both_busy),
        ], note=_t1_note(hx, "без первых снимков файлов") + "; если оба HT-потока ядра заняты, реальная производительность "
                                                            "на поток ниже номинальной")
    # Прерывания по CPU с загрузки ОС (BBBP /proc/stat): nmon за период записи irq/softirq от sys не отделяет
    ps = host.proc_stat()
    per = []
    for cpu, d in sorted((ps or {}).get("cpus", {}).items()):
        t = sum(d.values())
        if t > 0:
            per.append([f"CPU{cpu + 1:03d}", 100.0 * d["softirq"] / t, 100.0 * d["irq"] / t, 100.0 * d["system"] / t,
                        100.0 * (d["user"] + d["nice"]) / t, 100.0 * d["iowait"] / t, d["softirq"]])
    soft_total = sum(x[6] for x in per)
    if per and soft_total > 0:
        ag = ps["cpu"] or {f: sum(d[f] for d in ps["cpus"].values()) for f in next(iter(ps["cpus"].values()))}
        at = sum(ag.values())
        k = max(1, len(per) // 4)
        hot_soft = sorted(per, key=lambda x: -x[6])[:k]
        conc = 100.0 * sum(x[6] for x in hot_soft) / soft_total
        ks = ag["system"] + ag["irq"] + ag["softirq"]
        rep.kv("Прерывания с загрузки ОС (BBBP /proc/stat, до начала записи)", [
            ("irq, % времени всех CPU", 100.0 * ag["irq"] / at if at else NAN),
            ("softirq, % времени всех CPU", 100.0 * ag["softirq"] / at if at else NAN),
            ("доля irq+softirq в system+irq+softirq (≈ Sys% nmon), %", 100.0 * (ag["irq"] + ag["softirq"]) / ks if ks else NAN),
            ("доля softirq на 25% CPU с наибольшим softirq, %", conc),
            ("CPU в этой четверти", k)],
            prec={"irq, % времени всех CPU": 2, "softirq, % времени всех CPU": 2},
            note="средние с загрузки ОС до старта nmon (BBBP /proc/stat), а не за период записи; nmon для Linux включает "
                 "irq и softirq в Sys%: CPU, обслуживающие прерывания/softirq сетевых карт (IRQ affinity, RSS/RPS), "
                 "выглядят загруженнее по sys")
        per.sort(key=lambda x: (-x[1], x[0]))
        rep.table("CPU с наибольшей долей softirq с загрузки ОС (BBBP /proc/stat)",
                  ["ядро", "softirq%", "irq%", "system%", "user%", "iowait%"], [x[:6] for x in per[:top or 5]],
                  total=len(per), prec={"softirq%": 2, "irq%": 2},
                  note="% от всего времени этого CPU с загрузки ОС (user — с nice); имя ядра — как в nmon (CPUnnn = cpu ОС + 1)")
        if conc > 75:
            # сколько CPU (с наибольшим softirq) набирают 75% всего softirq
            acc, most = 0, []
            for x in sorted(per, key=lambda x: -x[6]):
                if acc >= 0.75 * soft_total:
                    break
                acc += x[6]
                most.append(x[0])
            rep.text("Концентрация прерываний",
                     f"{conc:.0f}% времени softirq с загрузки ОС приходится на четверть CPU ({k} из {len(per)}), 75% — "
                     f"на {len(most)} CPU ({', '.join(sorted(most, key=lambda c: int(c[3:])))}): обработка прерываний/"
                     "softirq (обычно сеть) сосредоточена на части ядер (IRQ affinity, RSS/RPS); эти CPU выглядят "
                     "загруженнее по sys и при росте трафика первыми становятся узким местом")
    return rep


def _timed_runs(host, arr, thr, min_len=2, max_gap=5.0, instant=False):
    """Эпизоды arr > thr не короче min_len снимков подряд: [(начало, конец, max, длительность с)]. Длительность — по
    меткам времени + шаг (короткие пропуски снимков внутри эпизода входят в неё); на пропуске данных > max_gap
    интервалов (другой файл, перезапуск nmon) эпизод разрывается. instant — мгновенная метрика (Runnable, Blocked:
    значение в момент снимка, а не среднее за интервал): длительность — только наблюдённый промежуток между первым и
    последним отсчётом, без шага, и эпизод рвёт любой пропуск снимка (> 1.5 интервала)."""
    if instant:
        max_gap = 1.5
    out = []
    for s, e, _mx in runs_above(arr, thr, min_len=1):
        a = s
        for i in range(s, e + 1):
            if i < e and (host.times[i + 1] - host.times[i]).total_seconds() <= max_gap * host.pair_iv(i):
                continue
            if i - a + 1 >= min_len:
                out.append((a, i, max(arr[a:i + 1]),
                            (host.times[i] - host.times[a]).total_seconds() + (0.0 if instant else host.iv(a))))
            a = i + 1
    return out


# Мгновенные метрики (значение в момент снимка, а не среднее за интервал): эпизоды — _timed_runs(instant=True)
INSTANT_METRICS = ("proc.runq", "proc.blocked")
# Насыщение физического диска (DISK_BUSY_SUSTAINED, DISK_BUSY_RUN, эпизоды disk.busy_max в events), busy %
DISK_BUSY_HIGH = 90.0


def blocked_levels(thr, ncpu):
    """Действующие пороги BLOCKED_HIGH -> (WARN, CRIT, подпись). По умолчанию масштабируются с числом CPU: WARN =
    max(5, CPU/8), CRIT = max(20, 4×WARN). Значения, явно заданные в --thr BLOCKED_HIGH=WARN[,CRIT], применяются как есть
    (CRIT — не мягче WARN); незаданный CRIT при явном WARN — max(CRIT по умолчанию, 4×WARN)."""
    w, c = _thr(thr, "BLOCKED_HIGH")
    o = thr.get("BLOCKED_HIGH") if thr else None
    w_set = bool(o) and o[0] is not None
    c_set = bool(o) and len(o) > 1 and o[1] is not None
    w_eff = w if w_set or not ncpu else max(w, ncpu / 8.0)
    c_eff = max(c, w_eff) if c_set else max(c, w_eff * 4)
    lbl = "BLOCKED_HIGH из --thr" if w_set else ("max(BLOCKED_HIGH, CPU/8)" if ncpu else "BLOCKED_HIGH")
    return w_eff, c_eff, lbl


def episode_levels(thr, ncpu):
    """Пороги эпизодов превышения — WARN правил health за весь период с учётом --thr, одни для cpu (эпизоды насыщения и
    iowait), events («Эпизоды превышения порогов») и эпизодных правил health CPU_SATURATION_RUN / RUNQ_RUN /
    DISK_BUSY_RUN / BLOCKED_RUN: {метрика: (порог, откуда)}; proc.runq — только при известном числе CPU."""
    w_bl, _c, lbl = blocked_levels(thr, ncpu)
    out = {"cpu.busy": (_thr(thr, "CPU_SATURATION")[0], "CPU_SATURATION"), "cpu.wait": (_thr(thr, "CPU_WAIT")[0], "CPU_WAIT"),
           "cpu.steal": (_thr(thr, "CPU_STEAL")[0], "CPU_STEAL"), "disk.busy_max": (DISK_BUSY_HIGH, "DISK_BUSY_RUN"),
           "proc.blocked": (w_bl, lbl)}
    if ncpu:
        out["proc.runq"] = (_thr(thr, "RUNQ_HIGH")[0] * ncpu, "RUNQ_HIGH × CPU")
    return out


def _episodes(host, arr, thr, min_len=2):
    """Непрерывные эпизоды arr > thr длиной ≥ min_len снимков: [начало, конец, длительность (с), max, avg, топ-процесс]."""
    rows = []
    for s, e, mx, dur in _timed_runs(host, arr, thr, min_len=min_len):
        seg = [v for v in arr[s:e + 1] if v == v]
        rows.append([host.times[s], host.times[e], dur, mx, sum(seg) / len(seg) if seg else NAN,
                     _top_proc_at(host, s + argmax(arr[s:e + 1]))])
    rows.sort(key=lambda r: -(r[3] if r[3] == r[3] else 0))
    return rows


def _hot_core_episodes(host, thr=90.0, busy_below=50.0, min_len=2):
    """Эпизоды «горячего ядра»: в каждом снимке какое-то ядро > thr при общем busy < busy_below, ≥ min_len снимков
    подряд. Ищутся по ряду-индикатору, поэтому миграция потока между ядрами эпизод не рвёт. Самые длинные первыми:
    [{start, end, dur (с), core — чаще всего горячее, ncores, max, user, sys — у горячего ядра в точке максимума,
    busy_avg — общий, top — топ-процесс в точке максимума, s, e — индексы}]."""
    busy = host.cpu_busy()
    if busy is None or not host.cpu_cores:
        return []
    vals, names = _core_busy_argmax(host)
    hit = [1.0 if (v == v and v > thr and b == b and b < busy_below) else 0.0 for v, b in zip(vals, busy)]
    out = []
    for s, e, _m, dur in _timed_runs(host, hit, 0.5, min_len=min_len):
        im = max(range(s, e + 1), key=lambda i: vals[i])
        cnt = {}
        for c in names[s:e + 1]:
            cnt[c] = cnt.get(c, 0) + 1
        out.append({"start": host.times[s], "end": host.times[e], "dur": dur, "core": max(cnt, key=cnt.get),
                    "ncores": len(cnt), "max": vals[im], "user": host.col(names[im], "User%")[im],
                    "sys": host.col(names[im], "Sys%")[im], "busy_avg": fmean(busy[s:e + 1]),
                    "top": _top_proc_at(host, im), "s": s, "e": e})
    out.sort(key=lambda x: (-x["dur"], x["start"]))
    return out


def analyze_mem(host, args=None):
    rep = Report("Память", host.name)
    if not host.has("MEM"):
        rep.text("", "Секция MEM отсутствует")
        return rep
    if host.col("MEM", "memtotal") is None or host.col("MEM", "memfree") is None:
        rep.text("", "Секция MEM без колонок memtotal/memfree (не Linux-формат nmon, например AIX): колонки: "
                     + ", ".join(host.cols("MEM")) + "; используйте export --section MEM")
        return rep
    total = fmax(host.col("MEM", "memtotal"))
    off = host.mem_avail_offset()
    # все ряды — без первого снимка каждого файла/запуска (T0001), как в report, health и cluster: один минимум avail
    # и memfree во всех командах; калибровка avail (опорный снимок, MemAvailable) вычислена в build() по полному ряду
    hx = host.without_first()
    rows = []
    for label, arr in (("memfree", hx.col("MEM", "memfree")), ("cached (включая shmem)", hx.col("MEM", "cached")),
                       ("buffers", hx.col("MEM", "buffers")), ("used (total-free-cached-buffers)", hx.mem_used()),
                       ("avail ≈ free+buffers+(cached−shmem)+slab", hx.mem_avail()),
                       ("avail с калибровкой по MemAvailable (≈ ядро)", hx.mem_avail_calibrated() if off > 0 else None),
                       ("active", hx.col("MEM", "active")), ("inactive", hx.col("MEM", "inactive")),
                       ("memshared (Shmem/tmpfs)", hx.col("MEM", "memshared")),
                       ("swap used", hx.swap_used()), ("swapcached", hx.col("MEM", "swapcached"))):
        if arr is None:
            continue
        c = clean(arr)
        if not c or all(v < 0 for v in c):
            continue
        s = series_stats(arr, hx.times)
        rows.append([label, s["first"], s["mean"], s["min"], _extreme_time(s, "min"), s["max"], _extreme_time(s), s["last"],
                     100.0 * s["last"] / total if total else NAN])
    mi = host.meminfo()
    calib = ""
    ref = host.mem_avail_anchor()
    if mi.get("MemAvailable") is not None:
        calib = f"; MemAvailable ядра на старте = {fmt_bytes_kb(mi['MemAvailable'])}"
        if ref:
            calib += (f" (оценка avail в снимке {ref['snap']} рядом с BBBP{' @ ' + ts(ref['time']) if ref['time'] else ''}"
                      f" = {fmt_mb(ref['est'])})")
        if off > 0:
            calib += (f"; поправка калибровки −{fmt_mb(off)}" + (f" ({100.0 * off / total:.1f}% RAM)" if total == total and total > 0 else "")
                      + " — резервы ядра (watermarks), постоянны в MB; вычитается из оценки во всём периоде")
        elif host.mem_avail_reason():
            calib += f"; без калибровки: {host.mem_avail_reason()}"
    elif host.mem_avail_reason():
        calib = (f"; без калибровки: {host.mem_avail_reason()} (avail — оценка, выше MemAvailable ядра на резервы "
                 "watermarks)")
    rep.table("Сводка MEM (значения в MB; в тексте — в удобных единицах)",
              ["метрика", "начало", "avg", "min", "время min", "max", "время max", "конец", "% от total (конец)"],
              rows, prec={"начало": "mb", "avg": "mb", "min": "mb", "max": "mb", "конец": "mb"},
              note=f"memtotal = {fmt_mb(total)}; swaptotal = {fmt_mb(fmax(host.col('MEM', 'swaptotal')))}{calib}; "
                   + _t1_note(hx, "без первого снимка каждого файла/запуска (T0001), как в report/health/cluster"))
    # Тренды
    trows = []
    for label, arr, limit in (("used", hx.mem_used(), total), ("cached", hx.col("MEM", "cached"), None),
                              ("memfree", hx.col("MEM", "memfree"), None),
                              ("swap used", hx.swap_used(), fmax(host.col("MEM", "swaptotal")))):
        if arr is None:
            continue
        tr = trend(arr, hx.times)
        last = series_stats(arr, hx.times)["last"]
        tte = time_to_limit(last, tr["slope_per_h"], limit) if limit else NAN
        trows.append([label, tr["slope_per_h"], tr["r2"], tr["delta"],
                      tte * 3600 if (tte == tte and _reliable_trend(tr)) else NAN])
    rep.table("Тренды (линейная регрессия)", ["метрика", "наклон, MB/ч", "r²", "конец − начало", "до исчерпания при таком росте"],
              trows, prec={"наклон, MB/ч": 0, "r²": 2, "конец − начало": "mb", "до исчерпания при таком росте": "dur"},
              note="r² близко к 1 = устойчивый линейный рост (утечка/накопление); низкое r² = колебания; "
                   "«конец − начало» — разница последнего и первого значений (не из регрессии); "
                   f"время до исчерпания показано только при r² ≥ {TREND_R2_MIN:g} (как в MEM_GROWTH)")
    # Минимум свободной памяти и что было в этот момент
    avail = hx.mem_avail()
    i = argmin(avail)
    if i >= 0:
        ctx = [("время", hx.times[i]), ("avail, MB", avail[i])]
        if off > 0:
            ctx.append(("avail с калибровкой, MB", avail[i] - off))
        ctx += [("memfree, MB", hx.col("MEM", "memfree")[i]), ("cached, MB", hx.col("MEM", "cached")[i])]
        kver = host.kernel_version()
        for name in ("vm.pageoutrun", "vm.pgmajfault", "vm.pswpout", "vm.allocstall"):
            r = resolve_metric(hx, name)
            if r and r[2]:  # без секции VM ряды vm.* пустые
                if name == "vm.allocstall" and fsum(r[2]) == 0 and kver >= (4, 10):
                    ctx.append((name, f"n/a (ядро {kver[0]}.{kver[1]}: счётчик переименован в /proc/vmstat, nmon его не собирает)"))
                else:
                    ctx.append((name, r[2][i]))
        ctx.append(("топ-процесс", _top_proc_at(hx, i)))
        rep.kv("Момент минимума доступной памяти", ctx,
               prec={"avail, MB": "mb", "avail с калибровкой, MB": "mb", "memfree, MB": "mb", "cached, MB": "mb"})
    if any(host.top):
        used = host.mem_used()
        diffs = []
        for i, procs in enumerate(host.top):
            if not procs or used is None or used[i] != used[i]:
                continue
            rss = [p.rss for p in procs if p.rss == p.rss]
            if rss:  # снимок без единой RSS (в TOP нет колонки ResSet) — не «RSS = 0»
                diffs.append(used[i] - sum(rss) / 1024.0)
        if not diffs and used is not None and any(host.top):
            rep.text("Память вне видимых процессов", "нет данных: в TOP нет колонки ResSet (RSS процессов) — разницу "
                                                     "used − Σ RSS посчитать нельзя")
        if diffs:
            shl = []
            for procs in host.top:
                v_ = [p.shlib for p in procs if p.shlib == p.shlib]
                if v_:
                    shl.append(sum(v_) / 1024.0)
            rep.kv("Память вне видимых процессов", [
                ("used − Σ RSS процессов из TOP: avg, MB", fmean(diffs)),
                ("used − Σ RSS процессов из TOP: max, MB", fmax(diffs)),
                ("Σ ShdLib (file/shmem-backed часть RSS) avg, MB", fmean(shl) if shl else NAN)],
                prec={"used − Σ RSS процессов из TOP: avg, MB": "mb", "used − Σ RSS процессов из TOP: max, MB": "mb",
                      "Σ ShdLib (file/shmem-backed часть RSS) avg, MB": "mb"},
                note="положительная разница = slab, page tables, hugetlbfs, процессы ниже порога TOP; отрицательная = в RSS входят "
                     "file-backed и shmem страницы (ShdLib), которые nmon учитывает в cached, а не в used; "
                     "анонимная часть RSS ≈ ResSet − ShdLib")
    # meminfo (BBBP)
    mi = host.meminfo()
    if mi:
        keys = ["MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree", "Dirty",
                "Writeback", "AnonPages", "Mapped", "Shmem", "Slab", "SReclaimable", "SUnreclaim", "KernelStack",
                "PageTables", "CommitLimit", "Committed_AS", "AnonHugePages", "HugePages_Total", "HugePages_Free",
                "Hugepagesize", "Hugetlb", "Unevictable", "Mlocked"]
        counts = ("HugePages_Total", "HugePages_Free")
        items = [(k, mi[k]) for k in keys if k in mi]
        note = "однократный снимок в момент запуска nmon, не временной ряд; в JSON — числа в KB"
        promised = "Committed_AS − AnonPages − Shmem"
        if "Committed_AS" in mi and "AnonPages" in mi:
            pv = mi["Committed_AS"] - mi["AnonPages"] - mi.get("Shmem", 0)
            items.append((promised, pv))
            note += ("; Committed_AS − AnonPages − Shmem — верхняя оценка обещанной, но не занятой памяти (выделено процессам: "
                     "heap, data regions, стеки потоков, арены malloc, — но ещё не тронуто): если сопоставимо с MemAvailable "
                     "или больше — при заполнении уже выделенной памяти page cache будет вытесняться, растёт риск reclaim/OOM")
            if mi.get("MemAvailable"):
                note += f" (сейчас {100.0 * pv / mi['MemAvailable']:.0f}% от MemAvailable)"
        rep.kv("/proc/meminfo на старте nmon (BBBP), значения в KB", items,
               prec={**{k: "kb" for k in keys if k not in counts}, promised: "kb"}, note=note)
    return rep


def analyze_vm(host, args=None):
    rep = Report("Подкачка и виртуальная память (VM)", host.name)
    if not host.has("VM"):
        rep.text("", "Секция VM отсутствует")
        return rep
    rows = []
    specs = [
        ("pgpgin, KB/s", "vm.pgpgin"), ("pgpgout, KB/s", "vm.pgpgout"),
        ("pswpin, pages/интервал", "vm.pswpin"), ("pswpout, pages/интервал", "vm.pswpout"),
        ("pgfault, /s", "vm.pgfault"), ("pgmajfault, /s", "vm.pgmajfault"),
        ("kswapd_steal, pages/интервал", "vm.kswapd_steal"), ("pgscan_kswapd, pages/интервал", "vm.pgscan_kswapd"),
        ("pgscan_direct, pages/интервал", "vm.pgscan_direct"), ("pgsteal, pages/интервал", "vm.pgsteal"),
        ("allocstall, /интервал", "vm.allocstall"), ("pageoutrun, /интервал", "vm.pageoutrun"),
        ("slabs_scanned, /интервал", "vm.slabs_scanned"), ("pgdeactivate, pages/интервал", "vm.pgdeactivate"),
        ("pgactivate, pages/интервал", "vm.pgactivate"),
        ("nr_dirty, MB", "vm.nr_dirty"), ("nr_writeback, MB", "vm.nr_writeback"),
        ("nr_mapped, MB", "vm.nr_mapped"), ("nr_slab_reclaimable, MB", "vm.nr_slab"),
        ("nr_page_table_pages, MB", "vm.nr_page_table"),
    ]
    # avg/p95/max и «снимков > 0» — без первого снимка каждого файла/запуска (T0001: приращение за 1–2 с, как в report и
    # health); «сумма за период» — по всем снимкам (приращение T0001 — реальные события)
    hx = host.without_first()
    for label, name in specs:
        r = resolve_metric(hx, name)
        if not r:
            continue
        arr = r[2]
        s = series_stats(arr, hx.times)
        nz = sum(1 for v in arr if v == v and v > 0)
        rows.append([label, s["mean"], s["p95"], s["max"], _extreme_time(s),
                     fsum(resolve_metric(host, name)[2]) if "интервал" in label else NAN, nz])
    rep.table("Сводка VM", ["метрика", "avg", "p95", "max", "время max", "сумма за период", "снимков > 0"], rows,
              prec={"avg": 1, "p95": 1, "max": 1, "сумма за период": 0},
              note="pgpgin/pgpgout — обмен с блочными устройствами (включая page cache); "
                   "pswpin/pswpout > 0 = реальная подкачка (swap); pgscan_direct/allocstall > 0 = прямой reclaim "
                   "(процесс сам ждёт освобождения памяти); kswapd_* = фоновый reclaim; "
                   "/s — по фактическому шагу между снимками файла (после разрыва — среднее за весь разрыв), "
                   "«за интервал» — приращение с предыдущего снимка (после разрыва покрывает весь разрыв); "
                   + _t1_note(hx, f"avg/p95/max и «снимков > 0» — без первого снимка каждого файла/запуска (T0001; "
                                  f"{hx.n()} снимков)") + f"; «сумма за период» — по всем {host.n()} снимкам")
    nd = resolve_metric(hx, "vm.nr_dirty")
    wb = resolve_metric(hx, "vm.nr_writeback")
    dw = resolve_metric(hx, "disk.write")
    if nd and clean(nd[2]):
        kv = [("nr_dirty avg, MB", fmean(nd[2])), ("nr_dirty max, MB", fmax(nd[2])),
              ("время max nr_dirty", _extreme_time(series_stats(nd[2], hx.times)))]
        if dw and fmean(dw[2]) > 0:
            kv.append(("время сброса max dirty при средней скорости записи", fmax(nd[2]) * 1024.0 / fmean(dw[2])))
        if wb and clean(wb[2]):
            kv += [("nr_writeback max, MB", fmax(wb[2])), ("снимков с nr_writeback > 0", count_above(wb[2], 0)),
                   ("снимков всего (без T0001)", hx.n())]
        rep.kv("Грязные страницы page cache (ожидают записи на диск)", kv,
               note="большой dirty-backlog в момент fsync = долгий fsync (WAL, завершение checkpoint); "
                    "постоянно ненулевой nr_writeback = диск не успевает за сбросом",
               prec={"время сброса max dirty при средней скорости записи": "dur", "nr_dirty avg, MB": "mb",
                     "nr_dirty max, MB": "mb", "nr_writeback max, MB": "mb"})
    # Интерпретация
    notes = []
    for name, text in (("vm.pswpout", "были выгрузки в swap"), ("vm.pswpin", "были загрузки из swap"),
                       ("vm.allocstall", "были direct-reclaim stalls (нехватка памяти, задержки в аллокациях)"),
                       ("vm.pgscan_direct", "было прямое сканирование страниц (memory pressure)"),
                       ("vm.kswapd_steal", "kswapd освобождал страницы (фоновый reclaim, давление на page cache)"),
                       ("vm.pageoutrun", "kswapd просыпался (фоновый reclaim: свободной памяти меньше watermark)"),
                       ("vm.slabs_scanned", "сканировался slab (reclaim затронул кэши ядра)")):
        r = resolve_metric(hx, name)
        if r and count_above(r[2], 0) > 0:
            notes.append(f"{name}: {text}; снимков > 0: {count_above(r[2], 0)} из {hx.n()}"
                         f"{'' if hx.firsts_kept else ' (без T0001)'}, сумма за период: "
                         f"{fsum(resolve_metric(host, name)[2]):.0f}")
    ks = resolve_metric(hx, "top.kswapd.cpu")
    if ks and count_above(ks[2], 0) > 0:
        seen = [v for v in ks[2] if v == v and v > 0]  # среднее — по снимкам, где kswapd виден в TOP
        notes.append(f"kswapd* в TOP (сумма по всем kswapdN): {len(seen)} снимков, CPU avg {fmean(seen):.1f}%, "
                     f"max {fmax(seen):.1f}% — фоновый reclaim работает")
        per = defaultdict(list)  # по каждому kswapdN (обычно один на NUMA-узел) — справочно
        for procs in host.top:
            for p in procs:
                if p.cmd.startswith("kswapd") and p.cpu == p.cpu:
                    per[p.cmd].append(p.cpu)
        if per:
            notes.append("по процессам: " + "; ".join(f"{k}: {len(v)} снимков, CPU max {fmax(v):.1f}%"
                                                      for k, v in sorted(per.items(), key=lambda kv: (len(kv[0]), kv[0]))))
    if notes:
        rep.text("Признаки давления на память", "\n".join(notes))
    else:
        rep.text("Признаки давления на память", "не обнаружены (нет swap-активности и reclaim)")
    dead = [c for c in ("kswapd_steal", "allocstall", "pgscan_kswapd_normal", "pgscan_direct_normal", "pgsteal_normal", "pgrefill_normal")
            if host.col("VM", c) is not None and fmax(host.col("VM", c)) == 0]
    if dead:
        kver = host.kernel_version()
        rep.text("Замечание о ядре", "колонки " + ", ".join(dead) + f" равны 0 за весь период (ядро {kver[0]}.{kver[1]}). "
                 "В /proc/vmstat эти счётчики переименованы: kswapd_steal/pgsteal_normal → pgsteal_kswapd/pgsteal_direct (ядро ≥ 3.4), "
                 "pgscan_*_normal/pgrefill_normal → pgscan_kswapd/pgscan_direct/pgrefill (≥ 4.8), allocstall → allocstall_* (≥ 4.10); "
                 "nmon читает старые имена и получает 0. На RHEL/CentOS 7 (3.10) allocstall и pgscan_*_normal ещё работают. "
                 "Признаки reclaim на новых ядрах смотрите по pageoutrun, slabs_scanned, pgdeactivate, kswapd* в TOP, memfree.")
    return rep


def analyze_proc(host, args=None):
    rep = Report("Планировщик: очередь, блокировки, переключения контекста", host.name)
    if not host.has("PROC"):
        rep.text("", "Секция PROC отсутствует")
        return rep
    ncpu = host.ncpus()
    # все статистики — без первых снимков файлов (T0001: неполный интервал, pswitch/fork там 0)
    hx = host.without_first()
    sdt = _snap_dt(hx)
    top = _opt(args, "top", 5) or 5
    rows = []
    for label, col in (("Runnable (очередь)", "Runnable"), ("Blocked (D-state)", "Blocked"),
                       ("pswitch, /s", "pswitch"), ("fork, /s", "fork"), ("syscall, /s", "syscall"),
                       ("read, /s", "read"), ("write, /s", "write"), ("exec, /s", "exec")):
        arr = hx.col("PROC", col)
        if arr is None:
            continue
        c = clean(arr)
        if not c or all(v < 0 for v in c):
            continue
        s = series_stats(arr, hx.times)
        rows.append([label, s["mean"], s["median"], s["p95"], s["max"], _extreme_time(s)])
    rep.table("Сводка PROC", ["метрика", "avg", "median", "p95", "max", "время max"], rows,
              note=f"CPU = {ncpu}; Runnable > CPU = очередь на выполнение (CPU-насыщение); Blocked = процессы в D-state "
                   f"(ждут I/O); " + _t1_note(hx, "без первых снимков файлов (T0001, неполный интервал)"))
    rq = hx.col("PROC", "Runnable")
    bl = hx.col("PROC", "Blocked")
    thr_rows = []
    if rq is not None and ncpu:
        for f in (1.0, 2.0):
            thr_rows.append([f"Runnable > {f:.0f}×CPU ({f * ncpu:.0f})", time_above(rq, f * ncpu, sdt),
                             count_above(rq, f * ncpu)])
    if bl is not None:
        for thr in (1, 5, 20):
            thr_rows.append([f"Blocked > {thr}", time_above(bl, thr, sdt), count_above(bl, thr)])
    if thr_rows:
        rep.table("Время выше порогов", ["условие", "время", "снимков"], thr_rows, prec={"время": "dur"})
    busy = hx.cpu_busy()
    sy = hx.col("CPU_ALL", "Sys%")
    psw = hx.col("PROC", "pswitch")
    if rq is not None:
        prow = []
        for t, v in top_peaks(rq, hx.times, n=top, min_gap=2):
            if v <= 0:
                continue
            i = hx.times.index(t)
            prow.append([t, v, v / ncpu if ncpu else NAN, busy[i] if busy is not None else NAN,
                         sy[i] if sy is not None else NAN, psw[i] if psw is not None else NAN, _top_proc_at(hx, i)])
        if prow:
            rep.table("Пики Runnable", ["время", "Runnable", "Runnable/CPU", "busy%", "sys%", "pswitch, /s", "топ-процесс"],
                      prow, prec={"Runnable/CPU": 2, "pswitch, /s": 0},
                      note="Runnable — мгновенное значение в момент снимка (не среднее за интервал); busy/sys/pswitch — за интервал")
    if bl is not None:
        peaks = top_peaks(bl, hx.times, n=top, min_gap=2)
        w = hx.col("CPU_ALL", "Wait%")
        dbusy, dwho = hx.disk_max_busy()
        prow = []
        for t, v in peaks:
            if v <= 0:
                continue
            i = hx.times.index(t)
            prow.append([t, v, w[i] if w is not None else NAN,
                         f"{dwho[i]} {dbusy[i]:.0f}%" if dbusy is not None and dbusy[i] == dbusy[i] else "-",
                         _top_proc_at(hx, i)])
        if prow:
            rep.table("Пики Blocked", ["время", "blocked", "wait%", "самый занятый диск", "топ-процесс"], prow)
    # Контекст: нормировка на CPU, связь с sys/busy, средние с загрузки ОС и load average на старте (BBBP)
    ctx = []
    prec = {}
    if clean(psw) and ncpu:
        ctx += [("pswitch на CPU avg, /s", fmean(psw) / ncpu), ("pswitch на CPU p95, /s", percentile(psw, 95) / ncpu)]
        prec.update({"pswitch на CPU avg, /s": 0, "pswitch на CPU p95, /s": 0})
    if sy is not None and clean(psw):
        ctx.append(("корреляция Sys% ↔ pswitch (Пирсон r)", pearson(sy, psw)))
        prec["корреляция Sys% ↔ pswitch (Пирсон r)"] = 2
    if busy is not None and rq is not None:
        ctx.append(("корреляция Runnable ↔ busy (Пирсон r)", pearson(rq, busy)))
        prec["корреляция Runnable ↔ busy (Пирсон r)"] = 2
    ps = host.proc_stat()
    up = host.uptime_seconds()
    if ps and up:
        if ps["ctxt"] is not None:
            ctx.append(("переключений контекста с загрузки ОС, /s (ctxt / uptime)", ps["ctxt"] / up))
            prec["переключений контекста с загрузки ОС, /s (ctxt / uptime)"] = 0
        if ps["processes"] is not None:
            ctx.append(("fork с загрузки ОС, /s (processes / uptime)", ps["processes"] / up))
    la = host.load_average()
    if la:
        for k, mins in enumerate((1, 5, 15)):
            key = f"load average {mins} мин на старте nmon (BBBP uptime)"
            ctx.append((key, la[k]))
            prec[key] = 2
        if ncpu:
            ctx.append(("load average 1 мин / CPU", la[0] / ncpu))
            prec["load average 1 мин / CPU"] = 2
        base = host.unfiltered or host
        r0, b0 = base.col("PROC", "Runnable"), base.col("PROC", "Blocked")
        for i in range(min(2, base.n())):
            if r0 is not None and b0 is not None and r0[i] == r0[i] and b0[i] == b0[i]:
                ctx += [(f"Runnable + Blocked, снимок {i + 1} данных", r0[i] + b0[i]),
                        (f"время снимка {i + 1} данных", base.times[i])]
                prec[f"Runnable + Blocked, снимок {i + 1} данных"] = 0
    if ctx:
        rep.kv("Контекст", ctx, prec=prec,
               note="pswitch/fork — в секунду; r(Sys%, pswitch) близко к 1 — доля sys объясняется переключениями контекста "
                    "(много потоков, futex/epoll, сетевой обмен); «с загрузки ОС» — средние от загрузки до старта nmon "
                    "(BBBP), для сравнения с окном записи; load average в Linux учитывает и процессы в D-state (Blocked)")
    return rep


PSEUDO_FS_TYPES = {"tmpfs", "devtmpfs", "squashfs", "overlay", "iso9660", "udf", "ramfs", "proc", "sysfs", "cgroup",
                   "cgroup2", "devpts", "mqueue", "hugetlbfs", "autofs"}
PSEUDO_DF_NAMES = {"tmpfs", "devtmpfs", "overlay", "shm"}  # колонка Filesystem у df для псевдо-ФС


def _pseudo_fs(host, mount, dfrows=None):
    """Псевдо-/служебная ФС: /dev, /run, /sys, /proc и всё под ними; тип по mount (tmpfs, squashfs, overlay…) либо
    имя в df (tmpfs, devtmpfs…). Такие точки скрываются в fs/report и не проверяются правилами FS_*."""
    if mount in ("/dev", "/run", "/sys", "/proc", "/dev/shm") or mount.startswith(("/dev/", "/run/", "/sys/", "/proc/")):
        return True
    if host.mount_info().get(mount, ("", ""))[0] in PSEUDO_FS_TYPES:
        return True
    if dfrows is None:
        dfrows = {r["mount"]: r for r in host.df()}
    return dfrows.get(mount, {}).get("filesystem", "") in PSEUDO_DF_NAMES


def _disk_mount_label(e, n=3):
    """mount устройства для таблиц и замечаний: своя точка монтирования, а у диска без своей ФС — точки монтирования
    его LV/разделов (первые n и «(+K)»)."""
    mount = e.get("mount", "") or ""
    if not mount and e.get("child_mounts"):
        cm = e["child_mounts"]
        mount = "LVM/разделы: " + ", ".join(cm[:n]) + (f" (+{len(cm) - n})" if len(cm) > n else "")
    return mount


def _disk_rows(host, devices):
    """Строки таблицы DISK_COLS; host — ряды без первых снимков файлов (host.without_first())."""
    dts = _snap_dt(host)
    dm = host.dm_map()
    dmap = {e["device"]: e for e in host.device_map()}
    rows = []
    for d in devices:
        busy = host.col("DISKBUSY", d)
        rd = host.col("DISKREAD", d)
        wr = host.col("DISKWRITE", d)
        xf = host.col("DISKXFER", d)
        sb = series_stats(busy, host.times) if busy is not None else None
        name = d + (f" ({dm[d]})" if d in dm else "")
        stalled = 0
        if busy is not None and xf is not None:
            stalled = sum(1 for b, x in zip(busy, xf) if b == b and x == x and b >= 95 and x < 1)
        svc, svc_n = _svc_estimate(busy, xf)
        rows.append([
            name, _disk_mount_label(dmap.get(d, {})),
            sb["mean"] if sb else NAN, sb["p95"] if sb else NAN, sb["max"] if sb else NAN,
            _extreme_time(sb) if sb else None,
            time_above(busy, 80, dts) if busy is not None else NAN,
            fmean(rd) if rd is not None else NAN, fmax(rd) if rd is not None else NAN,
            fmean(wr) if wr is not None else NAN, fmax(wr) if wr is not None else NAN,
            fmean(xf) if xf is not None else NAN, fmax(xf) if xf is not None else NAN,
            _io_size(rd, wr, xf),
            svc, svc_n,
            stalled,
            _integrate(host, rd, dts),
            _integrate(host, wr, dts),
        ])
    return rows


def _disk_lv_rows(host, disks):
    """Какие LV/разделы дают трафик физического диска: смонтированные устройства nmon, лежащие только на этом диске
    (по дереву lsblk), — для дисков с ≥ 2 такими потомками. Строки с долей < 1% и по чтению, и по записи пропускаются.
    host — без первых снимков файлов."""
    dm = host.dm_map()
    dmap = host.device_map()
    rows = []
    for d in disks:
        kids = [e for e in dmap if e["device"] != d and e.get("mount") and e.get("phys_list") == [d]]
        if len(kids) < 2:
            continue
        drd, dwr = fmean(host.col("DISKREAD", d)), fmean(host.col("DISKWRITE", d))
        part = []
        for e in kids:
            rd, wr = fmean(host.col("DISKREAD", e["device"])), fmean(host.col("DISKWRITE", e["device"]))
            rs = 100.0 * rd / drd if drd > 0 and rd == rd else NAN
            ws = 100.0 * wr / dwr if dwr > 0 and wr == wr else NAN
            if not ((rs == rs and rs >= 1) or (ws == ws and ws >= 1)):
                continue
            name = e["device"] + (f" ({dm[e['device']]})" if e["device"] in dm else "")
            part.append([d, name, e["mount"], rd, rs, wr, ws, percentile(host.col("DISKBUSY", e["device"]), 95)])
        part.sort(key=lambda r: -max(r[4] if r[4] == r[4] else 0.0, r[6] if r[6] == r[6] else 0.0))
        rows.extend(part)
    return rows


def _io_size(rd, wr, xf):
    """Средний размер операции, KB = Σ(read+write) / Σ IOPS (взвешенно по операциям, без искажения простоями).
    Суммируются только снимки, где известны и read/write, и IOPS (неполный снимок не смещает отношение)."""
    if xf is None:
        return NAN
    tot = ops = 0.0
    for k, x in enumerate(xf):
        r = rd[k] if rd is not None else 0.0
        w = wr[k] if wr is not None else 0.0
        if x == x and r == r and w == w:
            tot += r + w
            ops += x
    return tot / ops if ops > 0 else NAN


DISK_PREC = {"IO size avg KB": 1, "svc≈ms": 2, "svc n": 0, "stalled": 0, "время > 80%": "dur", "прочитано всего": "kb",
             "записано всего": "kb"}


def link_capacity_kbs(mbit):
    """Пропускная способность одного порта в KB/s (KiB, как в nmon) по скорости в Mbit/s (--link-mbit)."""
    return float(mbit) * 1e6 / 8.0 / 1024.0


def _is_loopback(name, flags=""):
    """Loopback: имя lo, lo0… или флаг LOOPBACK в ifconfig (flags — строка 'UP,LOOPBACK,…' или множество флагов)."""
    return bool(re.fullmatch(r"lo\d*", name)) or "LOOPBACK" in (flags or ())


NET_ZERO_KBS = 0.5       # «нулевой» трафик интерфейса (rx+tx), KB/s
NET_ZERO_MIN_P75 = 5.0   # NET_ZERO проверяется у интерфейса с обычным уровнем p75(rx+tx) ≥ 5 KB/s
NET_DROP_SHARE = 0.05    # провал трафика — ниже 5 % обычного уровня (доля фиксирована, как 10 % в JAVA_CPU_DROP)
NET_RX_DROP_SHARE = 1e-3  # NET_ERRORS: rx dropped меньше 0.1 % принятых пакетов не учитываются (резервный слейв, протоколы)
NET_TX_DROP_SHARE = 1e-5  # ... tx dropped меньше 10 ppm переданных — не учитываются (кадры при поднятии bond и т. п.)
NET_DROP_MIN_P75 = 50.0  # NET_DROP / NET_BOND_MEMBER — у интерфейса с p75(rx+tx) ≥ 50 KB/s


def _net_tot(host, iface):
    """rx + tx интерфейса по снимкам, KB/s (NaN, если нет хотя бы одного из значений); None, если колонок нет."""
    rd, wr = host.col("NET", f"{iface}-read-KB/s"), host.col("NET", f"{iface}-write-KB/s")
    if rd is None or wr is None:
        return None
    return [a + b if (a == a and b == b) else NAN for a, b in zip(rd, wr)]


def _net_level(host, iface):
    """Обычный уровень трафика интерфейса — p75(rx + tx), KB/s, по полному ряду хоста (до --from/--to/--around:
    в узком окне вокруг провала p75 был бы занижен самим провалом)."""
    tot = _net_tot(host.unfiltered if host.unfiltered is not None else host, iface)
    return percentile(tot, 75) if tot is not None else NAN


def _net_quiet_runs(host, tot, alive=None, level=None):
    """«Молчание» интерфейса относительно его обычного уровня L = p75(tot) (или level — см. _net_level),
    tot = rx + tx (KB/s) по снимкам host.
    Возвращает dict: L; thr = max(0.5, 5 % L); zero — отрезки tot < 0.5 KB/s (при L ≥ 5 KB/s); drop — провалы
    0.5 ≤ tot < thr при L ≥ 50 KB/s (снимки нулевых отрезков от 2 снимков исключены: они уже в NET_ZERO);
    quiet — все снимки tot < thr подряд при L ≥ 50 KB/s (для слейва bond). Отрезок — (start, end, min, длительность с).
    alive — маска снимков, которые проверяются (для слейва — bond ещё передаёт трафик); NaN разрывает отрезок, как и
    пропуск данных > 5 интервалов (как в _timed_runs); длительность — по меткам времени + шаг."""
    L = level if level is not None and level == level else percentile(tot, 75)
    out = {"L": L, "thr": NAN, "zero": [], "drop": [], "quiet": []}
    if L != L:
        return out
    thr = max(NET_ZERO_KBS, NET_DROP_SHARE * L)
    out["thr"] = thr

    def runs(mask):
        return [(s, e, fmin(tot[s:e + 1]), dur)
                for s, e, _m, dur in _timed_runs(host, [1.0 if ok else 0.0 for ok in mask], 0.5, min_len=1)]

    live = [alive is None or bool(alive[k]) for k in range(len(tot))]
    if L >= NET_ZERO_MIN_P75:
        out["zero"] = runs([v == v and v < NET_ZERO_KBS and a for v, a in zip(tot, live)])
    if L >= NET_DROP_MIN_P75:
        in_zero = [False] * len(tot)
        for s, e, _mn, _d in out["zero"]:
            if e > s:
                in_zero[s:e + 1] = [True] * (e - s + 1)
        out["drop"] = runs([v == v and v < thr and a and not z for v, a, z in zip(tot, live, in_zero)])
        out["quiet"] = runs([v == v and v < thr and a for v, a in zip(tot, live)])
    return out


SVC_MIN_SNAPSHOTS = 5  # svc≈ms по меньшему числу снимков с IOPS ≥ 10 не выводится


def _svc_estimate(busy, xf):
    """Оценка среднего времени обслуживания одной операции, ms = util% × 10 / IOPS (медиана по снимкам с IOPS ≥ 10).
    Это грубая нижняя оценка латентности (без учёта очереди); для NVMe с параллелизмом занижает в разы.
    Возвращает (оценка, число снимков); при числе снимков < SVC_MIN_SNAPSHOTS оценка — NaN.
    Ряды — без первых снимков файлов (T0001)."""
    if busy is None or xf is None:
        return NAN, 0
    vals = [b * 10.0 / x for b, x in zip(busy, xf) if b == b and x == x and x >= 10]
    return (fmedian(vals) if len(vals) >= SVC_MIN_SNAPSHOTS else NAN), len(vals)


DISK_COLS = ["устройство", "mount", "busy avg%", "busy p95%", "busy max%", "время max", "время > 80%",
             "read avg KB/s", "read max KB/s", "write avg KB/s", "write max KB/s", "IOPS avg", "IOPS max",
             "IO size avg KB", "svc≈ms", "svc n", "stalled", "прочитано всего", "записано всего"]


def analyze_disk(host, args=None):
    rep = Report("Диски (блочные устройства)", host.name)
    if not host.has("DISKBUSY") and not host.has("DISKREAD"):
        rep.text("", "Секции DISK* отсутствуют")
        return rep
    devs_all = host.disk_devices()
    sel = _opt(args, "dev", None)
    if sel:
        dmm = host.dm_map()

        def lv_short(d):
            # имя LV без группы томов: 'vg-lv' -> 'lv' (двойной дефис в /dev/mapper экранирует одиночный)
            name = dmm.get(d, "")
            m = re.match(r"^((?:[^-]|--)+)-(.+)$", name)
            return m.group(2).replace("--", "-") if m else name

        devices = [d for d in devs_all if any(re.fullmatch(p, d) or re.fullmatch(p, dmm.get(d, "")) or re.fullmatch(p, lv_short(d))
                                              for p in sel)]
        if not devices:
            rep.text("", f"устройства {sel} не найдены; доступны: {', '.join(devs_all)}")
            return rep
    elif _opt(args, "all", False):
        devices = devs_all
    else:
        devices = host.physical_disks()
    # Вся статистика — без первого снимка каждого файла/запуска nmon: T0001 охватывает 1–2 с старта nmon (его же
    # команды BBBP читают диск) — ложные max
    hx = host.without_first()
    rows = _disk_rows(hx, devices)
    active = [r for r in rows if not (r[2] != r[2] and r[7] != r[7])]
    active.sort(key=lambda r: -(r[3] if r[3] == r[3] else -1))
    rep.table("Устройства" + (" (все, включая разделы и dm-*)" if _opt(args, "all", False) else " (физические; разделы и dm-* см. --all или --dev)"),
              DISK_COLS, active, prec=DISK_PREC,
              note="busy% = доля времени, когда у устройства была хотя бы одна операция в очереди (util); "
                   "для NVMe/RAID 100% ещё не означает предел производительности; IO size = Σ(read+write)/Σ IOPS; "
                   f"svc≈ms = util×10/IOPS — грубая оценка времени на операцию, медиана по svc n снимкам с IOPS ≥ 10 "
                   f"(при svc n < {SVC_MIN_SNAPSHOTS} значение не выводится); для NVMe и устройств с параллельной очередью "
                   "svc≈ms занижает время операции в разы — не путать с await; для HDD/SAS сверяйте с avg ms из diskmap "
                   "(/proc/diskstats); stalled = снимков с busy ≥ 95% при IOPS < 1; "
                   "для физического диска в колонке mount перечислены точки монтирования его LV/разделов; "
                   + _t1_note(hx, "статистика без первого снимка каждого файла/запуска (T0001 — неполный интервал на старте nmon)"))
    # Всего по физическим дискам
    rt, wt, xt = hx.disk_total("DISKREAD"), hx.disk_total("DISKWRITE"), hx.disk_total("DISKXFER")
    if rt is not None:
        dts = _snap_dt(hx)
        kr, kw = _integrate(hx, rt, dts), _integrate(hx, wt, dts)
        rep.kv("Итого по физическим дискам", [
            ("read avg KB/s", fmean(rt)), ("read max KB/s", fmax(rt)),
            ("write avg KB/s", fmean(wt)), ("write max KB/s", fmax(wt)),
            ("IOPS avg", fmean(xt)), ("IOPS max", fmax(xt)),
            ("прочитано за период", kr), ("записано за период", kw),
            ("доля записи в трафике, %", 100.0 * kw / max(1e-9, kr + kw) if kr == kr and kw == kw else NAN),
        ], prec={"read avg KB/s": 0, "read max KB/s": 0, "write avg KB/s": 0, "write max KB/s": 0, "IOPS avg": 0,
                 "IOPS max": 0, "прочитано за период": "kb", "записано за период": "kb", "доля записи в трафике, %": 0},
            note=_t1_note(hx, "без первого снимка каждого файла/запуска (T0001)")
                 + "; объёмы — Σ скорости × фактический шаг снимка (после разрыва — его длительность, как в export --agg sum)")
    # Распределение трафика физического диска по его LV/разделам (только в режиме по умолчанию)
    if not sel and not _opt(args, "all", False):
        lvrows = _disk_lv_rows(hx, devices)
        if lvrows:
            rep.table("Распределение трафика по LV/разделам",
                      ["физ. диск", "устройство", "mount", "read avg KB/s", "доля read диска %", "write avg KB/s",
                       "доля write диска %", "busy p95%"], lvrows,
                      prec={"доля read диска %": 0, "доля write диска %": 0},
                      note="доля — от среднего трафика физического диска; строки с долей < 1% в обоих направлениях скрыты; "
                           "LV/RAID/multipath поверх нескольких дисков не показываются (см. disk --all); "
                           + _t1_note(hx, "без T0001"))
    # Пики записи/чтения и периодичность (checkpoint-подобные всплески)
    n_top = _opt(args, "top", 5) or 5
    for label, sec in (("записи", "DISKWRITE"), ("чтения", "DISKREAD")):
        for d in devices:
            arr = hx.col(sec, d)
            if arr is None or fmax(arr) < 1024:
                continue
            pr = periodicity(arr, hx.times, hx.step())
            # значимые пики: не ниже p90 и 10% максимума — у разреженного ряда хвост top_peaks состоит из нулей
            floor = max(percentile(arr, 90), 0.1 * fmax(arr))
            peaks = [(t, v) for t, v in top_peaks(arr, hx.times, n=n_top, min_gap=1) if v > 0 and v >= floor]
            busy = hx.col("DISKBUSY", d)
            bs = hx.col("DISKBSIZE", d)
            prow = []
            for t, v in peaks:
                i = hx.times.index(t)
                prow.append([t, v, busy[i] if busy is not None else NAN, bs[i] if bs is not None else NAN,
                             _top_proc_at(hx, i)])
            notes = []
            if pr["regular"]:
                tol = max(0.25 * pr["period"], hx.step())
                notes.append(f"всплески {label} регулярны: медианный период {fmt_dur(pr['period'])}, {pr['npeaks']} пиков ≥ p90, "
                             f"{100 * pr['share_within']:.0f}% интервалов в пределах ±{tol:.0f} с (max(25%, шаг)) от медианы")
            elif pr["period"] == pr["period"]:
                notes.append(f"пики {label} нерегулярны: {pr['npeaks']} пиков ≥ p90, медианный интервал {fmt_dur(pr['period'])}, "
                             f"разброс MAD/медиана {pr['spread']:.2f} — период не определён")
            else:
                notes.append("периодичность не оценена: мало выраженных пиков (нужно ≥ 3 локальных пиков ≥ p90 при p90 > "
                             "1.2 × медианы ряда и ≥ 2 интервалов ≥ 60 с между ними)")
            if len(prow) < n_top:
                notes.append(f"значимых пиков: {len(prow)} (≥ 10% максимума и ≥ p90)")
            if prow and fmean(arr) > 0 and (fmax(arr) > 2 * fmean(arr) or pr["regular"] or pr["npeaks"] >= 6):
                rep.table(f"Пики {label}: {d}", ["время", "KB/s", "busy%", "IO size KB", "топ-процесс"], prow,
                          note="; ".join(notes) or None)
    # Латентность (если есть)
    if hx.has("DISKREADSERV") or hx.has("DISKWRITESERV"):
        lrows = []
        for d in devices:
            rs, ws = hx.col("DISKREADSERV", d), hx.col("DISKWRITESERV", d)
            lrows.append([d, fmean(rs) if rs is not None else NAN, percentile(rs, 95) if rs is not None else NAN,
                          fmax(rs) if rs is not None else NAN, fmean(ws) if ws is not None else NAN,
                          percentile(ws, 95) if ws is not None else NAN, fmax(ws) if ws is not None else NAN])
        rep.table("Время обслуживания, ms", ["устройство", "read avg", "read p95", "read max", "write avg", "write p95", "write max"], lrows)
    return rep


def analyze_diskmap(host, args=None):
    rep = Report("Карта устройств: диск → LVM → точка монтирования", host.name)
    rows = []
    dmap = host.device_map()
    for e in dmap:
        mount = e.get("mount", "") or ""
        if not mount and e.get("child_mounts"):
            mount = "→ " + ", ".join(e["child_mounts"][:4]) + (" …" if len(e["child_mounts"]) > 4 else "")
        rows.append([e["device"], e.get("type", ""), e.get("size_mb", NAN), e.get("phys", "") or "", e.get("parent", "") or "",
                     e.get("lv", ""), mount, e.get("fstype", ""), e.get("fs_use_pct_start", NAN), (e.get("options", "") or "")[:60]])
    rep.table("Устройства nmon", ["устройство", "тип", "размер", "физ. диск", "родитель", "LV", "mount", "fs", "use% на старте", "опции монтирования"],
              rows, prec={"размер": "mb"},
              note="источники: lsblk (дерево), ls -l /dev/mapper, /proc/partitions, mount, df -m из BBBP; "
                   "«физ. диск» — корень дерева lsblk; несколько физ. дисков (и родителей) через запятую — LV/RAID/multipath "
                   "поверх нескольких устройств; для диска без своей ФС в mount перечислены точки монтирования потомков")
    dflist = host.df()
    if dflist:
        dfrows = {r["mount"]: r for r in dflist}
        rep.table("df -m на старте nmon", ["filesystem", "mount", "size", "used", "avail", "use%"],
                  [[r["filesystem"], r["mount"], r["size_mb"], r["used_mb"], r["avail_mb"], r["use_pct"]]
                   for r in dflist if not _pseudo_fs(host, r["mount"], dfrows)],
                  prec={"size": "mb", "used": "mb", "avail": "mb"},
                  note="псевдо-ФС (tmpfs, devtmpfs, squashfs, /dev, /run, /sys …) скрыты — полный вывод: bbbp --block df-m")
    ign = [e for e in dmap
           if re.search(r"ignite|wal|persist|snapshot|archive|marshaller|binary_meta|/db(/|$)|/data(/|$)",
                        (e.get("mount", "") or "") + " " + (e.get("lv", "") or ""), re.I)]
    if ign:
        rep.table("Точки монтирования, похожие на хранилище Ignite (по именам)",
                  ["устройство", "физ. диск", "LV", "mount", "fs", "размер", "use% на старте"],
                  [[e["device"], ", ".join(e.get("phys_list", [])), e.get("lv", ""), e.get("mount", ""), e.get("fstype", ""),
                    e.get("size_mb", NAN), e.get("fs_use_pct_start", NAN)] for e in ign],
                  prec={"размер": "mb"},
                  note="эвристика по именам; точные пути work/wal/walArchive/snapshots берите из конфигурации Ignite; "
                       "если несколько каталогов Ignite лежат на одном физическом диске — они конкурируют за его IOPS")
    ds = host.diskstats()
    up = host.uptime_seconds()
    if ds:
        lrows = []
        for d in host.disk_devices():
            s = ds.get(d)
            if not s:
                continue
            n_r, n_w = s["reads"], s["writes"]
            lrows.append([d, n_r, n_w,
                          s["ms_reading"] / n_r if n_r else NAN, s["ms_writing"] / n_w if n_w else NAN,
                          s["sectors_read"] / 2.0 / n_r if n_r else NAN, s["sectors_written"] / 2.0 / n_w if n_w else NAN,
                          s["sectors_read"] / 2.0, s["sectors_written"] / 2.0,
                          100.0 * s["io_ticks"] / 1000.0 / up if up else NAN, s["in_flight"]])
        rep.table("/proc/diskstats на старте nmon: накопительно с загрузки ОС",
                  ["устройство", "reads", "writes", "avg read ms", "avg write ms", "avg read KB", "avg write KB",
                   "прочитано", "записано", "util% с загрузки", "in_flight"], lrows,
                  prec={"reads": 0, "writes": 0, "avg read ms": 2, "avg write ms": 2, "прочитано": "kb", "записано": "kb",
                        "in_flight": 0},
                  note="средняя латентность = ms/операцию за всё время с загрузки (включая ожидание в очереди); "
                       "HDD обычно > 5 ms, SSD/NVMe < 1 ms; это не значения за период наблюдения")
    fstab = [x.split(None, 1) for x in host.bbbp.get("/etc/fstab", []) if x.strip() and not x.strip().startswith("#")]
    if fstab:
        rep.text("/etc/fstab", "\n".join(re.sub(r"\s+", " ", " ".join([_bbbp_dev(p[0])] + p[1:])).strip() for p in fstab))
    return rep


def analyze_fs(host, args=None):
    rep = Report("Файловые системы (заполненность)", host.name)
    if not host.has("JFSFILE"):
        rep.text("", "Секция JFSFILE отсутствует")
        return rep
    dfrows = {r["mount"]: r for r in host.df()}
    rows = []
    skipped = []
    shown = []  # точки монтирования основной таблицы — по ним же ищутся скачки
    sel = _opt(args, "mount", None)
    if sel and not any(re.fullmatch(p, m) for m in host.cols("JFSFILE") for p in sel):
        rep.text("", f"точки монтирования {sel} не найдены (--mount — regex на полное совпадение, например '/opt.*'); "
                     f"доступны: {', '.join(host.cols('JFSFILE'))}")
        return rep
    for m in host.cols("JFSFILE"):
        if sel and not any(re.fullmatch(p, m) for p in sel):
            continue
        arr = host.col("JFSFILE", m)
        if arr is None or not clean(arr):
            continue
        if not sel and _pseudo_fs(host, m, dfrows):
            skipped.append(m)
            continue
        shown.append(m)
        s = series_stats(arr, host.times)
        tr = trend(arr, host.times)
        size_mb = dfrows.get(m, {}).get("size_mb")
        tte = time_to_limit(s["last"], tr["slope_per_h"], 100.0) if _reliable_trend(tr, FS_SLOPE_MIN) else NAN
        growth_mb_h = tr["slope_per_h"] / 100.0 * size_mb if size_mb else NAN
        rows.append([m, size_mb if size_mb else NAN, s["first"], s["last"], s["min"], s["max"], _extreme_time(s),
                     s["last"] - s["first"], tr["slope_per_h"], tr["r2"], growth_mb_h, tte * 3600 if tte == tte else NAN,
                     (100 - s["last"]) / 100.0 * size_mb if size_mb else NAN])
    rows.sort(key=lambda r: -(r[3] if r[3] == r[3] else -1))
    rep.table("JFSFILE, % занято", ["mount", "размер", "начало%", "конец%", "min%", "max%", "время max", "Δ% за период",
                                     "рост п.п./ч", "r²", "рост MB/ч", "до 100% при таком росте", "свободно (конец)"],
              rows, prec={"размер": "mb", "рост п.п./ч": 3, "r²": 2, "рост MB/ч": 0, "до 100% при таком росте": "dur", "свободно (конец)": "mb"},
              note=f"рост оценён линейной регрессией; «до 100%» показано только при r² ≥ {TREND_R2_MIN:g} и росте ≥ "
                   f"{FS_SLOPE_MIN:g} п.п./ч, как в FS_GROWTH (разрешение JFSFILE 0.1%, на больших ФС шаг = гигабайты)" +
                   (f"; скрыты псевдо-ФС: {', '.join(skipped)} (укажите --mount, чтобы показать)" if skipped else ""))
    # Резкие изменения (освобождение / скачки): ≥ 2 п.п. либо, на большой ФС, ≥ 10 GB (и ≥ 0.3 п.п. — выше шага JFSFILE)
    jumps = []
    for m in shown:
        arr = host.col("JFSFILE", m)
        size_mb = dfrows.get(m, {}).get("size_mb")
        for i in range(1, len(arr)):
            if arr[i] != arr[i] or arr[i - 1] != arr[i - 1]:
                continue
            dp = arr[i] - arr[i - 1]
            dmb = dp / 100.0 * size_mb if size_mb else NAN
            # допуск 1e-9: значения JFSFILE с одним знаком, разность 8.2 − 6.2 (в float 1.9999…) не должна выпасть из-за округления
            if abs(dp) >= 2.0 - 1e-9 or (dmb == dmb and abs(dp) >= 0.3 - 1e-9 and abs(dmb) >= 10240):
                jumps.append([host.times[i], m, arr[i - 1], arr[i], dp, dmb])
    if jumps:
        # отбор крупнейших по |Δ, MB| (без размера ФС — по |Δ| после них), вывод по времени
        top = sorted(jumps, key=lambda r: (abs(r[5]) if r[5] == r[5] else -1.0, abs(r[4])), reverse=True)[:50]
        top.sort(key=lambda r: (r[0], r[1]))
        rep.table("Скачки заполненности (≥ 2 п.п. или ≥ 10 GB за интервал)", ["время", "mount", "было%", "стало%", "Δ", "Δ, MB"],
                  top, prec={"Δ, MB": "mb"}, total=len(jumps),
                  note="отбор — 50 крупнейших по |Δ, MB| (без размера ФС в df — по |Δ|), вывод по времени; "
                       "Δ, MB = Δ п.п. × размер ФС из df на старте")
    if host.has("JFSINODE"):
        irows = []
        for m in host.cols("JFSINODE"):
            arr = host.col("JFSINODE", m)
            if arr is not None and clean(arr):
                irows.append([m, fmax(arr), series_stats(arr, host.times)["last"]])
        rep.table("JFSINODE, % inode", ["mount", "max%", "конец%"], irows)
    return rep


NET_TOTAL_NOTE = "без lo, bond-слейвов, VLAN, мостов и виртуальных интерфейсов (их трафик учтён на нижележащем интерфейсе)"


def _net_peak_pkt_size(kb, pk):
    """Средний размер пакета в пиках, байт: Σ KB/s × 1024 / Σ pkt/s по снимкам с трафиком ≥ p95; NaN без NETPACKET."""
    if kb is None or pk is None:
        return NAN
    p95 = percentile(kb, 95)
    if p95 != p95 or p95 <= 0:
        return NAN
    s_kb = s_pk = 0.0
    for a, b in zip(kb, pk):
        if a == a and b == b and a >= p95 and b > 0:
            s_kb += a
            s_pk += b
    return s_kb * 1024.0 / s_pk if s_pk > 0 else NAN


def _bond_ports(host, bond):
    """Число портов bond для оценки ёмкости: RUNNING-слейвы по ifconfig (слейвы без флагов в ifconfig — все); bond, у
    которого трафик несёт один слейв (_bond_single_active: active-backup), — один порт; 0 — неизвестно."""
    ifc = {x["name"]: x for x in host.ifconfig()}
    ms = host._bond_members().get(bond, [])
    n = sum(1 for s in ms if not ifc.get(s, {}).get("flags") or "RUNNING" in ifc[s]["flags"].split(","))
    return min(n, 1) if _bond_single_active(host, bond) is not None else n


NET_AB_SHARE = 0.95  # bond с одним активным слейвом: слейв несёт ≥ 95 % rx+tx bond в ≥ 95 % снимков с трафиком bond
NET_AB_MIN_SNAPS = 10  # ... и таких снимков не меньше 10


def _net_full(host):
    """Полный ряд хоста для свойств, которые нельзя определять по окну (состав и режим bond, «молчал с начала записи»):
    до --from/--to/--around (host.unfiltered) или исходный хост среза (без T0001 и т. п.)."""
    return host.unfiltered if host.unfiltered is not None else (host.slice_of or host)


def _bond_single_active(host, bond):
    """Bond, трафик которого в каждом снимке несёт один слейв (active-backup или LACP с одним живым портом): из ≥ 2
    слейвов один несёт ≥ 95 % rx+tx bond в ≥ 95 % снимков, где bond передаёт ≥ 5 % своего p75 (таких снимков ≥ 10).
    Режим определяется по полному ряду хоста без первых снимков файлов (_net_full: окно --from/--to, целиком попавшее
    в отказ слейва LACP, не выглядит как active-backup), отрезки обрезаются по окну host. Возвращает отрезки
    активности слейвов [(слейв, первый снимок, последний снимок)] — индексы host (смена слейва — failover; [] — в
    окне отрезков нет) — или None, если трафик делят несколько слейвов или данных мало."""
    full = _net_full(host)
    cache = getattr(full, "_bond_sa", None)
    if cache is None:
        cache = full._bond_sa = {}
    if bond not in cache:
        fx = full.without_first()
        segs = _bond_single_active_raw(fx, bond)
        cache[bond] = None if segs is None else [(sl, fx.times[a], fx.times[b]) for sl, a, b in segs]
    segs = cache[bond]
    if segs is None:
        return None
    out = []
    for sl, ta, tb in segs:
        k0, k1 = bisect.bisect_left(host.times, ta), bisect.bisect_right(host.times, tb) - 1
        if k0 <= k1:
            out.append((sl, k0, k1))
    return out


def _bond_single_active_raw(host, bond):
    """_bond_single_active по рядам самого host (без перехода к полному ряду): отрезки [(слейв, снимок, снимок)] или None."""
    btot = _net_tot(host, bond)
    stot = {s: t for s in host._bond_members().get(bond, []) for t in [_net_tot(host, s)] if t is not None}
    bl = _net_level(host, bond)
    if btot is None or len(stot) < 2 or bl != bl or bl <= 0:
        return None
    act = []  # (снимок, активный слейв или None — трафик делят несколько слейвов)
    for k, b in enumerate(btot):
        if b != b or b < NET_DROP_SHARE * bl:
            continue
        s = max(stot, key=lambda x: stot[x][k] if stot[x][k] == stot[x][k] else -1.0)
        v = stot[s][k]
        act.append((k, s if v == v and v >= NET_AB_SHARE * b else None))
    if len(act) < NET_AB_MIN_SNAPS or sum(1 for _k, s in act if s) < NET_AB_SHARE * len(act):
        return None
    segs = []
    for k, s in act:
        if s is None:
            continue
        if segs and segs[-1][0] == s:
            segs[-1][2] = k
        else:
            segs.append([s, k, k])
    return [tuple(x) for x in segs]


def _net_port_util(host, iface, role, cap):
    """(util p95 %, util max %) интерфейса — максимум из rx и tx относительно ёмкости: nic и слейв — один порт
    (cap), bond — cap × число его портов; для bond с неизвестным составом, VLAN, мостов, виртуальных и lo — NaN."""
    if not cap:
        return NAN, NAN
    if role == "nic" or role.startswith("bond-slave"):
        c = cap
    elif role == "bond":
        c = cap * _bond_ports(host, iface)
    else:
        c = 0
    if not c:
        return NAN, NAN
    rd, wr = host.col("NET", f"{iface}-read-KB/s"), host.col("NET", f"{iface}-write-KB/s")
    p95 = fmax([percentile(rd, 95), percentile(wr, 95)])
    mx = fmax([fmax(rd), fmax(wr)])
    return (100.0 * p95 / c if p95 == p95 else NAN), (100.0 * mx / c if mx == mx else NAN)


def _neterror_series(host):
    """Колонки NETERROR: [(колонка, интерфейс, ряд /s, остаток bond)]. У bond с известными слейвами берётся только
    остаток над суммой одноимённых колонок слейвов (max(0, …) по снимку), чтобы ошибки слейва не считались дважды."""
    ifaces = sorted(host.net_ifaces(), key=len, reverse=True)
    members = host._bond_members()
    out = []
    for c in host.cols("NETERROR"):
        arr = host.col("NETERROR", c)
        if arr is None:
            continue
        iface = next((i for i in ifaces if c.startswith(i + "-")), None)
        own = False
        if iface in members:
            suffix = c[len(iface) + 1:]
            scols = [s for s in (host.col("NETERROR", f"{m}-{suffix}") for m in members[iface]) if s is not None]
            if scols:
                arr = [max(0.0, v - sum(s[k] for s in scols if s[k] == s[k])) if v == v else NAN for k, v in enumerate(arr)]
                own = True
        out.append((c, iface, list(arr), own))
    return out


def _net_error_counters(host):
    """Накопительные ошибки/дропы интерфейсов на старте (BBBP) без двойного учёта: у bond с известными слейвами по
    каждому счётчику берётся собственный остаток max(0, bond − Σ слейвов). Только интерфейсы с ненулевыми значениями:
    [{name, role, own, rx_errors, tx_errors, rx_dropped, tx_dropped, rx_packets, tx_packets, slaves_tx_dropped}]."""
    cnt = host.net_counters()
    roles = host.net_roles()
    members = host._bond_members()
    keys = ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
    out = []
    for name, x in cnt.items():
        v = {k: x.get(k) or 0 for k in keys}
        ms = [cnt[m] for m in members.get(name, []) if m in cnt]
        if ms:
            for k in keys:
                v[k] = max(0, v[k] - sum(m.get(k) or 0 for m in ms))
        if not any(v.values()):
            continue
        out.append({"name": name, "role": roles.get(name, "-"), "own": bool(ms), "rx_packets": x.get("rx_packets"),
                    "tx_packets": x.get("tx_packets"), "slaves_tx_dropped": sum(m.get("tx_dropped") or 0 for m in ms), **v})
    return out


def _slave_quiet(host, slave):
    """Молчание слейва bond (_net_quiet_runs, quiet) в снимках, когда сам bond передаёт ≥ 5 % своего p75:
    (bond, q, p75 bond, [(start, end, min, длительность с, с начала записи)]); «с начала записи» — до отрезка слейв
    ни разу не нёс трафик ≥ порога (резервный слейв active-backup или линк, поднявшийся позже) — это не отказ.
    None — нет рядов слейва или его bond."""
    b = host.bond_of(slave)
    tot = _net_tot(host, slave)
    btot = _net_tot(host, b) if b else None
    if tot is None or btot is None:
        return None
    bl = _net_level(host, b)
    q = _net_quiet_runs(host, tot, [v == v and bl == bl and bl > 0 and v >= NET_DROP_SHARE * bl for v in btot],
                        level=_net_level(host, slave))
    # «с начала записи» — по полному ряду до начала отрезка, а не по окну: отказ, начавшийся до окна, остаётся отказом
    full = _net_full(host)
    ftot = _net_tot(full, slave) if full is not host else tot

    def never(s):
        k = bisect.bisect_left(full.times, host.times[s]) if full is not host else s
        return not any(v == v and v >= q["thr"] for v in ftot[:k])

    return b, q, bl, [(s, e, mn, d, never(s)) for s, e, mn, d in q["quiet"]]


def _net_quiet_rows(host, ifaces=None):
    """Отрезки «молчания» от 2 снимков (_net_quiet_runs): основные интерфейсы — ноль и провал; слейвы bond — ноль или
    провал, пока сам bond передаёт ≥ 5 % своего p75 (кроме bond, трафик которого несёт один слейв — см.
    _bond_single_active). [(iface, роль, тип, start, end, p75, min, длительность с)] по времени."""
    roles = host.net_roles()
    single = {}  # bond -> _bond_single_active
    out = []
    for i in (ifaces if ifaces is not None else host.net_ifaces()):
        role = roles.get(i, "nic")
        tot = _net_tot(host, i)
        if tot is None:
            continue
        if role in ("bond", "nic"):
            q = _net_quiet_runs(host, tot, level=_net_level(host, i))
            for kind, label in (("zero", "ноль"), ("drop", "провал < 5% p75")):
                out.extend((i, role, label, s, e, q["L"], mn, d) for s, e, mn, d in q[kind] if e > s)
        elif role.startswith("bond-slave"):
            b = host.bond_of(i)
            if b is not None and b not in single:
                single[b] = _bond_single_active(host, b)
            if b is not None and single[b] is not None:
                continue  # молчание резервного слейва — норма; смены активного слейва — отдельная таблица net
            sq = _slave_quiet(host, i)
            if sq is None:
                continue
            b, q, _bl, runs = sq
            for s, e, mn, d, never in runs:
                if e > s:
                    kind = "ноль" if fmax(tot[s:e + 1]) < NET_ZERO_KBS else "провал < 5% p75"
                    out.append((i, role, f"{kind} {'с начала записи ' if never else ''}при живом {b}", s, e, q["L"], mn, d))
    out.sort(key=lambda r: (r[3], r[0]))
    return out


def analyze_net(host, args=None):
    rep = Report("Сеть", host.name)
    if not host.has("NET"):
        rep.text("", "Секция NET отсутствует")
        return rep
    ifc = host.net_counters()
    sel = _opt(args, "iface", None)

    def selected(i):
        return not sel or any(re.fullmatch(p, i) for p in sel)

    if sel and not any(selected(i) for i in list(host.net_ifaces()) + list(ifc)):
        rep.text("", f"интерфейсы {sel} не найдены (--iface — regex на полное совпадение, например 'bond.*'); доступны: "
                     f"{', '.join(host.net_ifaces())}")
        return rep
    # вся статистика (таблица, итоги, объёмы, пики, отрезки молчания, NETERROR) — без первого снимка каждого файла/запуска
    # (T0001 — 1–2 с на старте nmon), как в report, health и cluster
    hx = host.without_first()
    roles = hx.net_roles()
    dts = _snap_dt(hx)
    link = _opt(args, "link_mbit", None)
    cap = link_capacity_kbs(link) if link else None
    rows = []
    for i in hx.net_ifaces():
        if not selected(i):
            continue
        rd = hx.col("NET", f"{i}-read-KB/s")
        wr = hx.col("NET", f"{i}-write-KB/s")
        pr = hx.col("NETPACKET", f"{i}-read/s")
        pw = hx.col("NETPACKET", f"{i}-write/s")
        if rd is None:
            continue
        # без трафика или без единого значения (колонка есть, данных нет) — только с --all
        if not (fmax(rd) > 0 or fmax(wr) > 0) and not _opt(args, "all", False):
            continue
        role = roles.get(i, "nic")
        avg_pkt_in = (fmean(rd) * 1024.0 / fmean(pr)) if pr is not None and fmean(pr) > 0 else NAN
        avg_pkt_out = (fmean(wr) * 1024.0 / fmean(pw)) if pw is not None and fmean(pw) > 0 else NAN
        row = [i, role, ifc.get(i, {}).get("mtu", NAN),
               fmean(rd), percentile(rd, 95), fmax(rd), _extreme_time(series_stats(rd, hx.times)),
               fmean(wr), percentile(wr, 95), fmax(wr), _extreme_time(series_stats(wr, hx.times)),
               fmean(pr) if pr is not None else NAN, fmean(pw) if pw is not None else NAN,
               avg_pkt_in, avg_pkt_out, _net_peak_pkt_size(rd, pr), _net_peak_pkt_size(wr, pw),
               _integrate(hx, rd, dts), _integrate(hx, wr, dts)]
        if cap:
            row.extend(_net_port_util(hx, i, role, cap))
        rows.append(row)
    rows.sort(key=lambda r: -((r[4] if r[4] == r[4] else 0) + (r[8] if r[8] == r[8] else 0)))
    cols = ["iface", "роль", "mtu", "rx avg KB/s", "rx p95", "rx max", "время rx max",
            "tx avg KB/s", "tx p95", "tx max", "время tx max", "rx pkt/s", "tx pkt/s",
            "avg rx pkt B", "avg tx pkt B", "rx B/pkt в пиках", "tx B/pkt в пиках", "принято всего", "передано всего"]
    prec = {"mtu": 0, "rx pkt/s": 0, "tx pkt/s": 0, "avg rx pkt B": 0, "avg tx pkt B": 0, "rx B/pkt в пиках": 0,
            "tx B/pkt в пиках": 0, "принято всего": "kb", "передано всего": "kb"}
    if cap:
        cols += ["util p95 %", "util max %"]
    note = ("интерфейсы без трафика скрыты (--all покажет); суммарный трафик хоста — " + NET_TOTAL_NOTE +
            "; B/pkt в пиках — средний размер пакета в снимках с трафиком ≥ p95 (среднее за период определяется фоном "
            "мелких сообщений); объёмы — Σ скорости × фактический шаг снимка; "
            + _t1_note(hx, "вся статистика — без первого снимка каждого файла/запуска (T0001)"))
    if any("по трафику" in r for r in roles.values()):
        note += "; слейвы bond определены по совпадению рядов rx/tx (в ifconfig нет флагов SLAVE/MASTER)"
    if hx._bond_unresolved:
        note += f"; слейвы bond по трафику не определены: {', '.join(hx._bond_unresolved)} (bond и NIC входят в итог)"
    if cap:
        note += (f"; util — максимум из rx и tx относительно --link-mbit {link:g} (скорость одного порта): nic и слейв — "
                 "один порт, bond — порт × число слейвов (bond с одним активным слейвом — один порт); для bond с "
                 "неизвестным составом, VLAN и виртуальных — «-»")
    rep.table("Интерфейсы", cols, rows, prec=prec, note=note)
    rt, wt = hx.net_total("read"), hx.net_total("write")
    if rt is not None and wt is not None:
        kv = [("rx avg KB/s", fmean(rt)), ("rx p95 KB/s", percentile(rt, 95)), ("rx max KB/s", fmax(rt)),
              ("tx avg KB/s", fmean(wt)), ("tx p95 KB/s", percentile(wt, 95)), ("tx max KB/s", fmax(wt)),
              ("принято за период", _integrate(hx, rt, dts)), ("передано за период", _integrate(hx, wt, dts))]
        kprec = {k: 0 for k, _ in kv[:6]}
        kprec.update({"принято за период": "kb", "передано за период": "kb"})
        knote = [_t1_note(hx, "без первого снимка каждого файла/запуска (T0001)"), "объёмы — Σ скорости × фактический шаг снимка"]
        if cap:
            ports = [(u95, umax, i) for i in hx.net_ifaces()
                     if roles.get(i) == "nic" or roles.get(i, "").startswith("bond-slave")
                     for u95, umax in [_net_port_util(hx, i, roles[i], cap)] if u95 == u95]
            if ports:
                b95, bmax = max(ports, key=lambda p: p[0]), max(ports, key=lambda p: p[1])
                kv += [("макс. загрузка порта p95, %", b95[0]), ("макс. загрузка порта max, %", bmax[1]),
                       ("порт (p95 / max)", b95[2] if b95[2] == bmax[2] else f"{b95[2]} / {bmax[2]}")]
                kprec.update({"макс. загрузка порта p95, %": 1, "макс. загрузка порта max, %": 1})
            knote.append(f"загрузка порта — максимум из rx и tx по nic и слейвам bond относительно --link-mbit {link:g} "
                         "(скорость одного порта); средние за интервал nmon скрывают микровсплески: заметная загрузка по "
                         "nmon уже допускает кратковременное насыщение порта")
        if sel:
            knote.append("итог — по всем основным интерфейсам хоста независимо от --iface")
        rep.kv(f"Итого ({NET_TOTAL_NOTE.split(' (')[0]})", kv, prec=kprec, note="; ".join(knote))
        rp, wp = hx.net_total("read", packets=True), hx.net_total("write", packets=True)
        peaks = top_peaks([a + b for a, b in zip(rt, wt)], hx.times, n=_opt(args, "top", 5) or 5, min_gap=2)
        cs = hx.col("CPU_ALL", "Sys%")

        def size(kb, pk):
            return kb * 1024.0 / pk if kb == kb and pk == pk and pk > 0 else NAN

        pkts = rp is not None and wp is not None  # без NETPACKET колонок пакетов нет
        prows = []
        for t, _ in peaks:
            k = hx.times.index(t)
            prows.append([t, rt[k], wt[k]] + ([rp[k], wp[k], size(rt[k], rp[k]), size(wt[k], wp[k])] if pkts else []) +
                         [cs[k] if cs is not None else NAN, _top_proc_at(hx, k)])
        pnote = ["B/pkt = Σ KB/s × 1024 / Σ pkt/s основных интерфейсов в снимке: ~MTU — массовая передача "
                 "(rebalance, снапшот, putAll), сотни байт — мелкие сообщения/RPC и подтверждения"] if pkts else []
        if sel:
            pnote.append("по всем основным интерфейсам хоста независимо от --iface")
        rep.table("Пики суммарного трафика", ["время", "rx KB/s", "tx KB/s"] +
                  (["rx pkt/s", "tx pkt/s", "rx B/pkt", "tx B/pkt"] if pkts else []) + ["sys%", "топ-процесс"], prows,
                  prec={"rx pkt/s": 0, "tx pkt/s": 0, "rx B/pkt": 0, "tx B/pkt": 0}, note="; ".join(pnote) or None)
    # Отрезки «молчания»: ноль и провал трафика основных интерфейсов, отказ слейва bond при живом bond
    quiet = _net_quiet_rows(hx, [i for i in hx.net_ifaces() if selected(i)])
    if quiet:
        rep.table("Отрезки нулевого трафика и провалов (возможная изоляция узла, падение линка или слейва bond)",
                  ["iface", "роль", "тип", "от", "до", "длительность", "снимков", "p75 rx+tx KB/s", "min KB/s"],
                  [[i, role, kind, hx.times[s], hx.times[e], d, e - s + 1, L, mn]
                   for i, role, kind, s, e, L, mn, d in quiet[:30]],
                  prec={"длительность": "dur", "p75 rx+tx KB/s": 0},
                  note=f"ноль — rx+tx < {NET_ZERO_KBS:g} KB/s у интерфейса с p75 ≥ {NET_ZERO_MIN_P75:g} KB/s; провал — ниже "
                       f"max({NET_ZERO_KBS:g} KB/s, {100 * NET_DROP_SHARE:g}% p75) при p75 ≥ {NET_DROP_MIN_P75:g} KB/s; "
                       "для слейва bond — только снимки, когда сам bond передаёт ≥ 5% своего p75 («с начала записи» — до "
                       "отрезка слейв трафика не нёс: резервный слейв или линк, поднявшийся позже); от 2 снимков подряд; "
                       "на пропуске данных > 5 интервалов отрезок рвётся, длительность — по меткам времени + интервал",
                  total=len(quiet))
    # bond, трафик которого несёт один слейв (active-backup): кто и когда был активным, смены — failover
    arows = []
    for b in hx.net_ifaces():
        if roles.get(b) != "bond" or not (selected(b) or any(selected(s) for s in hx._bond_members().get(b, []))):
            continue
        for s, k0, k1 in _bond_single_active(hx, b) or []:
            arows.append([b, s, hx.times[k0], hx.times[k1], k1 - k0 + 1])
    if arows:
        rep.table("Bond с одним активным слейвом (active-backup или LACP с одним живым портом)",
                  ["bond", "активный слейв", "с", "по", "снимков"], arows[:30], total=len(arows), prec={"снимков": 0},
                  note=f"в ≥ {100 * NET_AB_SHARE:g}% снимков, когда bond передаёт ≥ 5% своего p75, один слейв несёт ≥ "
                       f"{100 * NET_AB_SHARE:g}% rx+tx bond; смена активного слейва — failover (NET_BOND_MEMBER в health, "
                       "журнал ядра: bonding); молчание другого слейва — норма, в отрезки молчания не входит; ёмкость "
                       "bond для util — один порт")
    # Конфигурация интерфейсов
    crow = []
    for i in ifc.values():
        if not selected(i["name"]):
            continue
        crow.append([i["name"], roles.get(i["name"], "-"), i["inet"] or "-", i["mtu"], (i["flags"] or "")[:40],
                     i["rx_packets"], i["tx_packets"], i["rx_errors"], i["rx_dropped"], i.get("rx_overruns"),
                     i.get("rx_frame"), i["tx_errors"], i["tx_dropped"], i.get("tx_overruns"), i.get("tx_carrier"),
                     i.get("tx_collisions"), i.get("source", "ifconfig")])
    if crow:
        rep.table("Счётчики интерфейсов на старте (BBBP): ошибки/дропы — накопительные с загрузки ОС",
                  ["iface", "роль", "inet", "mtu", "flags", "rx packets", "tx packets", "rx err", "rx drop", "rx overruns",
                   "rx frame", "tx err", "tx drop", "tx overruns", "carrier", "collisions", "источник"], crow,
                  prec={"mtu": 0},
                  note="счётчики bond = сумма счётчиков его слейвов + собственные (например, tx drop при отсутствии "
                       "активного слейва); overruns (fifo), frame, carrier, collisions — для сведения, в NET_ERRORS не входят")
    if hx.has("NETERROR"):
        erows = []
        for c, iface, arr, own in _neterror_series(hx):
            if sel and not selected(iface or c):
                continue
            ev = _integrate(hx, arr, dts)
            if ev > 0:
                erows.append([c + (" (сверх слейвов)" if own else ""), ev, fmax(arr)])
        erows.sort(key=lambda r: -r[1])
        rep.table("NETERROR (ненулевые)", ["колонка", "≈ событий за период (Σ rate × шаг)", "max /s"], erows,
                  prec={"≈ событий за период (Σ rate × шаг)": 0},
                  note="NETERROR — ошибки в секунду, событий = Σ rate × фактический шаг снимка; у bond с известными "
                       "слейвами — только остаток над суммой одноимённых колонок слейвов; "
                       + _t1_note(hx, "без T0001"))
    return rep


# --------------------------------------------------------------------------
# Процессы (TOP), JVM, командные строки (UARG)
# --------------------------------------------------------------------------


def _proc_sum(cmd, procs):
    """Сводный Proc процессов одного снимка (группа --by-cmd): числовые поля — суммы по процессам (NaN пропускаются,
    NaN у всех — NaN), pid = 0."""
    vals = []
    for f in Proc.__slots__[2:]:
        xs = [v for v in (getattr(p, f) for p in procs) if v == v]
        vals.append(sum(xs) if xs else NAN)
    return Proc(0, cmd, *vals)


RE_KWORKER = re.compile(r"^kworker/[^-+]*[-+]?")  # kworker/<cpu>:<id>[H] или u<pool>:<id>, затем '-'/'+' и задача
RE_PERCPU_KTHREAD = re.compile(r"^(ksoftirqd|migration|cpuhp|watchdog|idle_inject|rcuo[a-z]*)/\d+$")


def cmd_group(cmd):
    """Имя группы для сводок по команде: kworker/8:0-events, kworker/u64:1+flush-253:0 -> kworker/*-events,
    kworker/*-flush-* (имя kworker содержит текущую задачу workqueue; номер устройства flush-<maj>:<min> -> *;
    без задачи — kworker/*); потоки ядра по CPU (ksoftirqd/N, migration/N, cpuhp/N, watchdog/N, rcuo*/N,
    idle_inject/N) -> <имя>/*; остальные имена — как есть."""
    if cmd.startswith("kworker/"):
        task = re.sub(r"^flush-[\d:]*$", "flush-*", RE_KWORKER.sub("", cmd))
        return f"kworker/*-{task}" if task else "kworker/*"
    m = RE_PERCPU_KTHREAD.match(cmd)
    return f"{m.group(1)}/*" if m else cmd


def _proc_summary_rows(host, groups, n_snap):
    """groups: (команда, pid или число PID) -> list[(idx, Proc)], не больше одного Proc на снимок. n_snap — снимков
    с данными TOP: «cpu Σ/снимков%» = Σ %CPU / n_snap (снимок без процесса = 0). Возвращает строки сводки."""
    rows = []
    for key, lst in groups.items():
        idxs = [i for i, _ in lst]
        cpu = [p.cpu for _, p in lst]
        rss = [p.rss for _, p in lst if p.rss == p.rss]
        thr = [p.threads for _, p in lst if p.threads == p.threads]
        usr = [p.usr for _, p in lst]
        sy = [p.sys for _, p in lst]
        majf = [p.majflt for _, p in lst if p.majflt == p.majflt]
        minf = [p.minflt for _, p in lst if p.minflt == p.minflt]
        iow = [p.iowait for _, p in lst if p.iowait == p.iowait]
        imax = argmax(cpu)
        rows.append([
            key[0], key[1], len(lst), host.times[idxs[0]], host.times[idxs[-1]],
            fsum(cpu) / n_snap if n_snap and clean(cpu) else NAN,
            fmean(cpu), percentile(cpu, 95), fmax(cpu), host.times[idxs[imax]] if imax >= 0 else None,
            (100.0 * fsum(sy) / max(1e-9, fsum(usr) + fsum(sy))) if (fsum(usr) + fsum(sy)) > 0 else NAN,
            (rss[0] / 1024.0) if rss else NAN, (max(rss) / 1024.0) if rss else NAN, (rss[-1] / 1024.0) if rss else NAN,
            (thr[0]) if thr else NAN, (max(thr)) if thr else NAN, (thr[-1]) if thr else NAN,
            fmean(majf), fmax(majf), fmean(minf), fsum(iow),
        ])
    return rows


PROC_COLS = ["команда", "pid", "снимков", "впервые", "последний", "cpu Σ/снимков%", "cpu avg% (когда виден)", "cpu p95%",
             "cpu max%", "время cpu max", "доля sys%", "rss нач. MB", "rss max MB", "rss кон. MB", "thr нач.", "thr max",
             "thr кон.", "majflt avg/s", "majflt max/s", "minflt avg/s", "iowait Σ"]
PROC_SORT = {"cpu": "cpu Σ/снимков%", "cpuavg": "cpu avg% (когда виден)", "cpumax": "cpu max%", "rss": "rss max MB",
             "threads": "thr max", "majflt": "majflt avg/s", "sys": "доля sys%", "snapshots": "снимков"}
PROC_NOTE = ("MinorFault/MajorFault в TOP — события в секунду (nmon делит приращение на длительность интервала); "
             "MajorFault процесса может включать faults, завершённые после повтора (не чтения с диска) — сверка в check; "
             "IOwaitTime учитывает только главный поток процесса и для многопоточных JVM неинформативен")


def _no_top_text(host):
    """Сообщение об отсутствии данных TOP: в окне времени нет снимков с TOP (а в файлах TOP есть) или nmon без -t."""
    if host.top_in_files():
        return ("в выбранном окне нет снимков с данными TOP (TOP пишется начиная со второго снимка); расширьте окно")
    return "Секция TOP отсутствует (nmon запущен без -t) — данных по процессам нет"


def analyze_top(host, args=None):
    rep = Report("Процессы (секция TOP)", host.name)
    if not any(host.top):
        rep.text("", _no_top_text(host))
        return rep
    n_snap = sum(1 for x in host.top if x)
    pid_filter = _opt(args, "pid", None)
    cmd_filter = _opt(args, "cmd", None)
    by_cmd = _opt(args, "by_cmd", False)
    groups = defaultdict(list)
    names = defaultdict(lambda: defaultdict(int))  # по PID: kworker меняет имя по текущей задаче — показываем самое частое
    pids = defaultdict(set)
    for i, procs in enumerate(host.top):
        snap = defaultdict(list)
        for p in procs:
            if pid_filter and int(p.pid) not in pid_filter:
                continue
            if cmd_filter and not any(re.search(c, p.cmd) for c in cmd_filter):
                continue
            if by_cmd:
                g = cmd_group(p.cmd)
                snap[g].append(p)
                pids[g].add(p.pid)
            else:
                key = ("kworker" if p.cmd.startswith("kworker/") else p.cmd, p.pid)
                groups[key].append((i, p))
                names[key][p.cmd] += 1
        # --by-cmd: одна строка на снимок — сумма по всем PID группы
        for g, ps in snap.items():
            groups[g].append((i, ps[0] if len(ps) == 1 else _proc_sum(g, ps)))
    if by_cmd:
        groups = {(g, len(pids[g])): lst for g, lst in groups.items()}
    else:
        groups = {(max(names[k].items(), key=lambda kv: kv[1])[0] + (f" (имён: {len(names[k])})" if len(names[k]) > 1 else ""),
                   k[1]): lst for k, lst in groups.items()}
    rows = _proc_summary_rows(host, groups, n_snap)
    sort = _opt(args, "sort", "cpu") or "cpu"
    keyidx = PROC_COLS.index(PROC_SORT.get(sort, PROC_SORT["cpu"]))
    rows.sort(key=lambda r: -(r[keyidx] if r[keyidx] == r[keyidx] else -1))
    total = len(rows)
    n_top = _opt(args, "top", 20) or 20
    if not (pid_filter or cmd_filter):
        rows = rows[:n_top]
    cols = [("PID шт." if by_cmd and c == "pid" else c) for c in PROC_COLS]
    grp_note = ("--by-cmd: значения — суммы по всем PID группы в снимке (kworker/*-<задача>, <поток ядра>/* — группы "
                "потоков ядра), «снимков» — где группа была в TOP, «PID шт.» — число разных PID; RSS — сумма "
                "(разделяемые страницы учитываются несколько раз); " if by_cmd else
                "kworker меняет имя по текущей задаче: показано самое частое имя PID и число имён; ")
    rep.table("Сводка по процессам" + (" (сгруппировано по команде)" if by_cmd else ""), cols, rows, total=total,
              prec={"pid": 0, "PID шт.": 0, "cpu Σ/снимков%": 2, "rss нач. MB": 0, "rss max MB": 0, "rss кон. MB": 0, "thr нач.": 0,
                    "thr max": 0, "thr кон.": 0, "majflt avg/s": 1, "majflt max/s": 0, "minflt avg/s": 0, "iowait Σ": 0},
              note=f"снимков с TOP: {n_snap}; в TOP попадают только процессы с заметным CPU в интервале, "
                   f"поэтому отсутствие процесса в снимке ≠ он не работал; cpu Σ/снимков% — среднее за весь период "
                   f"(снимок без процесса = 0), по нему сортировка --sort cpu (по умолчанию); cpu avg% (когда виден) — "
                   f"среднее только по снимкам присутствия (--sort cpuavg); сортировка: {sort}; {grp_note}{PROC_NOTE}")
    # Сумма CPU процессов vs CPU_ALL
    sum_cpu = _top_sum_cpu(host)
    busy = host.cpu_busy()
    ncpu = host.ncpus()
    if busy is not None and ncpu:
        # %CPU в TOP — в процентах одного ядра; CPU_ALL — в % от всех ядер; busy — только по снимкам с TOP (в первом
        # снимке файла TOP нет, а busy его неполного интервала завышен) — сравниваются одни и те же снимки
        busy = [b if s == s else NAN for b, s in zip(busy, sum_cpu)]
        sys_pct = [v / ncpu if v == v else NAN for v in sum_cpu]
        diff = [b - s if (b == b and s == s) else NAN for b, s in zip(busy, sys_pct)]
        rep.kv("Учёт CPU: сумма %CPU процессов (в % от всех CPU) vs CPU_ALL busy", [
            ("сумма TOP avg, % всех CPU", fmean(sys_pct)), ("сумма TOP max, % всех CPU", fmax(sys_pct)),
            ("CPU_ALL busy avg, %", fmean(busy)), ("CPU_ALL busy max, %", fmax(busy)),
            ("неучтённое в TOP (busy − сумма) avg, п.п.", fmean(diff)),
        ], note="CPU_ALL busy — по тем же снимкам, где есть TOP (без первого снимка файла); большая неучтённая доля = много "
                "мелких процессов ниже порога TOP либо прерывания/softirq/kernel-потоки")
    # Появления/исчезновения (перезапуски) — по полному ряду: при окне времени край окна не выглядит перезапуском
    changes = _life_changes(_java_life(host), host)
    if changes:
        rep.table("Смена PID у команд (перезапуск процесса)", PID_CHANGE_COLS, changes[:30], total=len(changes), prec=PID_CHANGE_PREC)
    return rep


PROC_CATEGORIES = [
    (r"^(kswapd|kcompactd|khugepaged|oom_reaper)", "ядро: память/reclaim/THP"),
    (r"^(jbd2|xfsaild|flush-|writeback|md\d+_raid|md\d+_resync|dmcrypt|kdmwork|kcopyd|nvme|scsi_eh|kblockd|loop\d)", "ядро: I/O/writeback"),
    (r"^(ksoftirqd|irq/|rcu_|migration|watchdog|kthreadd|cpuhp)", "ядро: прерывания/планировщик"),
    (r"^(zabbix|node_exporter|telegraf|collectd|datadog|dd-agent|nrpe|snmpd|filebeat|fluent|promtail|metricbeat|wazuh|osquery|mpstat|pidstat|iostat|sar$|sadc|vmstat|nmon|splunk|vector|logstash)", "мониторинг/агенты"),
    (r"^(clamd|clamav|kesl|klnagent|drweb|savd|falcon|cs-?agent|mfe|mcafee|symantec|sophos|tanium|crowdstrike|freshclam|kaspersky|avp)", "антивирус/безопасность"),
    (r"^(rsync|tar|gzip|bzip2|xz|zstd|pigz|bacula|bpbkar|nbjm|veeam|borg|restic|dd$|cp$|scp|sftp|rclone|aws|s3cmd|mc$)", "бэкап/копирование/сжатие"),
    (r"^(jstack|jmap|jcmd|jfr|jinfo|jstat|control\.sh|ignitevisor)", "JVM-диагностика/утилиты Ignite"),
    (r"^java", "JVM"),
    (r"^(postgres|mysqld|mariadbd|oracle|redis|mongod|kafka|zookeeper|etcd|elasticsearch|clickhouse)", "другая СУБД/брокер"),
    (r"^(sshd|bash|sh$|python|perl|ruby|ansible|salt|puppet|chef|crond|cron|systemd|dbus|rsyslog|journal|tuned|NetworkManager|polkitd|auditd|sssd|chronyd|ntpd)", "система/скрипты"),
]


# kworker: категория по задаче workqueue в имени (kworker/u64:1-writeback, kworker/*-flush-*)
KWORKER_CATEGORIES = [
    (r"^(writeback|flush|xfs|ext4|jbd2|dio|kblockd|blk)", "ядро: I/O/writeback"),
    (r"^(events|mm_percpu_wq|rcu|cgroup)", "ядро: служебные очереди"),
]


def proc_category(cmd):
    if cmd.startswith("kworker/"):
        task = RE_KWORKER.sub("", cmd)
        if not task:
            return "ядро: workqueue (задача в имени не указана)"
        for pat, cat in KWORKER_CATEGORIES:
            if re.search(pat, task):
                return cat
        return "ядро: прочие workqueue (драйверы)"
    for pat, cat in PROC_CATEGORIES:
        if re.search(pat, cmd):
            return cat
    return "прочее"


JAVA_MAIN_RSS_SHARE = 0.25  # основной JVM: RSS max ≥ 25 % RSS max одновременно живших java (без ResSet — по Σ %CPU)
JAVA_MAIN_MIN_SNAPS = 3     # ... и RSS max ≥ JAVA_MAIN_RSS_KB или (виден в TOP ≥ 3 снимков и RSS max ≥ 25 % наибольшей)
JAVA_MAIN_RSS_KB = 1024 * 1024


def _java_roles(host, jp=None):
    """pid -> True (основной JVM: узел Ignite/приложение) | False (вспомогательный java: утилита, короткий клиент) —
    по характеристикам за всю жизнь PID (при окне --from/--to — по полному ряду), а не по одному снимку.
    Основной: RSS max ≥ JAVA_MAIN_RSS_SHARE × наибольшей RSS max среди java, живших одновременно с ним (интервалы
    [первое, последнее появление] пересекаются; сам PID входит), и (RSS max ≥ 1 GB или снимков ≥ JAVA_MAIN_MIN_SNAPS
    при RSS max ≥ JAVA_MAIN_RSS_SHARE × наибольшей RSS max всех java за период). Поэтому два одновременных крупных JVM
    — оба основные, утилита рядом с сервером или в окне его простоя — вспомогательная, а перезапущенный JVM с холодным
    стартом (RSS много меньше, чем у погибшего) — основной. Если RSS нет ни у одного java (TOP без ResSet) — по Σ %CPU
    за жизнь PID (≥ JAVA_MAIN_RSS_SHARE наибольшей) при снимках ≥ JAVA_MAIN_MIN_SNAPS. Командная строка из UARG
    уточняет: серверный узел Ignite — основной, утилита control.sh — вспомогательный. jp — host.java_procs(), если
    уже посчитан."""
    base = host.unfiltered or host
    if jp is None or base is not host:
        jp = base.java_procs()
    rss = {pid: fmax([p.rss for _, p in lst]) for pid, lst in jp.items()}
    known = clean(rss.values())
    roles = {}
    if known:
        top = max(known)
        alive = [0.0] * base.n()  # по снимку: наибольшая RSS max среди java, живых в нём
        for pid, lst in jp.items():
            r = rss[pid]
            if r == r:
                for i in range(lst[0][0], lst[-1][0] + 1):
                    if r > alive[i]:
                        alive[i] = r
        for pid, lst in jp.items():
            r = rss[pid]
            peer = max(alive[lst[0][0]:lst[-1][0] + 1])
            roles[pid] = r == r and r >= JAVA_MAIN_RSS_SHARE * peer and (
                r >= JAVA_MAIN_RSS_KB or (len(lst) >= JAVA_MAIN_MIN_SNAPS and r >= JAVA_MAIN_RSS_SHARE * top))
    else:
        cpu = {pid: fsum([p.cpu for _, p in lst]) for pid, lst in jp.items()}
        top = fmax(cpu.values())
        for pid, lst in jp.items():
            c = cpu[pid]
            roles[pid] = c == c and top == top and c >= JAVA_MAIN_RSS_SHARE * top and len(lst) >= JAVA_MAIN_MIN_SNAPS
    cl = base.uarg_cmdlines()
    for pid in roles:
        if pid in cl:
            role = jvm_role(cl[pid][1])
            if role.startswith("серверный узел"):
                roles[pid] = True
            elif role.startswith("утилита"):
                roles[pid] = False
    return roles


def _pid_changes(host, cmds=("java",), roles=None):
    """Перезапуски процессов команд cmds по времени жизни каждого PID: PID X исчез до конца данных, и ПОСЛЕ его
    последнего появления впервые появился PID Y той же команды (не существовавший одновременно с X).
    Пары подбираются по ролям (_java_roles): исчезнувшему основному процессу — самый ранний ещё не использованный
    основной PID, а если такого нет — самый ранний похожий на серверный JVM (≥ JAVA_MAIN_MIN_SNAPS снимков и RSS max
    ≥ 1 GB или жив до последнего снимка TOP); вспомогательному — только вспомогательный. Поэтому короткая утилита
    java в окне простоя не делит перезапуск узла на два и не считается перезапуском погибшего JVM (см. JAVA_GONE).
    Строки: [команда, старый pid, последний раз, новый pid, впервые, между, RSS нового MB, RSS старого MB, роль старого]."""
    life = {}  # pid -> [cmd, first_idx, last_idx, first_proc, last_proc, снимков, RSS max KB]
    for i, procs in enumerate(host.top):
        for p in procs:
            if not any(p.cmd == c or p.cmd.startswith(c) for c in cmds):
                continue
            L = life.get(p.pid)
            if L is None:
                life[p.pid] = [p.cmd, i, i, p, p, 1, p.rss if p.rss == p.rss else -1.0]
            else:
                L[2] = i
                L[4] = p
                L[5] += 1
                if p.rss > L[6]:
                    L[6] = p.rss
    last_top = max((i for i, x in enumerate(host.top) if x), default=-1)
    by_cmd = defaultdict(list)
    for pid, L in life.items():
        by_cmd[L[0]].append((pid, L))
    if roles is None:
        roles = _java_roles(host)
    main = lambda pid: roles.get(pid, True)  # noqa: E731

    def server_like(M):
        return M[5] >= JAVA_MAIN_MIN_SNAPS and (M[6] >= JAVA_MAIN_RSS_KB or M[2] == last_top)

    out = []
    used_new = set()
    for cmd, items in by_cmd.items():
        order = sorted(items, key=lambda kv: kv[1][1])  # по первому появлению (кандидаты — двоичным поиском)
        firsts = [M[1] for _, M in order]
        vanished = [(pid, L) for pid, L in items if L[2] < last_top]
        # сначала основные процессы и те, что исчезли позже: они получают ближайший новый PID
        vanished.sort(key=lambda kv: (0 if main(kv[0]) else 1, -kv[1][2]))
        for pid, L in vanished:
            pick = spare = None
            for q, M in order[bisect.bisect_right(firsts, L[2]):]:
                if q in used_new:
                    continue
                if main(pid):
                    if main(q):
                        pick = (q, M)
                        break
                    if spare is None and server_like(M):
                        spare = (q, M)
                elif not main(q):
                    pick = (q, M)
                    break
            pick = pick or spare
            if pick is None:
                continue
            q, M = pick
            used_new.add(q)
            gap = (host.times[M[1]] - host.times[L[2]]).total_seconds()
            out.append([cmd, pid, host.times[L[2]], q, host.times[M[1]], fmt_dur(gap),
                        M[3].rss / 1024.0 if M[3].rss == M[3].rss else NAN,
                        L[4].rss / 1024.0 if L[4].rss == L[4].rss else NAN,
                        "основной" if main(pid) else "вспомогательный"])
    out.sort(key=lambda r: r[4])
    return out


PID_CHANGE_COLS = ["команда", "старый pid", "последний раз", "новый pid", "впервые", "между", "RSS нового MB", "RSS старого MB", "роль"]
PID_CHANGE_PREC = {"старый pid": 0, "новый pid": 0, "RSS нового MB": 0, "RSS старого MB": 0}


def _top_count(top_b, a, b):
    """Число снимков с TOP строго между индексами a и b (top_b — отсортированные индексы снимков с TOP)."""
    return max(0, bisect.bisect_left(top_b, b) - bisect.bisect_right(top_b, a))


def _java_life(host, jp=None):
    """Жизненный цикл java-PID по полному ряду хоста (host.unfiltered при окне --from/--to/--around): появление,
    исчезновение, паузы и перезапуски оцениваются по всем данным (иначе край окна выглядит как гибель или старт JVM),
    а сообщается то, что захватывает окно. dict: base — полный хост; lo, hi — индексы окна в base; top_b — индексы
    base со снимками TOP; jp — pid -> [(индекс base, Proc)]; roles — _java_roles, где преемник основного JVM в
    перезапуске тоже основной; changes — _pid_changes по base. jp — host.java_procs(), если уже посчитан."""
    base = host.unfiltered or host
    bjp = jp if jp is not None and base is host else base.java_procs()
    lo, hi = 0, base.n() - 1
    if base is not host and host.times:
        lo = bisect.bisect_left(base.times, host.times[0])
        hi = bisect.bisect_right(base.times, host.times[-1]) - 1
    roles = _java_roles(base, bjp)
    changes = _pid_changes(base, roles=roles)
    for r in changes:
        if r[8] == "основной":
            roles[r[3]] = True
    return {"base": base, "lo": lo, "hi": hi, "top_b": [k for k, x in enumerate(base.top) if x], "jp": bjp,
            "roles": roles, "changes": changes}


def _life_changes(life, host):
    """Перезапуски из _java_life, захватывающие окно host: новый PID появился не раньше начала окна, а старый
    исчез раньше его конца (простой пересекается с окном). Без окна — все."""
    if life["base"] is host or not host.times:
        return list(life["changes"])
    return [r for r in life["changes"] if r[4] >= host.times[0] and r[2] < host.times[-1]]


def _top_majflt_flag(host, pids):
    """Пометка колонки MajorFault TOP в at: (подпись колонки, примечание или None). По _fault_accounting (весь ряд
    хоста): 'retry' — колонка считает и faults после повтора; 'mismatch' — ненадёжна; 'unverified' — ≫ VM
    pgmajfault, но сверить с pgfault нельзя; иначе — сверка по каждому pid из pids по всем снимкам, где он есть
    в TOP: Σ majflt × шаг снимка (_snap_dt) > 10 × Σ VM pgmajfault (при Σ VM > 0) — ненадёжна. Без секции VM или
    колонки pgmajfault ничего не помечается."""
    pgmaj = host.col("VM", "pgmajfault")
    if pgmaj is None:
        return "majflt/s", None
    fa = _fault_accounting(host)
    dts = _snap_dt(host)  # события = скорость TOP × фактический шаг снимка (как приращения VM, после разрыва — весь разрыв)
    if fa["status"] == "retry":
        return "majflt/s (TOP, вкл. retry)", (
            f"MajorFault процессов TOP за период ≫ системного VM pgmajfault ({fa['top_major']:.0f} против {fa['vm_major']:.0f} "
            f"событий), но faults процессов сходятся с VM pgfault: TOP учитывает и faults, завершённые после повтора "
            f"(ожидание страницы/блокировки), а не только чтения с диска — реальные чтения с диска смотрите по vm.pgmajfault (см. check)")
    if fa["status"] == "unverified":
        return "majflt/s (TOP, не сверено)", _majflt_note(fa)
    bad = []
    if fa["status"] == "mismatch":
        bad.append(f"все процессы TOP: {fa['top_major']:.0f} против {fa['vm_major']:.0f} событий VM pgmajfault")
    else:
        want = set(pids)
        acc = {}  # pid -> [Σ majflt × шаг снимка, Σ VM pgmajfault] по снимкам, где pid в TOP (один проход по TOP)
        for i, procs in enumerate(host.top):
            done = set()
            for p in procs:
                if p.pid in want and p.pid not in done and p.majflt == p.majflt:
                    done.add(p.pid)
                    e = acc.setdefault(p.pid, [0.0, 0.0])
                    e[0] += p.majflt * dts[i]
                    if pgmaj[i] == pgmaj[i]:
                        e[1] += pgmaj[i]
        for pid in pids:
            proc_ev, sys_ev = acc.get(pid, (0.0, 0.0))
            if sys_ev > 0 and proc_ev > 10 * sys_ev:
                bad.append(f"pid {pid}: {proc_ev:.0f} событий MajorFault против {sys_ev:.0f} VM pgmajfault за те же интервалы")
    if not bad:
        return "majflt/s", None
    return "majflt/s (TOP, ненадёжно)", ("MajorFault в TOP не согласуется с системным VM pgmajfault (" + "; ".join(bad[:3])
                                         + "): для выводов о чтениях с диска смотрите vm.pgmajfault")


def analyze_at(host, args=None):
    """Срез всех метрик в момент времени ± окно: снимок, интервал которого содержит момент (первый снимок со
    временем ≥ момента; значения снимка — средние за интервал, предшествующий его метке), и ближайший по времени."""
    when = _opt(args, "time", None)
    rep = Report("Срез на момент времени", host.name)
    if not host.times:
        rep.text("", "нет снимков")
        return rep
    n = host.n()
    step = host.step()
    if when:
        t = getattr(args, "time_dt", None)
        if t is None:
            try:
                t = resolve_user_time(when, getattr(args, "time_ref", None) or host.times[0],
                                      getattr(args, "time_end", None) or host.times[-1])
            except UserError as e:
                raise SystemExit(f"ERROR: --time: {e}")
    else:
        # пик CPU без первых снимков файлов: T0001 охватывает ~1 с старта nmon и даёт ложный пик (и в нём нет TOP)
        hx = host.without_first()
        k = argmax(hx.cpu_busy() or [])
        t = hx.times[k] if k >= 0 else host.times[0]
    i = next((k for k, x in enumerate(host.times) if x >= t), n - 1)
    near = min(range(n), key=lambda k: abs((host.times[k] - t).total_seconds()))
    wv = _opt(args, "window_snaps", None)
    win = 2 if wv is None else max(0, int(wv))
    lo, hi = max(0, i - win), min(n, i + win + 1)
    firsts = host.first_snapshot_indices()
    after = t > host.times[-1]
    # предыдущий снимок — по полному ряду (у среза --from/--to первый снимок окна тоже имеет предшественника)
    base = host.unfiltered or host
    k = next((j for j, x in enumerate(base.times) if x >= host.times[i]), 0)
    prev = base.times[k - 1] if k > 0 else None
    # момент раньше начала записи файла/запуска nmon: первый снимок его интервал не покрывает (T0001 — ~1 с от старта)
    before = t < host.times[i] and (prev is None or i in firsts)
    contains = not after and not before and (prev is None or prev < t)
    items = [("запрошено", t), ("снимок (интервал содержит момент)" if contains else "снимок", host.times[i]),
             ("id", host.snap_ids[i])]
    if i in firsts:
        items.append(("интервал снимка", "неполный интервал (первый снимок файла/запуска)"))
    else:
        items.append(("интервал снимка", f"{ts(prev)} .. {ts(host.times[i])}" if prev is not None
                      else f"≈ {ts(host.times[i] - timedelta(seconds=host.iv(i)))} .. {ts(host.times[i])} (по интервалу nmon)"))
    if near != i:
        items.append(("ближайший по времени снимок", f"{ts(host.times[near])} ({host.snap_ids[near]})"))
    items.append(("окно", f"{host.times[lo]} .. {host.times[hi - 1]}"))
    dist = abs((host.times[near] - t).total_seconds())
    if t < host.start() - timedelta(seconds=1.5 * step) or t > host.end() + timedelta(seconds=1.5 * step):
        items.append(("ВНИМАНИЕ", f"запрошенный момент вне периода данных ({ts(host.start())} .. {ts(host.end())}), "
                                  f"ближайший снимок отстоит на {fmt_dur(dist)} — проверьте дату и часовой пояс (--tz-shift)"))
        warn(f"{host.name}: момент {ts(t)} вне периода данных, ближайший снимок {ts(host.times[near])}")
    elif after:
        items.append(("ВНИМАНИЕ", f"момент позже последнего снимка на {fmt_dur(dist)}: интервал, содержащий момент, "
                                  f"не записан — показан последний снимок"))
        warn(f"{host.name}: момент {ts(t)} позже последнего снимка {ts(host.times[-1])} на {fmt_dur(dist)} — интервал не записан")
    elif prev is not None and prev < t and (host.times[i] - prev).total_seconds() > 1.5 * host.iv(i):
        nxt = host.times[i]
        d = (nxt - prev).total_seconds()
        if i in firsts:
            # разрыв на границе файлов/запусков: nmon не работал; перезагрузка ОС — по boottime следующего запуска
            # (boottime с точностью до минуты — допуск минута до последнего снимка перед разрывом)
            boot = next((b for b in host.boot_times() if prev - timedelta(seconds=60) < b <= nxt), None)
            why = ("nmon не работал между файлами/запусками" + (f", в разрыве — перезагрузка ОС {ts(boot)}" if boot else "")
                   + "; снимок после разрыва — начало нового запуска nmon, разрыв не покрывает")
        else:
            why = ("nmon не записывал снимки — возможно, хост или nmon были заморожены; сам разрыв — улика (см. check); "
                   "значения снимка усреднены за весь разрыв")
        items.append(("ВНИМАНИЕ", f"момент попал в разрыв данных {ts(prev)} .. {ts(nxt)} ({fmt_dur(d)}): {why}"))
        warn(f"{host.name}: момент {ts(t)} попал в разрыв данных {ts(prev)} .. {ts(nxt)} ({fmt_dur(d)})")
    elif before:
        d = (host.times[i] - t).total_seconds()
        items.append(("ВНИМАНИЕ", f"момент раньше первого снимка файла/запуска на {fmt_dur(d)}: nmon ещё не писал, "
                                  f"интервал, содержащий момент, не записан — показан первый снимок"))
        warn(f"{host.name}: момент {ts(t)} раньше первого снимка файла/запуска {ts(host.times[i])} на {fmt_dur(d)} — "
             f"интервал не записан")
    rep.kv("Снимок", items)
    explicit = bool(_opt(args, "metrics", None))
    metrics = _opt(args, "metrics", None) or DEFAULT_TIMELINE + ["vm.pgmajfault"]
    resolved = [(m, r) for m, r in resolve_metrics(host, metrics, warn_missing=explicit) if len(r[2]) == n]  # vm.* без VM — []
    cols = ["время"] + [f"{m} [{r[1]}]" if r[1] else m for m, r in resolved]
    rows = []
    for k in range(lo, hi):
        row = [host.times[k]]
        for m, r in resolved:
            row.append(r[2][k])
        rows.append(row)
    rep.table("Ключевые метрики вокруг момента", cols, rows,
              prec={c: 0 for c, (m, _r) in zip(cols[1:], resolved) if m.startswith(("disk.", "net.", "mem.", "top.java.rss"))},
              note="CPU, диски, сеть, VM и TOP — средние за интервал снимка (до его метки времени); Runnable/Blocked, "
                   "память и ФС — мгновенные значения на конец интервала")
    # Процессы в этот момент
    procs = sorted(host.top[i], key=lambda p: -(p.cpu if p.cpu == p.cpu else -1))[:_opt(args, "top", 15) or 15]
    if procs:
        mcol, mnote = _top_majflt_flag(host.unfiltered or host, [p.pid for p in procs])
        rep.table(f"TOP в {ts(host.times[i])}", ["pid", "команда", "%CPU", "%usr", "%sys", "RSS MB", "threads", mcol, "iowait"],
                  [[p.pid, p.cmd, p.cpu, p.usr, p.sys, p.rss / 1024.0 if p.rss == p.rss else NAN, p.threads, p.majflt, p.iowait]
                   for p in procs], prec={"pid": 0, "RSS MB": 0, "threads": 0, mcol: 0, "iowait": 0}, note=mnote)
    elif host.top_in_files() and i in firsts:
        rep.text("TOP", "в первом снимке файла/запуска секции TOP нет (TOP пишется начиная со второго снимка)")
    # Диски и сеть в момент
    if host.has("DISKBUSY"):
        drows = []
        for d in host.disk_devices():
            b = host.col("DISKBUSY", d)
            if b is None or b[i] != b[i] or b[i] < 1:
                continue
            drows.append([d + (f" ({host.dm_map()[d]})" if d in host.dm_map() else ""), b[i],
                          (host.col("DISKREAD", d) or [NAN] * host.n())[i], (host.col("DISKWRITE", d) or [NAN] * host.n())[i],
                          (host.col("DISKXFER", d) or [NAN] * host.n())[i], (host.col("DISKBSIZE", d) or [NAN] * host.n())[i]])
        drows.sort(key=lambda r: -r[1])
        rep.table("Диски в этот момент (все устройства с busy ≥ 1%, включая разделы и dm-*)",
                  ["устройство", "busy%", "read KB/s", "write KB/s", "IOPS", "IO KB"], drows[:20], total=len(drows))
    if host.has("NET"):
        roles = host.net_roles()
        pkt = host.has("NETPACKET")

        def at_i(sec, col):
            a = host.col(sec, col)
            return a[i] if a is not None else NAN

        nrows = []
        for iface in host.net_ifaces():
            rd, wr = at_i("NET", f"{iface}-read-KB/s"), at_i("NET", f"{iface}-write-KB/s")
            if not (rd >= 1 or wr >= 1):
                continue
            row = [iface, roles.get(iface, ""), rd, wr]
            if pkt:
                pr, pw = at_i("NETPACKET", f"{iface}-read/s"), at_i("NETPACKET", f"{iface}-write/s")
                row += [pr, pw, rd * 1024.0 / pr if pr > 0 and rd == rd else NAN, wr * 1024.0 / pw if pw > 0 and wr == wr else NAN]
            nrows.append(row)
        rep.table("Сеть в этот момент", ["iface", "роль", "rx KB/s", "tx KB/s"] +
                  (["rx pkt/s", "tx pkt/s", "rx B/pkt", "tx B/pkt"] if pkt else []), nrows,
                  prec={"rx pkt/s": 0, "tx pkt/s": 0, "rx B/pkt": 0, "tx B/pkt": 0},
                  note="интерфейсы с трафиком ≥ 1 KB/s; трафик bond уже включает его слейвы — строки не складывайте; итог "
                       "хоста — net.read/net.write (без lo, слейвов, VLAN, мостов и виртуальных интерфейсов); B/pkt — средний размер пакета в интервале (~MTU — "
                       "массовая передача, сотни байт — мелкие сообщения/подтверждения)")
    # Ядра > 90%
    hot = []
    for core in host.cpu_cores:
        cu, cs = host.col(core, "User%"), host.col(core, "Sys%")
        if cu is None or cs is None:
            continue
        u, s = cu[i], cs[i]
        if u == u and s == s and u + s > 90:
            hot.append(f"{core}={u + s:.0f}%")
    if hot:
        rep.text("Ядра с busy > 90%", ", ".join(hot))
    return rep


# Повторённую опцию JVM применяет по последнему вхождению (скрипты запуска ставят значения по умолчанию в начало
# строки, пользовательские — после), поэтому значения берутся из последнего вхождения (кроме main class / jar).
JVM_FLAG_PATTERNS = [
    ("heap Xms", r"(?:-Xms|-XX:InitialHeapSize=)(\S+)"), ("heap Xmx", r"(?:-Xmx|-XX:MaxHeapSize=)(\S+)"),
    ("young Xmn", r"-Xmn(\S+)"),
    ("thread stack Xss", r"-Xss(\S+)|-XX:ThreadStackSize=(\d+)"),  # ThreadStackSize — в KB
    ("MaxRAMPercentage", r"-XX:MaxRAMPercentage=([\d.]+)"),
    ("MaxDirectMemorySize", r"-XX:MaxDirectMemorySize=(\S+)"),
    ("MaxMetaspaceSize", r"-XX:MaxMetaspaceSize=(\S+)"),
    ("GC", r"-XX:\+Use(\w+GC)"), ("MaxGCPauseMillis", r"-XX:MaxGCPauseMillis=(\d+)"),
    ("ParallelGCThreads", r"-XX:ParallelGCThreads=(\d+)"), ("ConcGCThreads", r"-XX:ConcGCThreads=(\d+)"),
    ("AlwaysPreTouch", r"-XX:(\+|-)AlwaysPreTouch"), ("UseLargePages", r"-XX:(\+|-)UseLargePages"),
    ("UseTransparentHugePages", r"-XX:(\+|-)UseTransparentHugePages"),
    ("HeapDumpOnOutOfMemoryError", r"-XX:(\+|-)HeapDumpOnOutOfMemoryError"),
    ("ExitOnOutOfMemoryError", r"-XX:(\+|-)ExitOnOutOfMemoryError"),
    ("DisableExplicitGC", r"-XX:(\+|-)DisableExplicitGC"),
    ("GC log", r"(-Xlog:gc\S*|-Xloggc:\S+|-verbose:gc)"),
    ("JMX port", r"-Dcom\.sun\.management\.jmxremote\.port=(\d+)"),
    ("java.net.preferIPv4Stack", r"-Djava\.net\.preferIPv4Stack=(\S+)"),
    ("main class / jar", r"(?:^|\s)(org\.apache\.ignite\.\S+|-jar \S+)"),
]


JVM_PAT = dict(JVM_FLAG_PATTERNS)


def _flag_values(pat, cmdline):
    """Значения опции по всем вхождениям в порядке командной строки (-XX:ThreadStackSize=N -> 'Nk': значение в KB)."""
    out = []
    for m in re.finditer(pat, cmdline):
        v = next((g for g in m.groups() if g is not None), m.group(0))
        out.append(v + "k" if m.group(0).startswith("-XX:ThreadStackSize=") else v)
    return out


def _last_flag(pat, cmdline):
    """Действующее значение опции — последнее вхождение (так её применяет JVM); None, если опции нет."""
    vals = _flag_values(pat, cmdline)
    return vals[-1] if vals else None


JVM_SIZE_FLAGS = {"heap Xms", "heap Xmx", "young Xmn", "thread stack Xss", "MaxDirectMemorySize", "MaxMetaspaceSize"}


def _size_txt(v):
    """Размер JVM-опции для вывода: в байтах или KB (-XX:MaxHeapSize=68719476736, -XX:ThreadStackSize=512) — с
    пересчётом в удобные единицы: '68719476736 (64.0 GB)'; с суффиксом m/g/t — как есть."""
    mb = _parse_size_mb(v)
    if mb == mb and re.match(r"^\d+(?:\.\d+)?[kK]?$", v.strip()):
        return f"{v} ({fmt_mb(mb)})"
    return v


def jvm_flags(cmdline):
    """Извлечь ключевые параметры JVM/Ignite из командной строки: список (имя, значение). Повторённая опция —
    последнее вхождение с пометкой «(переопределяет …)»; main class / jar — первое вхождение. Размеры в байтах/KB
    дополняются пересчётом (см. _size_txt)."""
    flags = []
    for label, pat in JVM_FLAG_PATTERNS:
        vals = _flag_values(pat, cmdline)
        if not vals:
            continue
        if label == "main class / jar":
            flags.append((label, vals[0]))
            continue
        fmt = _size_txt if label in JVM_SIZE_FLAGS else str
        prev = [fmt(v) for v in dict.fromkeys(vals[:-1]) if v != vals[-1]]
        flags.append((label, fmt(vals[-1]) + (f" (переопределяет {', '.join(prev)})" if prev else "")))
    ign = {}
    for k, v in re.findall(r"-D(IGNITE_\w+)=(\S+)", cmdline):
        ign[k] = v  # повтор -D — действует последнее значение
    flags.extend(ign.items())
    xx = re.findall(r"-XX:[+-]?\w+(?:=\S+)?", cmdline)
    if xx:
        flags.append(("все -XX", " ".join(xx)))
    return flags


def analyze_uarg(host, args=None):
    rep = Report("Командные строки процессов (UARG) и параметры JVM", host.name)
    base = host.unfiltered or host  # командная строка процесса пишется не в каждом снимке — ищем по всему ряду
    cl = base.uarg_cmdlines()
    if not cl:
        rep.text("", "Секция UARG отсутствует (nmon запущен без -T). Параметры JVM недоступны; "
                     "используйте логи Ignite или `ps` с узла.")
        return rep
    note = "полная строка: --full"
    if base is not host:
        seen = {p.pid for procs in host.top for p in procs}
        cl = {pid: v for pid, v in cl.items() if pid in seen or host.start() <= v[2] <= host.end()}
        note += ("; окно времени: показаны процессы, видимые в TOP окна или впервые записанные в UARG в окне "
                 "(nmon пишет командную строку процесса не в каждом снимке, обычно при первом появлении)")
        if not cl:
            rep.text("", "в выбранном окне нет процессов с командной строкой в UARG (ни один процесс из UARG не виден "
                         "в TOP окна); расширьте окно")
            return rep
    cmd_filter = _opt(args, "cmd", None)
    rows = []
    for pid, (prog, full, first) in sorted(cl.items(), key=lambda kv: kv[1][2]):
        if cmd_filter and not any(re.search(c, prog) or re.search(c, full) for c in cmd_filter):
            continue
        rows.append([pid, prog, first, full if _opt(args, "full", False) else (full[:200] + ("…" if len(full) > 200 else ""))])
    rep.table("Процессы", ["pid", "prog", "впервые", "командная строка"], rows, prec={"pid": 0}, note=note)
    jp = host.java_procs()
    total_mb = fmax(host.col("MEM", "memtotal")) if host.has("MEM") else NAN
    for pid, (prog, full, first) in cl.items():
        if prog != "java" and "java" not in full.split(" ")[0]:
            continue
        flags = [("роль", jvm_role(full))] + jvm_flags(full)
        rep.kv(f"JVM-параметры java[{pid}]", flags,
               note="повторённая опция: действует последнее вхождение (как в JVM), «переопределяет» — более ранние значения"
               if any("(переопределяет " in str(v) for _, v in flags) else None)
        thr_max = fmax([p.threads for _, p in jp.get(pid, [])]) if pid in jp else NAN
        rss_max = fmax([p.rss for _, p in jp.get(pid, [])]) / 1024.0 if pid in jp else NAN
        fp = jvm_footprint(full, thr_max, rss_max, total_mb)
        if fp:
            rep.kv(f"Оценка памяти java[{pid}] по флагам", fp, prec=JVM_FOOTPRINT_PREC,
                   note="RSS − (heap + direct + стеки) ≈ off-heap Ignite (data regions, checkpoint buffer) + metaspace + буферы; "
                        "heap может быть занят не полностью, поэтому оценка приблизительная")
    return rep


def _parse_size_mb(s):
    """Размер JVM-опции ('64g', '512m', '1024k', '1.5G', байты без суффикса) -> MB; NaN, если не разобрать."""
    m = re.match(r"^(\d+(?:\.\d+)?)([kKmMgGtT]?)$", s.strip())
    if not m:
        return NAN
    v = float(m.group(1))
    return v * {"": 1.0 / 1024 / 1024, "k": 1.0 / 1024, "m": 1.0, "g": 1024.0, "t": 1024.0 * 1024}[m.group(2).lower()]


def jvm_role(cmdline):
    if re.search(r"org\.apache\.ignite\.startup\.cmdline\.CommandLineStartup|IgniteNodeRunner|ignite\.sh", cmdline):
        return "серверный узел Ignite (CommandLineStartup)"
    if re.search(r"QuorumPeerMain|zookeeper", cmdline, re.I):
        return "ZooKeeper"
    if re.search(r"control\.sh|CommandHandler", cmdline):
        return "утилита control.sh"
    if re.search(r"ignite", cmdline, re.I):
        return "JVM с Ignite в classpath (клиентский узел / приложение)"
    return "JVM (роль по командной строке не определена)"


def jvm_footprint(cmdline, threads_max, rss_max_mb, total_mb=NAN):
    """Оценка памяти JVM по флагам (действуют последние вхождения опций): heap max (-Xmx / -XX:MaxHeapSize, без них —
    -XX:MaxRAMPercentage × RAM, total_mb — MemTotal, MB), MaxDirectMemorySize, стеки потоков (threads max ×
    -Xss / -XX:ThreadStackSize, по умолчанию 1 MB) против фактической RSS. None — ни heap, ни direct не заданы."""
    xmx = _last_flag(JVM_PAT["heap Xmx"], cmdline)
    mdm = _last_flag(JVM_PAT["MaxDirectMemorySize"], cmdline)
    xss = _last_flag(JVM_PAT["thread stack Xss"], cmdline)
    heap = _parse_size_mb(xmx) if xmx else NAN
    heap_txt = heap if heap == heap else "не задан (по умолчанию 1/4 RAM)"
    heap_src = None
    pct = _last_flag(JVM_PAT["MaxRAMPercentage"], cmdline)
    if heap != heap and pct:
        p = to_float(pct)
        if p == p and total_mb == total_mb and total_mb > 0:
            heap = heap_txt = total_mb * p / 100.0
            heap_src = f"оценка по MaxRAMPercentage={pct}% от RAM; при лимите cgroup — от лимита"
        else:
            heap_txt = f"не задан: MaxRAMPercentage={pct}% от RAM"
    direct = _parse_size_mb(mdm) if mdm else NAN
    stack = _parse_size_mb(xss) if xss else 1.0
    stacks = threads_max * stack if threads_max == threads_max else NAN
    if heap != heap and direct != direct:
        return None
    parts = [v for v in (heap, direct, stacks) if v == v]
    total = sum(parts)
    out = [("-Xmx (heap max)", heap_txt)] + ([("heap max: источник", heap_src)] if heap_src else []) + [
        ("-XX:MaxDirectMemorySize", direct if direct == direct else "не задан (по умолчанию = Xmx)"),
        ("стеки потоков (threads max × Xss)", stacks if stacks == stacks else "-")]
    if stacks == stacks:
        out += [("threads max", threads_max), ("Xss (стек потока)", stack)]
    out.append(("сумма учтённого", total))
    if rss_max_mb == rss_max_mb:
        out.append(("RSS max (факт)", rss_max_mb))
        out.append(("RSS − учтённое ≈ off-heap/metaspace/прочее", rss_max_mb - total))
    return out


# форматы ключей jvm_footprint для kv: размеры — MB (в text/md — GB/TB, в JSON — число MB с units)
JVM_FOOTPRINT_PREC = {"-Xmx (heap max)": "mb", "-XX:MaxDirectMemorySize": "mb", "стеки потоков (threads max × Xss)": "mb",
                      "threads max": 0, "Xss (стек потока)": "mb", "сумма учтённого": "mb", "RSS max (факт)": "mb",
                      "RSS − учтённое ≈ off-heap/metaspace/прочее": "mb"}


def _majflt_note(fa):
    """Пояснение к колонке MajorFault процессов TOP по сверке хоста (_fault_accounting); '' — пояснять нечего."""
    if fa["status"] == "retry":
        return ("MajorFault процесса учитывает faults, завершённые после повтора (ожидание страницы/блокировки), — это не "
                "чтения с диска; реальные чтения — vm.pgmajfault")
    if fa["status"] == "mismatch":
        mr = fa["major_ratio"]
        mr_s = "∞" if mr == math.inf else f"{mr:.0f}"
        return (f"Σ MajorFault процессов TOP НЕ согласуется с системным VM pgmajfault ({fa['vm_major']:.0f} событий за те же "
                f"интервалы, TOP больше в {mr_s} раз) и не сходится с VM pgfault: значение TOP MajorFault ненадёжно; "
                f"для major faults используйте vm.pgmajfault")
    if fa["status"] == "unverified":
        mr = fa["major_ratio"]
        mr_s = "∞" if mr == math.inf else f"{mr:.0f}"
        return (f"Σ MajorFault процессов TOP ≫ системного VM pgmajfault ({fa['vm_major']:.0f} событий за те же интервалы, "
                f"TOP больше в {mr_s} раз); сверить с VM pgfault нельзя (колонки нет или она всегда 0), поэтому смысл "
                f"колонки MajorFault не установлен — о чтениях с диска судите по vm.pgmajfault")
    return ""


JAVA_KV_PREC = {"pid": 0, "снимков в TOP": 0, "снимков с TOP всего": 0, "доля снимков присутствия, %": 0,
                "снимков TOP без процесса до первого появления": 0, "снимков TOP без процесса после последнего появления": 0,
                "%CPU avg (в % одного ядра; 100% = 1 ядро)": 0, "%CPU p95": 0, "%CPU max": 0, "ядер avg": 1, "ядер max": 1,
                "ядер на хосте": 0, "% машины avg": 1, "% машины max": 1, "доля sys в CPU процесса, %": 0,
                "RSS начало": "mb", "RSS max": "mb", "RSS конец": "mb", "RSS max, % RAM": 0,
                "анонимная RSS (ResSet − ShdLib) max": "mb", "анонимная RSS max, % RAM": 0,
                "file/shmem-backed часть RSS (ShdLib) max": "mb", "RSS тренд, MB/ч": 0, "RSS тренд r²": 2, "VSZ max": "mb",
                "threads начало": 0, "threads max": 0, "threads конец": 0, "threads тренд, /ч": 1, "threads тренд r²": 2,
                "major faults avg, /s": 1, "major faults max, /s": 0, "minor faults avg, /s": 0, "minor faults max, /s": 0,
                "faults всего (minor+major) avg, /s": 0, "faults всего (minor+major) max, /s": 0,
                "доля faults после повтора, %": 1, "IOwaitTime Σ (только главный поток — для JVM неинформативно)": 0}


def analyze_java(host, args=None):
    rep = Report("JVM (java) — процесс Ignite глазами ОС", host.name)
    if not any(host.top):
        rep.text("", _no_top_text(host))
        return rep
    jp = host.java_procs()
    life = _java_life(host, jp)
    base, top_b, bjp, roles, lo, hi = life["base"], life["top_b"], life["jp"], life["roles"], life["lo"], life["hi"]
    win = base is not host
    if not jp:
        if bjp:
            seen = sorted(bjp.items(), key=lambda kv: kv[1][0][0])
            rep.text("", "В окне процесс java не виден в TOP (JVM не работала или потребляла < порога TOP); по полному ряду: "
                         + "; ".join(f"java[{pid}] в TOP {ts(base.times[lst[0][0]])} .. {ts(base.times[lst[-1][0]])}"
                                     for pid, lst in seen[:5]) + (f"; ещё PID: {len(seen) - 5}" if len(seen) > 5 else ""))
        else:
            rep.text("", "Процесс java не найден в TOP за период (Ignite не запущен на узле, либо потреблял < порога TOP)")
        return rep
    ncpu = host.ncpus()
    total_mb = fmax(host.col("MEM", "memtotal")) if host.has("MEM") else NAN
    top_idx = [i for i, x in enumerate(host.top) if x]
    n_snap = len(top_idx)
    olds = {r[1] for r in life["changes"]}
    fa = _fault_accounting(host)
    maj_note = _majflt_note(fa)
    cl = base.uarg_cmdlines()  # командная строка (UARG) пишется не в каждом снимке — ищем по всему ряду
    # подробный блок — основные JVM и --top вспомогательных с наибольшим Σ %CPU; остальные вспомогательные (короткие
    # утилиты/клиенты, их могут быть тысячи) — одной сводной таблицей
    n_top = _opt(args, "top", 5) or 5
    cpu_sum = {pid: fsum([p.cpu for _, p in lst]) for pid, lst in jp.items()}
    aux = sorted((pid for pid in jp if not roles.get(pid, True)), key=lambda pid: -cpu_sum[pid])
    detail = {pid for pid in jp if roles.get(pid, True)} | set(aux[:n_top])
    for pid, lst in sorted(jp.items(), key=lambda kv: kv[1][0][0]):
        if pid not in detail:
            continue
        idxs = [i for i, _ in lst]
        cpu = [p.cpu for _, p in lst]
        usr = [p.usr for _, p in lst]
        sy = [p.sys for _, p in lst]
        rss = [p.rss / 1024.0 for _, p in lst]
        rss_c = clean(rss)
        anon = [(p.rss - p.shlib) / 1024.0 if (p.rss == p.rss and p.shlib == p.shlib) else NAN for _, p in lst]
        vsz = [p.size / 1024.0 for _, p in lst]
        thr = [p.threads for _, p in lst]
        thr_c = clean(thr)
        majf = [p.majflt for _, p in lst]
        minf = [p.minflt for _, p in lst]
        allf = [a + b if (a == a and b == b) else NAN for a, b in zip(minf, majf)]
        iow = [p.iowait for _, p in lst]
        times = [host.times[i] for i in idxs]
        # до первого / после последнего появления — по полному ряду (при окне: край окна — не старт и не гибель)
        bl = bjp.get(pid, lst)
        head = bisect.bisect_left(top_b, bl[0][0])
        tail = len(top_b) - bisect.bisect_right(top_b, bl[-1][0])
        tr_rss = trend(rss, times)
        tr_thr = trend(thr, times)
        imax = argmax(cpu)
        us_sum = fsum(usr) + fsum(sy)
        kv = [
            ("pid", pid),
            ("роль", "основной JVM" if roles.get(pid, True) else
             "вспомогательный java (утилита/клиент: малая RSS или короткая жизнь)"),
            ("снимков в TOP", len(lst)), ("снимков с TOP всего", n_snap),
            ("доля снимков присутствия, %", 100.0 * len(lst) / max(1, n_snap)),
            ("впервые", times[0]), ("последний раз", times[-1]),
        ]
        if win and (bl[0][0] < lo or bl[-1][0] > hi):
            kv.append(("в TOP по полному ряду (вне окна)", f"{ts(base.times[bl[0][0]])} .. {ts(base.times[bl[-1][0]])}"))
        kv += [
            ("снимков TOP без процесса до первого появления", head),
            ("снимков TOP без процесса после последнего появления", tail),
            ("%CPU avg (в % одного ядра; 100% = 1 ядро)", fmean(cpu)), ("%CPU p95", percentile(cpu, 95)),
            ("%CPU max", fmax(cpu)), ("время max %CPU", times[imax] if imax >= 0 else None),
            ("ядер avg", fmean(cpu) / 100), ("ядер max", fmax(cpu) / 100), ("ядер на хосте", ncpu),
        ]
        if ncpu:
            kv += [("% машины avg", fmean(cpu) / ncpu), ("% машины max", fmax(cpu) / ncpu)]
        kv += [
            ("доля sys в CPU процесса, %", 100.0 * fsum(sy) / us_sum if us_sum > 0 else NAN),
            ("RSS начало", rss_c[0] if rss_c else NAN), ("RSS max", fmax(rss)), ("RSS конец", rss_c[-1] if rss_c else NAN),
            ("RSS max, % RAM", 100.0 * fmax(rss) / total_mb if total_mb == total_mb and total_mb > 0 else NAN),
            ("анонимная RSS (ResSet − ShdLib) max", fmax(anon)),
            ("анонимная RSS max, % RAM", 100.0 * fmax(anon) / total_mb if total_mb == total_mb and total_mb > 0 else NAN),
            ("file/shmem-backed часть RSS (ShdLib) max", fmax([p.shlib / 1024.0 for _, p in lst])),
            ("RSS тренд, MB/ч", tr_rss["slope_per_h"]), ("RSS тренд r²", tr_rss["r2"]),
            ("VSZ max", fmax(vsz)),
        ]
        if thr_c:
            kv += [("threads начало", thr_c[0]), ("threads max", fmax(thr)), ("threads конец", thr_c[-1]),
                   ("threads тренд, /ч", tr_thr["slope_per_h"]), ("threads тренд r²", tr_thr["r2"])]
        else:
            kv.append(("threads", "нет данных (старая версия nmon без колонки Threads)"))
        kv += [("major faults avg, /s", fmean(majf)), ("major faults max, /s", fmax(majf)),
               ("minor faults avg, /s", fmean(minf)), ("minor faults max, /s", fmax(minf)),
               ("faults всего (minor+major) avg, /s", fmean(allf)), ("faults всего (minor+major) max, /s", fmax(allf))]
        if fa["status"] == "retry" and fsum(allf) > 0:
            kv.append(("доля faults после повтора, %",
                       100.0 * fsum([m for m, a in zip(majf, allf) if a == a]) / fsum(allf)))
        if maj_note:
            kv.append(("MajorFault: сверка с VM (по хосту)", maj_note))
        kv.append(("IOwaitTime Σ (только главный поток — для JVM неинформативно)", fsum(iow)))
        if not any(base.uarg):
            kv.append(("командная строка (UARG)", "нет (nmon без -T) — флаги JVM недоступны"))
        elif pid in cl:
            kv.append(("командная строка (UARG)", f"есть — см. «JVM-параметры java[{pid}] (UARG)»"))
        else:
            kv.append(("командная строка (UARG)", "нет строки UARG для этого PID"))
        gone = ""
        if tail:
            gone = ("; процесс сменился новым PID (перезапуск, см. health JAVA_RESTART)" if pid in olds else
                    "; процесс исчез из TOP до конца данных" + (" (см. health JAVA_GONE)" if roles.get(pid, True) else ""))
        rep.kv(f"java[{pid}]", kv, prec=JAVA_KV_PREC,
               note="RSS = heap + off-heap + metaspace + стеки + file/shmem-страницы (ShdLib); анонимная RSS ближе к "
                    "реальному потреблению памяти процессом; %CPU и faults — по снимкам, где процесс виден в TOP"
                    + ("; до первого / после последнего появления — по полному ряду (вне окна тоже)" if win else "") + gone)
        # Провалы CPU процесса (возможные паузы/зависания)
        med = fmedian(cpu)
        if med == med and med > 20:
            drops = [(times[k], cpu[k]) for k in range(len(cpu)) if cpu[k] == cpu[k] and cpu[k] < 0.1 * med]
            if drops:
                rep.table(f"java[{pid}]: снимки с %CPU < 10% от медианы ({med:.0f}%) — возможные паузы/остановки",
                          ["время", "%CPU"], [[t, v] for t, v in drops[:20]], total=len(drops))
        # Пропуски присутствия (паузы), захватывающие окно; длина — снимков TOP без процесса по полному ряду
        bidx = [i for i, _ in bl]
        j0 = max(0, bisect.bisect_left(bidx, lo) - 1)
        gaps = []
        for a, b in zip(bidx[j0:], bidx[j0 + 1:]):
            if a > hi:
                break
            miss = _top_count(top_b, a, b)
            if miss and _top_count(top_b, max(a, lo - 1), min(b, hi + 1)):
                gaps.append([base.times[a], base.times[b], miss])
        if gaps:
            rep.table(f"java[{pid}]: отсутствие в TOP между снимками (процесс не потреблял CPU или был остановлен)",
                      ["последний", "следующий", "пропущено снимков"], gaps[:20], total=len(gaps), prec={"пропущено снимков": 0},
                      note="пропущено — снимков с TOP без процесса; паузы на краю окна — по полному ряду (время может быть "
                           "вне окна)" if win else None)
        peaks = top_peaks(cpu, times, n=_opt(args, "top", 5) or 5, min_gap=2)
        busy = host.cpu_busy()
        w = host.col("CPU_ALL", "Wait%")
        prow = []
        for t, v in peaks:
            k = times.index(t)
            i = idxs[k]
            prow.append([t, v, sy[k], busy[i] if busy is not None else NAN, w[i] if w is not None else NAN,
                         rss[k], thr[k], majf[k]])
        rep.table(f"java[{pid}]: пики %CPU", ["время", "%CPU", "%sys", "CPU_ALL busy%", "wait%", "RSS MB", "threads", "majflt/s"],
                  prow, prec={"RSS MB": 0, "threads": 0, "majflt/s": 0})
    rest = [pid for pid in aux if pid not in detail]
    if rest:
        rows = []
        for pid in rest[:20]:
            lst = jp[pid]
            rows.append([pid, host.times[lst[0][0]], host.times[lst[-1][0]], len(lst), cpu_sum[pid] / max(1, n_snap),
                         fmax([p.cpu for _, p in lst]), fmax([p.rss for _, p in lst]) / 1024.0,
                         fmax([p.threads for _, p in lst]), jvm_role(cl[pid][1]) if pid in cl else "-"])
        t0 = min(jp[pid][0][0] for pid in rest)
        t1 = max(jp[pid][-1][0] for pid in rest)
        rep.table("Вспомогательные java без подробного блока (утилиты/клиенты: малая RSS или короткая жизнь)",
                  ["pid", "впервые", "последний", "снимков", "cpu Σ/снимков%", "cpu max%", "RSS max MB", "threads max", "роль (UARG)"],
                  rows, total=len(rest) if len(rest) > len(rows) else None,
                  prec={"pid": 0, "снимков": 0, "cpu Σ/снимков%": 2, "RSS max MB": 0, "threads max": 0},
                  note=f"всего {len(rest)} PID, в TOP {ts(host.times[t0])} .. {ts(host.times[t1])}; Σ их %CPU / снимков с TOP = "
                       f"{fsum([cpu_sum[pid] for pid in rest]) / max(1, n_snap):.2f}%; сортировка по Σ %CPU; подробный блок — "
                       f"для основных JVM и {n_top} вспомогательных с наибольшим CPU (--top)")
    changes = _life_changes(life, host)
    if changes:
        shown = [r for r in changes if r[8] == "основной"]
        shown += [r for r in changes if r[8] != "основной"][:max(0, 30 - len(shown))]
        shown.sort(key=lambda r: r[4])
        rep.table("Перезапуски java (смена PID)", PID_CHANGE_COLS, shown, prec=PID_CHANGE_PREC,
                  total=len(changes) if len(shown) < len(changes) else None,
                  note="малый RSS нового процесса = «холодный» старт; между = время между последним снимком старого и первым нового; "
                       "роль — старого процесса: основной JVM определяется по RSS и времени жизни PID (см. JAVA_RESTART)"
                       + ("; при окне времени — перезапуски, простой которых захватывает окно (по полному ряду)" if win else "")
                       + ("; показаны все смены PID основных JVM и первые смены вспомогательных" if len(shown) < len(changes) else ""))
    # Конкуренты за CPU: сумма %CPU по всем PID группы команд в снимке (kworker/*-<задача>, <поток ядра>/*)
    others = defaultdict(list)
    for i, procs in enumerate(host.top):
        per_cmd = defaultdict(float)
        for p in procs:
            if not _is_java(p) and p.cpu == p.cpu:
                per_cmd[cmd_group(p.cmd)] += p.cpu
        for c, v in per_cmd.items():
            others[c].append(v)
    orow = [[c, proc_category(c), len(v), fsum(v) / max(1, n_snap), fmean(v), fmax(v)] for c, v in others.items()]
    orow.sort(key=lambda r: -r[3])
    rep.table("Другие процессы с заметным CPU (конкуренты за CPU/IO)",
              ["команда", "категория", "снимков", "cpu Σ/снимков%", "cpu avg% (когда виден)", "cpu max%"],
              orow[:_opt(args, "top", 10) or 10], total=len(orow), prec={"cpu Σ/снимков%": 2},
              note="суммы по всем PID группы в снимке; cpu Σ/снимков% — среднее за весь период (снимок без процесса = 0), "
                   "по нему сортировка; kswapd0 = reclaim памяти; kworker/*-flush-*, kworker/*-writeback = сброс грязных "
                   "страниц; антивирусы/бэкапы/агенты мониторинга — типичные «соседи»")
    # Командная строка, если есть UARG (для PID с подробным блоком)
    for pid, lst in jp.items():
        if pid in cl and pid in detail:
            flags = [("роль", jvm_role(cl[pid][1]))] + jvm_flags(cl[pid][1])
            rep.kv(f"JVM-параметры java[{pid}] (UARG)", flags)
            fp = jvm_footprint(cl[pid][1], fmax([p.threads for _, p in lst]), fmax([p.rss for _, p in lst]) / 1024.0, total_mb)
            if fp:
                rep.kv(f"Оценка памяти java[{pid}] по флагам", fp, prec=JVM_FOOTPRINT_PREC)
    rep.text("Ограничения", "nmon не видит GC-паузы, занятость heap/off-heap, пулы потоков Ignite и сетевые соединения; "
                             "RSS включает heap + off-heap (data regions) + metaspace + стеки потоков + буферы; "
                             "используйте GC-логи и логи Ignite для точной картины.")
    return rep


def analyze_timeline(host, args=None):
    rep = Report("Временной ряд ключевых метрик", host.name)
    metrics = _opt(args, "metrics", None) or DEFAULT_TIMELINE
    step_s = parse_duration(_opt(args, "step", None)) if _opt(args, "step", None) else 0
    agg = _opt(args, "agg", "mean") or "mean"
    cols = ["время"]
    units = {}
    resolved = [(m, r) for m, r in resolve_metrics(host, metrics, warn_missing=bool(_opt(args, "metrics", None)))
                if len(r[2]) == host.n()]  # vm.* без секции VM дают пустой ряд — как недоступные
    missing = [m for m in metrics if m not in {n for n, _ in resolved}]
    if not resolved:
        rep.text("", "ни одна из метрик недоступна: " + ", ".join(missing))
        return rep
    sum_note = None
    if step_s:
        # общая с export агрегация: при sum — количество за корзину (единица меняется), уровни — WARN
        times, series, nn, unit_l, sum_note = aggregate_series(host, [(m, r[1], r[2]) for m, r in resolved], step_s, agg)
        cols.append("снимков")
    else:
        times, series, unit_l = host.times, [r[2] for _m, r in resolved], [r[1] for _m, r in resolved]
    for (m, _r), unit in zip(resolved, unit_l):
        label = f"{m} [{unit}]" if unit else m
        units[label] = m
        cols.append(label)
    rows = []
    for k in range(len(times)):
        rows.append([times[k]] + ([nn[k]] if step_s else []) + [s[k] for s in series])
    limit = _opt(args, "limit", None)
    total = len(rows)
    if limit and len(rows) > limit:
        rows = rows[:limit]
    prec = {"снимков": 0}
    for label in units:
        m = units[label]
        if m.startswith(("disk.", "net.", "vm.pgpg", "proc.pswitch", "mem.", "top.java.rss", "top.java.vsz", "top.java.threads")):
            prec[label] = 0
    notes = []
    if step_s:
        notes.append(f"корзины по {fmt_dur(step_s)}: границы кратны шагу от фиксированной полуночи (для шагов, делящих сутки, — "
                     f"от полуночи каждого дня); «снимков» — снимков в корзине (неполные корзины на краях)")
        if sum_note:
            notes.append(sum_note)
    if missing:
        notes.append("недоступны: " + ", ".join(missing))
    rep.table("Ряд" + (f" (агрегация {agg} по {fmt_dur(step_s)})" if step_s else ""), cols, rows, total=total, prec=prec,
              note="; ".join(notes) or None)
    return rep


# Минимальное абсолютное отклонение от фона, чтобы точка считалась выбросом (в единицах метрики; общее для
# events, cluster, compare)
EVENT_MIN_ABS = {"cpu.busy": 10, "cpu.sys": 5, "cpu.wait": 5, "cpu.steal": 1, "cpu.core_max": 20, "proc.runq": 4,
                 "proc.blocked": 3, "mem.free": 1024, "mem.avail": 1024, "mem.avail_cal": 1024, "mem.swap_used": 64,
                 "disk.busy_max": 15, "disk.read": 20000, "disk.write": 20000,
                 "disk.iops": 500, "net.read": 10000, "net.write": 10000, "top.java.cpu": 100, "top.java.rss": 2048,
                 "top.java.threads": 30, "top.java.majflt": 100, "vm.pswpout": 1, "vm.pgmajfault": 20, "vm.allocstall": 1,
                 # reclaim, страниц за интервал: прямой — от одной порции (32 страницы), kswapd — от 4 MB
                 "vm.pswpin": 1, "vm.pgscan_direct": 32, "vm.pgsteal": 1024, "vm.kswapd_steal": 1024,
                 "vm.pgscan_kswapd": 1024}
# Для метрик без EVENT_MIN_ABS: минимальное отклонение — доля |фона| (иначе событием становятся колебания +0.02%)
EVENT_REL_FLOOR = 0.05
# ... и не меньше минимума по единице метрики (event_floor): на нулевом фоне доля фона равна 0, и выбросом стало бы
# любое отличие от нуля (процесс на 1 % в TOP при нулевом заполнении, единичный счётчик)
EVENT_UNIT_MIN = {"%": 5.0, "MB": 64.0, "KB/s": 1000.0, "/s": 1.0, "pkt/s": 10.0, "pages/int": 1.0, "count/int": 1.0,
                  "count": 1.0}
EVENT_TOP_CPU_MIN = 10.0  # top.<cmd>.cpu|usr|sys (% одного ядра), если метрики нет в EVENT_MIN_ABS
# Доля |фона| вдобавок к EVENT_MIN_ABS: пулы потоков JVM меняют размер на десятки потоков при фоне в сотни
EVENT_REL_MIN = {"top.java.threads": 0.10}
# Провалы нагрузочных метрик: отклонение вниз засчитывается уже от min(EVENT_MIN_ABS, доля·|фона|) — провал трафика или
# записи до доли фона (остановка нагрузки, изоляция узла) виден и на узле с фоном ниже EVENT_MIN_ABS; при фоне
# < EVENT_DROP_FLOOR·EVENT_MIN_ABS (почти пустой интерфейс/диск) — только EVENT_MIN_ABS
EVENT_DROP_REL = {"net.read": 0.5, "net.write": 0.5, "disk.read": 0.5, "disk.write": 0.5, "top.java.cpu": 0.5}
EVENT_DROP_FLOOR = 0.01


class EventMinAbs(float):
    """Минимальное отклонение от фона (число, как в EVENT_MIN_ABS) с порогом для провалов: drop_rel — при значении ниже
    фона достаточно min(self, drop_rel·|фон|) (rolling_spikes; при |фон| < EVENT_DROP_FLOOR·self — только self)."""

    def __new__(cls, value, drop_rel=None):
        obj = super().__new__(cls, value)
        obj.drop_rel = drop_rel
        return obj


def event_min_abs(host):
    """EVENT_MIN_ABS с порогами под размер хоста: proc.runq — max(4, CPU/4), proc.blocked — max(3, CPU/16),
    mem.free/mem.avail/mem.avail_cal — max(1024 MB, 1 % RAM); без числа CPU или memtotal — константы. Для метрик из
    EVENT_DROP_REL значение — EventMinAbs (число с порогом для провалов): rolling_spikes учитывает его сам, поэтому
    провалы net/disk/java CPU одинаково ищут events и cluster."""
    ma = dict(EVENT_MIN_ABS)
    n = host.ncpus() or 0
    ma["proc.runq"] = max(EVENT_MIN_ABS["proc.runq"], n / 4.0)
    ma["proc.blocked"] = max(EVENT_MIN_ABS["proc.blocked"], n / 16.0)
    total = fmax(host.col("MEM", "memtotal") or [])
    if total == total and total > 0:
        for m in ("mem.free", "mem.avail", "mem.avail_cal"):
            ma[m] = max(EVENT_MIN_ABS[m], 0.01 * total)
    for m, rel in EVENT_DROP_REL.items():
        ma[m] = EventMinAbs(ma[m], rel)
    return ma


def event_floor(metric, unit, mins):
    """Пороги выброса метрики для rolling_spikes -> (min_abs, rel_floor): EVENT_MIN_ABS под размер хоста (mins —
    event_min_abs) и EVENT_REL_MIN; для метрик без EVENT_MIN_ABS — EVENT_REL_FLOOR·|фона|, но не меньше минимума по
    единице (EVENT_UNIT_MIN; top.<cmd>.cpu|usr|sys — EVENT_TOP_CPU_MIN; неизвестная единица — без минимума)."""
    if metric in mins:
        return mins[metric], EVENT_REL_MIN.get(metric)
    if metric.startswith("top.") and metric.rsplit(".", 1)[-1] in ("cpu", "usr", "sys"):
        return EVENT_TOP_CPU_MIN, EVENT_REL_FLOOR
    return EVENT_UNIT_MIN.get(unit), EVENT_REL_FLOOR


# Направление поиска выбросов (одно для events и cluster): 'down' — плохо, когда значение падает; 'both' — интересны
# отклонения в обе стороны (нагрузочные метрики: одновременный провал записи/трафика/CPU — сигнатура остановки
# операций); остальные метрики — 'up' (имена на «.idle» — 'down'), см. event_direction()
EVENT_DIRECTION = {"mem.free": "down", "mem.avail": "down", "mem.avail_cal": "down", "cpu.idle": "down",
                   "mem.cached": "both", "cpu.busy": "both", "disk.read": "both", "disk.write": "both",
                   "net.read": "both", "net.write": "both", "top.java.cpu": "both", "top.java.threads": "both"}


def event_direction(metric):
    """Направление поиска выбросов для метрики: 'up' | 'down' | 'both' (EVENT_DIRECTION, «.idle» — 'down')."""
    d = EVENT_DIRECTION.get(metric)
    if d:
        return d
    return "down" if metric.lower().endswith(".idle") else "up"


def _event_episodes(points, step):
    """Подряд идущие выбросы одной метрики одного знака (промежуток ≤ 1.5 интервала; step — интервал или функция
    время -> номинальный интервал снимка) -> эпизоды
    [начало, конец, снимков, метрика, пик, время пика, фон, z, ед.]; пик — точка с наибольшим |z| (z = ±inf — с
    наибольшим отклонением от фона). Возвращает [(score, row)], score — для отбора сильнейших."""
    by_m = defaultdict(list)
    for p in points:
        by_m[p[1]].append(p)
    out = []
    for m, pts in by_m.items():
        pts.sort(key=lambda p: p[0])
        groups = []
        for p in pts:
            g = groups[-1] if groups else None
            lim = 1.5 * (max(step(p[0]), step(g[-1][0])) if callable(step) else step) if g else 0.0
            if g and (p[0] - g[-1][0]).total_seconds() <= lim and (p[4] > 0) == (g[-1][4] > 0):
                g.append(p)
            else:
                groups.append([p])
        for g in groups:
            pk = max(g, key=lambda p: (min(abs(p[4]), 99.0), abs(p[2] - p[3]) / (p[6] or abs(p[3]) or 1.0)))
            score = (min(abs(pk[4]), 99.0), abs(pk[2] - pk[3]) / (pk[6] or abs(pk[3]) or 1.0))
            z = math.copysign(99.0, pk[4]) if math.isinf(pk[4]) else pk[4]
            out.append((score, [g[0][0], g[-1][0], len(g), m, pk[2], pk[0], pk[3], z, pk[5]]))
    return out


def analyze_events(host, args=None):
    """Заметные события: короткие выбросы по скользящей медиане/MAD (подряд идущие объединены в эпизоды) и эпизоды
    превышения порогов health (устойчивые плато, которые скользящая медиана не видит). Фон и эпизоды считаются по
    полному ряду хоста, показываются эпизоды, задевающие окно --from/--to/--around (целиком)."""
    rep = Report("События и выбросы", host.name)
    zv = _opt(args, "z", None)
    z_thr = 4.0 if zv is None else float(zv)
    wsn = int(_opt(args, "window_snaps", 15) or 15)
    explicit = bool(_opt(args, "metrics", None))
    metrics = _opt(args, "metrics", None) or [
        "cpu.busy", "cpu.sys", "cpu.wait", "cpu.steal", "proc.runq", "proc.blocked", "mem.free", "mem.swap_used",
        "vm.pswpout", "vm.pgmajfault", "vm.allocstall", "disk.busy_max", "disk.read", "disk.write", "disk.iops",
        "net.read", "net.write", "top.java.cpu", "top.java.rss", "top.java.threads"]
    # фон — по полному ряду хоста (до --from/--to/--around): при узком окне вокруг инцидента медиана окна была бы
    # самим инцидентом; первые снимки файлов (T0001, неполный интервал) событиями не считаем
    base = host.unfiltered or host
    hx = base.without_first()
    lo, hi = host.start(), host.end()
    if hx.n() < 5:
        rep.text("", (f"в окне {host.n()} снимков, в ряду {hx.n()}" if host.unfiltered is not None else f"в данных {hx.n()} снимков")
                 + " — мало для поиска выбросов (нужно ≥ 5 в ряду без первых снимков файлов)")
        return rep
    iv_at = dict(zip(hx.times, hx.snap_iv)) if hx.snap_iv else {}
    step = (lambda t, d=base.step(): iv_at.get(t, d)) if iv_at else base.step()
    mins = event_min_abs(base)
    resolved = resolve_metrics(hx, metrics, warn_missing=explicit)
    points = []  # по всему ряду: (время, метрика, значение, фон, z, ед., мин. отклонение)
    for m, r in resolved:
        ma, rf = event_floor(m, r[1], mins)
        for t, v, b, z in rolling_spikes(r[2], hx.times, window=wsn, z_thr=z_thr, min_abs=ma, direction=event_direction(m),
                                         rel_floor=rf):
            points.append((t, m, v, b, z, r[1], ma))
    # эпизоды — по всему ряду, показываются задевающие окно (целиком, как эпизоды порогов ниже); моменты по
    # нескольким метрикам — по точкам внутри окна
    eps = [e for e in _event_episodes(points, step) if e[1][1] >= lo and e[1][0] <= hi]
    points = [p for p in points if lo <= p[0] <= hi]
    total = len(eps)
    limit = _opt(args, "limit", 200) or 200
    cut = ""
    if total > limit:
        eps = sorted(eps, key=lambda x: x[0], reverse=True)[:limit]
        cut = f"; показаны {limit} сильнейших по |z| из {total} (отсекаются слабые, а не поздние)"
    rows = sorted((r for _s, r in eps), key=lambda r: (r[0], r[3]))
    names = {m for m, _r in resolved}
    scaled = [f"{m} ≥ {fmt_num(mins[m], 1)}" for m in ("proc.runq", "proc.blocked") if m in names] + \
             [f"{m} ≥ {fmt_mb(mins[m])}" for m in ("mem.free", "mem.avail", "mem.avail_cal") if m in names] + \
             [f"{m} ≥ max({EVENT_MIN_ABS[m]}, {EVENT_REL_MIN[m]:.0%} фона)" for m in EVENT_REL_MIN if m in names]
    half = max(2, wsn // 2)
    rep.table("Выбросы (робастный z-score по скользящему окну)",
              ["начало", "конец", "снимков", "метрика", "пик", "время пика", "фон (медиана окна)", "z", "ед."],
              rows, total=total, prec={"снимков": 0, "пик": 1, "фон (медиана окна)": 1, "z": 1},
              note=f"порог |z| ≥ {z_thr}; фон — медиана ±{half} соседних снимков (без самой точки)"
                   + (f" по полному ряду хоста; показаны эпизоды, задевающие окно {ts(lo)} .. {ts(hi)} (целиком)"
                      if host.unfiltered is not None else "")
                   + f"; подряд идущие выбросы одной метрики (промежуток ≤ 1.5 интервала, один знак) — один эпизод, пик — "
                     f"точка с max |z|; блок видит только всплески короче ≈ {half} снимков — устойчивые плато см. «Эпизоды "
                     f"превышения порогов» и cpu/disk/proc/health; длительное исчезновение java из TOP (top.java.cpu = 0) — "
                     f"health (JAVA_ABSENT/JAVA_GONE) и timeline; минимальные отклонения от фона отсекают шум"
                   + (f" ({', '.join(scaled)}; остальные — раздел 4 руководства)" if scaled else "")
                   + f", для метрик без порога — {EVENT_REL_FLOOR:.0%} фона, но не меньше минимума по единице (% — "
                     f"{EVENT_UNIT_MIN['%']:g} п.п., top.<cmd>.cpu — {EVENT_TOP_CPU_MIN:g} п.п., MB — {EVENT_UNIT_MIN['MB']:g}, "
                     f"KB/s — {EVENT_UNIT_MIN['KB/s']:g}, за интервал — {EVENT_UNIT_MIN['pages/int']:g}); z = ±99 — "
                     f"плоский фон (MAD и σ = 0){cut}")
    # Эпизоды превышения порогов health: плато длиннее половины окна медиана «поглощает», здесь они видны
    thr = _opt(args, "thresholds", None)
    ncpu = base.ncpus()
    limits = episode_levels(thr, ncpu)  # те же пороги, что у cpu и правил health *_RUN
    erows = []
    for m, r in resolved:
        if m not in limits:
            continue
        v_thr = limits[m][0]
        arr = r[2]
        # proc.blocked — «≥ порога» (как BLOCKED_HIGH), остальные — «> порога»
        # те же эпизоды, что у правил health *_RUN: длительность по меткам + шаг, разрыв на пропуске > 5 интервалов;
        # мгновенные Runnable/Blocked — промежуток между первым и последним отсчётом, разрыв на любом пропуске снимка
        for s, e, mx, dur in _timed_runs(hx, arr, v_thr - 1e-9 if m == "proc.blocked" else v_thr, min_len=2,
                                         instant=m in INSTANT_METRICS):
            if hx.times[e] < lo or hx.times[s] > hi:
                continue
            k = s + argmax(arr[s:e + 1])
            erows.append([m, hx.times[s], hx.times[e], dur, e - s + 1, mx, hx.times[k], v_thr])
    checked = [m for m in limits if m in names]
    if checked:
        etotal, ecut = len(erows), ""
        if etotal > limit:
            # как у выбросов: при обрезке остаются самые длинные (затем — с наибольшим пиком над порогом), а не ранние
            erows = sorted(erows, key=lambda r: (r[3], (r[5] - r[7]) / max(abs(r[7]), 1e-9)), reverse=True)[:limit]
            ecut = f"; показаны {limit} самых длинных из {etotal} (отсекаются короткие, а не поздние)"
        erows.sort(key=lambda r: (r[1], r[0]))
        conds = ", ".join(f"{m} {'≥' if m == 'proc.blocked' else '>'} {fmt_num(limits[m][0], 1)} ({limits[m][1]})" for m in checked)
        rep.table("Эпизоды превышения порогов (≥ 2 снимков подряд)",
                  ["метрика", "начало", "конец", "длительность", "снимков", "пик", "время пика", "порог"],
                  erows, total=etotal, prec={"длительность": "dur", "снимков": 0, "пик": 1, "порог": 1},
                  note=("эпизодов нет; " if not erows else "") + f"пороги — WARN правил health с учётом --thr, как у эпизодов "
                       f"cpu и эпизодных правил health (CPU_SATURATION_RUN, RUNQ_RUN, BLOCKED_RUN, DISK_BUSY_RUN; "
                       f"disk.busy_max — по физическим дискам): {conds}; длительность — от начала интервала первого снимка до конца последнего, на "
                       "пропуске данных > 5 интервалов эпизод разрывается; у мгновенных proc.runq/proc.blocked — промежуток "
                       "между первым и последним отсчётом, эпизод рвёт любой пропуск снимка (как в RUNQ_RUN); эпизод, "
                       "задевающий окно, показан целиком" + ecut)
    # Кластеризация событий по времени (по всем точкам до отбора): в какие минуты «всё сразу»
    if points:
        by_time = defaultdict(set)
        for p in points:
            by_time[p[0]].add(p[1])
        multi = [[t, len(ms), ", ".join(sorted(ms))] for t, ms in by_time.items() if len(ms) >= 3]
        multi.sort(key=lambda r: (-r[1], r[0]))
        if multi:
            rep.table("Моменты с выбросами сразу по нескольким метрикам", ["время", "метрик", "какие"], multi[:30], total=len(multi))
    return rep


# --------------------------------------------------------------------------
# Правила health-проверок
# --------------------------------------------------------------------------

# code: (описание, порог WARN, порог CRIT, единица)
DEFAULT_THRESHOLDS = {
    "CPU_SATURATION": ("CPU busy p95, %", 80.0, 95.0, "%"),
    "CPU_SATURATION_RUN": ("самый длинный эпизод busy > WARN CPU_SATURATION подряд, мин (CRIT — при max в эпизоде ≥ CRIT "
                           "CPU_SATURATION)", 5.0, 15.0, "мин"),
    "CPU_WAIT": ("CPU iowait avg, %", 10.0, 25.0, "%"),
    "CPU_WAIT_PEAK": ("CPU iowait max, %", 30.0, 60.0, "%"),
    "CPU_STEAL": ("CPU steal max, %", 1.0, 5.0, "%"),
    "CPU_SYS_SHARE": ("доля sys в busy (avg; при sys avg < 10 % всех CPU — INFO), %", 40.0, 60.0, "%"),
    "CPU_HOT_CORE": ("снимков с ядром > 90% при общей busy < 50%, %", 20.0, 50.0, "% снимков"),
    "CPU_HOT_CORE_RUN": ("самый длинный эпизод: ядро > 90 % при busy < 50 %, мин", 5.0, 30.0, "мин"),
    "RUNQ_HIGH": ("Runnable p95 / CPU", 1.0, 2.0, "x"),
    "RUNQ_RUN": ("самый длинный эпизод Runnable > WARN RUNQ_HIGH × CPU: мин между первым и последним отсчётом (CRIT — при "
                 "max ≥ CRIT RUNQ_HIGH × CPU; busy+steal в эпизоде < 50 % — INFO)", 3.0, 10.0, "мин"),
    "BLOCKED_HIGH": ("Blocked p95", 5.0, 20.0, "процессов"),
    "BLOCKED_RUN": ("самый длинный эпизод Blocked ≥ WARN BLOCKED_HIGH: мин между первым и последним отсчётом (CRIT — при "
                    "max ≥ CRIT BLOCKED_HIGH; без подтверждения iowait/диском — INFO)", 3.0, 10.0, "мин"),
    "MEM_AVAIL_LOW": ("min avail (free+buffers+(cached−shmem)+slab), % от RAM", 10.0, 5.0, "%"),
    "MEM_FREE_LOW": ("min memfree, % от RAM", 2.0, 1.0, "%"),
    "MEM_GROWTH": ("используемая память: часов до исчерпания при тренде", 48.0, 12.0, "ч"),
    "SWAP_USED": ("swap used max, % от RAM", 0.0, 5.0, "%"),
    "SWAP_ACTIVITY": ("снимков с pswpin/pswpout > 0", 0.0, 10.0, "снимков"),
    "DIRECT_RECLAIM": ("снимков с allocstall/pgscan_direct > 0", 0.0, 10.0, "снимков"),
    "KSWAPD_ACTIVE": ("доля снимков с активностью kswapd (pageoutrun > 0, kswapd_steal > 0 или kswapd* в TOP), %", 30.0, 80.0, "%"),
    "MAJFAULT_HIGH": ("major faults p95, /s", 20.0, 200.0, "/s"),
    "DISK_BUSY": ("busy p95 физического диска, %", 80.0, 95.0, "%"),
    "DISK_BUSY_SUSTAINED": ("доля времени busy > 90% (физический диск), %", 10.0, 30.0, "%"),
    "DISK_BUSY_RUN": ("самый длинный эпизод busy > 90 % физического диска подряд, мин", 5.0, 15.0, "мин"),
    "DISK_LATENCY": ("время обслуживания p95, ms (если DISK*SERV есть)", 20.0, 50.0, "ms"),
    "FS_FULL": ("заполненность ФС (конец периода), %", 85.0, 95.0, "%"),
    "FS_GROWTH": ("часов до 100% ФС при текущем росте", 24.0, 6.0, "ч"),
    "NET_LINK_UTIL": ("загрузка порта p95 (nic/слейв bond; нужен --link-mbit — скорость одного порта), %", 70.0, 90.0, "%"),
    "NET_ZERO": ("отрезок нулевого трафика (rx+tx < 0.5 KB/s) интерфейса с p75 ≥ 5 KB/s, снимков", 2.0, 5.0, "снимков"),
    "NET_DROP": ("провал трафика ниже max(0.5 KB/s, 5% p75) интерфейса с p75 ≥ 50 KB/s, снимков подряд", 2.0, 10.0, "снимков"),
    "NET_BOND_MEMBER": ("слейв bond (p75 ≥ 50 KB/s) ниже 5% своего p75 при живом bond, снимков подряд (молчание с начала "
                        "записи — INFO; bond с одним активным слейвом — WARN на смену слейва)", 2.0, 10.0, "снимков"),
    "NET_ERRORS": ("ошибки и дропы с загрузки (ifconfig, /proc/net/dev; bond — сверх слейвов; rx dropped < 0.1% принятых "
                   "и tx dropped < 10 ppm переданных пакетов не учитываются) или NETERROR × шаг за период; ниже — INFO",
                   1000.0, 100000.0, "count"),
    "JAVA_RSS": ("RSS java max, % от RAM", 85.0, 95.0, "%"),
    "JAVA_RSS_GROWTH": ("часов до RAM при тренде RSS java", 48.0, 12.0, "ч"),
    "JAVA_THREADS": ("threads java max", 2000.0, 5000.0, "потоков"),
    "JAVA_THREADS_GROWTH": ("рост threads основного java: медиана конца периода vs медиана начала (без разгона после "
                            "старта процесса), %", 30.0, 100.0, "%"),
    "JAVA_SYS_SHARE": ("доля sys в CPU основного java (WARN/CRIT при %CPU avg ≥ 50 — 0.5 ядра — и sys JVM ≥ 10 % "
                       "ёмкости CPU), %", 30.0, 50.0, "%"),
    "JAVA_CPU_DROP": ("снимков с CPU java < 10% медианы (при медиане > 20%; вспомогательный java — INFO)", 1.0, 3.0, "снимков"),
    "JAVA_RESTART": ("смена PID java", 1.0, 1.0, "раз"),
    "JAVA_ABSENT": ("java не виден в TOP подряд, снимков (при наличии TOP; вспомогательный java — INFO)", 2.0, 5.0, "снимков"),
    "JAVA_GONE": ("java исчез из TOP до конца данных (без перезапуска), снимков TOP без него", 2.0, 5.0, "снимков"),
    "JAVA_START": ("основной java впервые появился в TOP после начала данных (информационно; от порога WARN JAVA_GONE "
                   "снимков TOP без него)", 0.0, -1.0, ""),
    "NMON_GAP": ("максимальный разрыв между снимками внутри запуска nmon / interval", 1.5, 5.0, "x"),
    "NMON_COVERAGE_GAP": ("максимальный разрыв между файлами/запусками nmon / interval (nmon не работал; от порога WARN "
                          "NMON_GAP до WARN — INFO)", 5.0, 1e12, "x"),
    "NMON_SHORT": ("длительность данных, мин", 15.0, 5.0, "мин"),
    "BOOT_RECENT": ("часов от загрузки ОС до начала данных", 24.0, 1.0, "ч"),
    "THP_ACTIVE": ("AnonHugePages на старте, MB (THP используется)", 0.0, 1e12, "MB"),
    "OVERCOMMIT": ("Committed_AS / MemTotal на старте", 1.0, 1.5, "x"),
    "COMMIT_LIMIT": ("Committed_AS / CommitLimit на старте", 0.9, 0.98, "x"),
    "NO_SWAP": ("swap отсутствует (информационно)", 0.0, -1.0, ""),
    "IO_STALL": ("снимков с сигнатурой I/O-stall: Blocked ≥ 5 и iowait ≥ 5% и диск ≥ 90%", 3.0, 10.0, "снимков"),
    "DISK_SMALL_IO": ("fsync-heavy профиль: busy p95 ≥ порога при среднем IO ≤ 16 KB (информационно)", 80.0, 1e12, "%"),
    "CHECKPOINT_PERIOD": ("периодические всплески записи на самом нагруженном диске (информационно)", 0.0, -1.0, ""),
    "THP_COMPACTION": ("khugepaged/kcompactd активны в TOP (информационно)", 0.0, -1.0, ""),
    "CLUSTER_OUTLIER": ("|z| хоста относительно кластера", 3.0, 5.0, "z"),
    "CLUSTER_SYNC": ("доля хостов-участников синхронного всплеска/плато/провала, %: WARN — минимум для эпизода; рост "
                     "нагрузки — INFO (WARN при стрессе или вместе с провалом), провал активности — WARN/CRIT от доли ≥ "
                     "CRIT-порога, ×≤ 0.5 и длительности, стресс-метрики — по доле при пике выше WARN health",
                     50.0, 80.0, "%"),
    "CLUSTER_COVERAGE": ("хост без данных, пока у ≥ половины остальных они есть, снимков (до медианы их концов)", 3.0,
                         10.0, "снимков"),
}
# JAVA_SYS_SHARE: ниже этой средней нагрузки JVM (%CPU в TOP — в % одного ядра; 50 = 0.5 ядра) высокая доля sys —
# не проблема (простаивающая JVM почти всё время в epoll/futex/таймерах): не выше INFO
JAVA_SYS_SHARE_MIN_CPU = 50.0
# ... и если sys JVM занимает меньше этой доли ёмкости всех CPU узла (%, как порог 10 % в CPU_SYS_SHARE): высокая доля
# sys — профиль нагрузки (page faults на mmap/WAL, futex, сеть), а не узкое место — не выше INFO
JAVA_SYS_SHARE_MIN_CAP = 10.0


def _thr(thr, code):
    d = DEFAULT_THRESHOLDS[code]
    o = thr.get(code) if thr else None
    warn_v = o[0] if o and o[0] is not None else d[1]
    crit_v = o[1] if o and len(o) > 1 and o[1] is not None else d[2]
    if o and (len(o) < 2 or o[1] is None):
        # задан только WARN: CRIT не должен оказаться «мягче» WARN
        if d[2] >= d[1] and crit_v < warn_v:      # правило «больше — хуже»
            crit_v = warn_v
        elif d[2] < d[1] and crit_v > warn_v:     # правило «меньше — хуже»
            crit_v = warn_v
    return warn_v, crit_v


def _sev(value, warn_v, crit_v, higher_is_worse=True):
    if value is None or value != value:
        return None
    if higher_is_worse:
        if value >= crit_v:
            return "CRIT"
        if value >= warn_v:
            return "WARN"
    else:
        if value <= crit_v:
            return "CRIT"
        if value <= warn_v:
            return "WARN"
    return None


def _page_cache(host):
    """Файловый page cache без shmem/tmpfs, MB: cached − memshared."""
    c = host.col("MEM", "cached")
    s = host.col("MEM", "memshared")
    if c is None:
        return None
    return [max(0.0, cv - (sv if s is not None and sv == sv and sv >= 0 else 0.0)) if cv == cv else NAN
            for cv, sv in zip(c, s if s is not None else [NAN] * len(c))]


def _memory_pressure_corroboration(host):
    """Строка с подтверждениями давления на память (пусто, если их нет): major faults, swap, direct reclaim,
    падение avail ниже 10% RAM, устойчивое сжатие page cache."""
    ev = []
    mj = resolve_metric(host, "vm.pgmajfault")
    if mj and percentile(mj[2], 95) >= 20:
        ev.append(f"major faults p95 {percentile(mj[2], 95):.0f}/s")
    for name in ("vm.pswpin", "vm.pswpout", "vm.allocstall", "vm.pgscan_direct"):
        r = resolve_metric(host, name)
        if r and count_above(r[2], 0):
            ev.append(f"{name.split('.')[1]} > 0")
    total = fmax(host.col("MEM", "memtotal")) if host.has("MEM") else NAN
    av = host.mem_avail_calibrated()
    if av and total == total and total > 0 and fmin(av) / total < 0.10:
        ev.append(f"avail (с калибровкой) min {100 * fmin(av) / total:.1f}% RAM")
    ca = host.col("MEM", "cached")
    if ca is not None and clean(ca):
        tr = trend(ca, host.times)
        if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] < 0 and _reliable_trend(tr) \
                and abs(tr["delta"]) >= 0.10 * fmean(ca):
            ev.append(f"page cache устойчиво сжимается ({fmt_mb(tr['delta'])} за период)")
    return "; ".join(ev)


def _direct_reclaim_caveat(host):
    """Оговорка к «признаков давления нет»: на ядре ≥ 4.10 allocstall и pgscan_direct_* в nmon всегда 0
    (счётчики переименованы в /proc/vmstat) — direct reclaim не виден; '' — если счётчики работают или ядро неизвестно."""
    if host.kernel_version() < (4, 10):
        return ""
    for c in ("allocstall", "pgscan_direct_high", "pgscan_direct_normal", "pgscan_direct_dma"):
        a = host.col("VM", c)
        if a is not None and fsum(a) > 0:
            return ""
    return " (direct reclaim на этом ядре nmon не собирает — его отсутствие не доказано)"


def _reclaim_share(host):
    """Доля снимков (%) с признаками работы kswapd: pageoutrun > 0, kswapd_steal > 0 или kswapd* в TOP."""
    n = host.n()
    if n == 0:
        return NAN
    flags = [False] * n
    for name in ("vm.pageoutrun", "vm.kswapd_steal", "top.kswapd.cpu"):
        r = resolve_metric(host, name)
        if not r:
            continue
        for i, v in enumerate(r[2]):
            if v == v and v > 0:
                flags[i] = True
    return 100.0 * sum(flags) / n


def health_checks(host, thr=None, link_mbit=None):
    """Список Finding для хоста по правилам DEFAULT_THRESHOLDS (с переопределениями thr)."""
    F = []
    hn = host.name
    step = host.step()
    n = host.n()
    if n == 0:
        return [Finding("WARN", "NMON_EMPTY", hn, "снимков", 0, None, "нет временных снимков", "проверьте файл")]
    # ряды без первого снимка каждого файла/запуска nmon (T0001 охватывает неполный интервал) — для правил по пикам
    hx = host.without_first()

    def add(sev, code, metric, value, threshold, evidence, hint="", time=None):
        if sev:
            F.append(Finding(sev, code, hn, metric, value, threshold, evidence, hint, time))

    # --- качество данных ---
    # длительность данных — по полному ряду хоста: узкое окно --from/--to/--around не делает данные «короткими»
    full = host.unfiltered or host
    dur_min = full.duration() / 60.0
    w, c = _thr(thr, "NMON_SHORT")
    add(_sev(dur_min, w, c, higher_is_worse=False), "NMON_SHORT", "длительность, мин", dur_min, f"< {w}",
        f"{ts(full.start())} .. {ts(full.end())}", "короткий период: статистика ненадёжна")
    if host.unfiltered is not None and host.duration() / 60.0 < w:
        add("INFO", "WINDOW_SHORT", "длительность окна, мин", host.duration() / 60.0, f"< {w}",
            f"окно {ts(host.start())} .. {ts(host.end())}, снимков: {n}; данные хоста {ts(full.start())} .. {ts(full.end())}",
            "узкое окно --from/--to/--around: статистика и правила по рядам — только по снимкам окна")
    # разрывы внутри запуска nmon — заморозка хоста (NMON_GAP); между файлами/запусками nmon не работал (NMON_COVERAGE_GAP)
    inner, edge = host.split_gaps(factor=1.0)
    w_gap, c_gap = _thr(thr, "NMON_GAP")
    if inner:
        mx = max(inner, key=lambda g: g[2] / g[3])
        ratio = mx[2] / mx[3]  # разрыв / интервал nmon соседних снимков (у файлов с разным interval — свой)
        add(_sev(ratio, w_gap, c_gap), "NMON_GAP", "макс. разрыв / interval", ratio, f"≥ {w_gap}",
            f"разрыв {fmt_dur(mx[2])} между {ts(mx[0])} и {ts(mx[1])} (внутри запуска nmon); всего разрывов > 1.5× "
            f"внутри запусков: {len(host.split_gaps()[0])}",
            "nmon не успевал снимать данные: хост был заморожен/перегружен (паузы ВМ, нехватка CPU/памяти)", time=mx[0])
    boots = host.boot_times()
    if edge:
        mx = max(edge, key=lambda g: g[2] / g[3])
        ratio = mx[2] / mx[3]
        w, c = _thr(thr, "NMON_COVERAGE_GAP")
        inside = [b for b in boots if mx[0] < b <= mx[1]]
        add(_sev(ratio, w, c) or ("INFO" if ratio >= w_gap else None), "NMON_COVERAGE_GAP",
            "макс. разрыв между файлами/запусками nmon / interval", ratio, f"≥ {w}",
            f"разрыв {fmt_dur(mx[2])} между {ts(mx[0])} и {ts(mx[1])} (граница файлов/запусков nmon)"
            + (f"; в разрыве — перезагрузка ОС {ts(inside[-1])}" if inside else "")
            + f"; всего разрывов > 1.5× на границах: {len(host.split_gaps()[1])}",
            "nmon не работал (остановлен, перезапущен, перезагрузка ОС): данных за этот период нет — события в нём nmon "
            "не покажет", time=mx[0])
    # проблемы разбора файлов: отсортированный многозапусковый файл, обрезанный конец, снимки без времени, хосты с
    # одинаковым AAA,host на разных машинах, запуски разных хостов в одном файле (подробности — check)
    dq = []
    for fi, f in enumerate(host.files):
        b = os.path.basename(f.path)
        if f.sorted_multirun:
            dq.append(("CRIT", f"{b}: {MSG_SORTED_MULTIRUN}"))
        if f.truncated or f.incomplete:
            dq.append(("WARN", f"{b}: запись оборвана — последний снимок неполный" + (f" ({', '.join(sorted(f.incomplete))})"
                                                                                       if f.incomplete else "")))
        if f.untimed:
            dq.append(("WARN", f"{b}: {f.untimed} снимков без времени (нет ZZZZ, а AAA date/time нет или не разбираются) не использованы"))
        same = host.dup_same_file[fi] if fi < len(host.dup_same_file) else 0
        if same:
            dq.append(("WARN", f"{b}: {same} снимков отброшено — время совпало с более ранними снимками файла (часы назад или повтор запуска)"))
        if f.merge_note:
            dq.append(("WARN", f"{b}: файлы с тем же AAA,host сняты на разных машинах — объединение между ними отключено"))
        if f.split_note:
            # запуски разных AAA,host в одном файле разделены — данные каждого хоста целы, только к сведению
            dq.append(("INFO", f.split_note))
    ivd = host.intervals_differ()
    if ivd:
        dq.append(("INFO", f"{MSG_IV_DIFFER}: {_iv_list(ivd)}"))
    if dq:
        sev = min((s for s, _ in dq), key=lambda x: SEV_ORDER.get(x, 9))
        add(sev, "DATA_QUALITY", "проблем разбора данных", len(dq), None,
            "; ".join(t for _, t in dq[:5]) + (f"; … ещё {len(dq) - 5}" if len(dq) > 5 else ""),
            "результаты по затронутым снимкам или файлам ненадёжны (CRIT — непригодны); подробности — check")
    mf = host.mem_format_issue()
    if mf:
        add("INFO", "MEM_FORMAT", "колонок MEM", len(host.cols("MEM")), None,
            f"{mf}; колонки: {', '.join(host.cols('MEM')[:10])}", "отсутствие замечаний по памяти не означает, что с ней всё в порядке")
    aix = sorted({s for f in host.files for s in f.sections if s in AIX_SECTIONS})
    if aix:
        add("INFO", "NMON_AIX", "секций AIX", len(aix), None, f"секции {', '.join(aix)}: файл, вероятно, снят на AIX",
            "правила health рассчитаны на nmon для Linux: к AIX-данным неприменимы или неполны; сырые значения — export")
    if hx.firsts_kept:
        # в выборке только T0001 (неполный интервал ~1–2 с): правила по рядам не применяются — пустой ряд
        add("INFO", "NMON_FIRST_ONLY", "снимков в выборке", n, None, MSG_T1_KEPT,
            "правила по рядам (CPU, память, VM, диски, сеть) не применялись; расширьте окно или используйте файл длиннее")
        hx = host.slice([False] * n)
    # boottime по всем файлам и запускам nmon хоста: загрузка внутри периода = перезагрузка во время наблюдения
    if boots and host.start():
        during = [b for b in boots if host.start() < b <= host.end()]
        if during:
            b = during[-1]
            before = [x for x in boots if x < b]
            add("WARN", "BOOT_RECENT", "перезагрузка ОС во время наблюдения", ts(b), None,
                f"boottime {ts(before[-1]) + ' → ' if before else ''}{ts(b)}"
                + (f" (загрузок в периоде: {len(during)})" if len(during) > 1 else "")
                + f"; данные {ts(host.start())} .. {ts(host.end())}",
                "узел перезагружался во время наблюдения: проверьте причину (OOM-killer, kernel panic, watchdog, "
                "плановые работы) по журналам ОС и логам Ignite", time=b)
        prior = [b for b in boots if b <= host.start()]
        if prior:
            boot = prior[-1]
            hours = (host.start() - boot).total_seconds() / 3600.0
            w, c = _thr(thr, "BOOT_RECENT")
            add(_sev(hours, w, c, higher_is_worse=False), "BOOT_RECENT", "часов от загрузки ОС", hours, f"< {w}",
                f"boottime {ts(boot)}, данные с {ts(host.start())}", "недавняя перезагрузка узла: проверьте причину (OOM-killer, kernel panic, плановые работы)")
    # --- CPU --- (по hx: T0001 завышает busy/wait/steal и даёт ложные 100% на ядре)
    def covered(have, new):
        """Эпизодное правило не нужно, если правило за весь период уже выдано с той же или более высокой серьёзностью."""
        return have is not None and SEV_ORDER.get(have, 9) <= SEV_ORDER.get(new, 9)

    busy = hx.cpu_busy()
    ncpu = host.ncpus()
    rqx = hx.col("PROC", "Runnable")
    lv = episode_levels(thr, ncpu)  # пороги эпизодов *_RUN — те же, что у cpu и events
    if busy is not None:
        p95 = percentile(busy, 95)
        w, c = _thr(thr, "CPU_SATURATION")
        sat_sev = _sev(p95, w, c)
        add(sat_sev, "CPU_SATURATION", "CPU busy p95, %", p95, f"≥ {w}",
            f"avg {fmean(busy):.0f}%, max {fmax(busy):.0f}% @ {ts(series_stats(busy, hx.times)['max_time'])}, "
            f"время > 90%: {fmt_dur(time_above(busy, 90, _snap_dt(hx)))}",
            "CPU-насыщение: проверьте пулы Ignite (striped/system/public), GC, SQL-запросы, rebalancing")
        # короткое насыщение в длинном файле p95 не видит: самый длинный эпизод busy > WARN CPU_SATURATION (≥ 2 снимков
        # подряд); CRIT — только если в эпизоде достигнут и CRIT CPU_SATURATION
        lb = lv["cpu.busy"][0]
        runs = _timed_runs(hx, busy, lb, min_len=2)
        if runs:
            s0, e0, mx, dur = max(runs, key=lambda r: r[3])
            w, c = _thr(thr, "CPU_SATURATION_RUN")
            sev = _sev(dur / 60.0, w, c)
            if sev == "CRIT" and mx < _thr(thr, "CPU_SATURATION")[1]:
                sev = "WARN"
            if sev and not covered(sat_sev, sev):
                rmax = fmax(rqx[s0:e0 + 1]) if rqx is not None else NAN
                add(sev, "CPU_SATURATION_RUN", f"эпизод busy > {lb:g} %, мин подряд", dur / 60.0, f"≥ {w}",
                    f"{ts(hx.times[s0])} .. {ts(hx.times[e0])}: busy max {mx:.0f}%, avg {fmean(busy[s0:e0 + 1]):.0f}%; "
                    f"порог эпизода {lb:g}% — WARN CPU_SATURATION, CRIT — при max ≥ {_thr(thr, 'CPU_SATURATION')[1]:g}%; "
                    f"эпизодов ≥ 2 снимков: {len(runs)}"
                    + (f"; Runnable max {rmax:.0f} при {ncpu} CPU" if rmax == rmax else "")
                    + f"; топ-процесс в максимуме: {_top_proc_at(hx, s0 + argmax(busy[s0:e0 + 1]))}",
                    "CPU-насыщение в окне: пулы Ignite (striped/system/public), GC, SQL, rebalance; сопоставьте с логами по "
                    "времени; детали — cpu и health --from/--to", time=hx.times[s0])
        wt = hx.col("CPU_ALL", "Wait%")
        if wt is not None:
            w, c = _thr(thr, "CPU_WAIT")
            add(_sev(fmean(wt), w, c), "CPU_WAIT", "iowait avg, %", fmean(wt), f"≥ {w}",
                f"p95 {percentile(wt, 95):.1f}%, max {fmax(wt):.1f}% @ {ts(series_stats(wt, hx.times)['max_time'])}",
                "CPU простаивает в ожидании диска: смотрите disk (busy, latency), checkpoint/WAL Ignite")
            w, c = _thr(thr, "CPU_WAIT_PEAK")
            add(_sev(fmax(wt), w, c), "CPU_WAIT_PEAK", "iowait max, %", fmax(wt), f"≥ {w}",
                f"@ {ts(series_stats(wt, hx.times)['max_time'])}", "кратковременный I/O-шторм (checkpoint, снапшот, бэкап)",
                time=series_stats(wt, hx.times)["max_time"])
        st = hx.col("CPU_ALL", "Steal%")
        if st is not None:
            w, c = _thr(thr, "CPU_STEAL")
            add(_sev(fmax(st), w, c), "CPU_STEAL", "steal max, %", fmax(st), f"≥ {w}",
                f"avg {fmean(st):.2f}%, снимков > 0: {count_above(st, 0)}",
                "гипервизор отбирает CPU (переподписка): риск таймаутов failureDetectionTimeout/metrics",
                time=series_stats(st, hx.times)["max_time"])
        sy = hx.col("CPU_ALL", "Sys%")
        if sy is not None and fmean(busy) > 5:
            pairs = [(a, b) for a, b in zip(sy, busy) if a == a and b == b]
            share = 100.0 * sum(a for a, _ in pairs) / max(1e-9, sum(b for _, b in pairs))
            snap = [100.0 * a / b for a, b in pairs if b > 0]
            w, c = _thr(thr, "CPU_SYS_SHARE")
            sev = _sev(share, w, c)
            low = fmean(sy) < 10.0  # ядро занимает меньше 10% всей ёмкости CPU: доля — свойство нагрузки, не узкое место
            if sev and low:
                sev = "INFO"
            ev = (f"sys avg {fmean(sy):.1f}%" + (f" (≈ {fmean(sy) * ncpu / 100.0:.1f} ядер из {ncpu})" if ncpu else "")
                  + f", user avg {fmean(hx.col('CPU_ALL', 'User%')):.1f}%; доля sys по снимкам: медиана {fmedian(snap):.0f}%, "
                  f"p95 {percentile(snap, 95):.0f}%")
            psw = hx.col("PROC", "pswitch")
            if clean(psw) and ncpu:
                ev += f"; pswitch avg {fmean(psw) / ncpu:.0f}/s на CPU, r(Sys%, pswitch) = {fmt_num(pearson(sy, psw), 2)}"
            if sev == "INFO":
                ev += "; sys avg < 10% всех CPU — понижено до INFO"
            add(sev, "CPU_SYS_SHARE", "доля sys в busy, %", share, f"≥ {w}", ev,
                "высокая доля ядра при низкой абсолютной загрузке — профиль нагрузки (много потоков, переключения "
                "контекста, futex/epoll, сетевой обмен; на Linux в Sys% входят irq/softirq), не узкое место; значимо, если "
                "доля sys растёт в окне инцидента (compare, --from/--to)" if sev == "INFO" else
                "много ядерного времени: page faults/THP, сеть (softirq), spin/futex, слишком много потоков; на Linux Sys% "
                "включает irq/softirq — сравните с net, proc (pswitch) и cores (ядра и NUMA-узлы с высоким sys)")
        if hx.cpu_cores:
            hot = _core_hot_count(hx)
            hits = [i for i in range(hx.n()) if hot[i] > 0 and busy[i] == busy[i] and busy[i] < 50]
            share = 100.0 * len(hits) / max(1, hx.n())
            w, c = _thr(thr, "CPU_HOT_CORE")
            hot_sev = _sev(share, w, c)
            add(hot_sev, "CPU_HOT_CORE", "% снимков: ядро > 90% при busy < 50%", share, f"≥ {w}",
                f"{len(hits)} из {hx.n()} снимков (без T0001)" + (f", первый @ {ts(hx.times[hits[0]])}" if hits else ""),
                "однопоточное узкое место (один поток Ignite/GC/приложения упирается в ядро); на Linux Sys% включает "
                "irq/softirq: горячее ядро с преобладанием sys указывает на обработку прерываний сети",
                time=hx.times[hits[0]] if hits else None)
            # доля снимков за весь период не видит 10–30-минутное горячее ядро в длинном файле: самый длинный эпизод
            hep = _hot_core_episodes(hx)
            if hep:
                x = hep[0]
                w, c = _thr(thr, "CPU_HOT_CORE_RUN")
                sev = _sev(x["dur"] / 60.0, w, c)
                if sev and not covered(hot_sev, sev):
                    add(sev, "CPU_HOT_CORE_RUN", "эпизод: ядро > 90 % при busy < 50 %, мин подряд", x["dur"] / 60.0, f"≥ {w}",
                        f"{ts(x['start'])} .. {ts(x['end'])}: ядро {x['core']}"
                        + (f" (всего ядер в эпизоде: {x['ncores']})" if x["ncores"] > 1 else "")
                        + f", max {x['max']:.0f}% (user {x['user']:.0f}% / sys {x['sys']:.0f}%), общий busy avg "
                        f"{x['busy_avg']:.0f}%; эпизодов ≥ 2 снимков: {len(hep)}; топ-процесс: {x['top']}",
                        "однопоточное узкое место в окне (поток Ignite: checkpoint, exchange, striped; GC-поток); sys ≫ user на "
                        "горячем ядре — обработка прерываний сети (на Linux Sys% включает irq/softirq); детали — cpu "
                        "(эпизоды горячего ядра), cores --sort max, thread dump/JFR", time=x["start"])
    # --- PROC --- (по hx)
    if rqx is not None and ncpu:
        ratio = percentile(rqx, 95) / ncpu
        w, c = _thr(thr, "RUNQ_HIGH")
        rq_sev = _sev(ratio, w, c)
        add(rq_sev, "RUNQ_HIGH", "Runnable p95 / CPU", ratio, f"≥ {w}",
            f"Runnable p95 {percentile(rqx, 95):.0f}, max {fmax(rqx):.0f} при {ncpu} CPU",
            "очередь на CPU длиннее числа ядер: задержки планирования потоков Ignite",
            time=series_stats(rqx, hx.times)["max_time"])
        # Runnable — мгновенное значение в момент снимка: эпизод — только наблюдённый промежуток между первым и последним
        # отсчётом (≥ 2 подряд, без пропусков снимков), без растягивания на интервал; без загрузки CPU — не выше INFO
        lq = lv["proc.runq"][0]
        runs = _timed_runs(hx, rqx, lq, min_len=2, instant=True)
        if runs:
            s0, e0, mx, dur = max(runs, key=lambda r: r[3])
            w, c = _thr(thr, "RUNQ_RUN")
            sev = _sev(dur / 60.0, w, c)
            if sev == "CRIT" and mx < _thr(thr, "RUNQ_HIGH")[1] * ncpu:
                sev = "WARN"
            st_ = hx.col("CPU_ALL", "Steal%")
            load = [b + (st_[k] if st_ is not None and st_[k] == st_[k] else 0.0)
                    for k, b in enumerate(busy[s0:e0 + 1], s0) if b == b] if busy is not None else []
            low = bool(load) and fmean(load) < 50.0
            if sev and low:
                sev = "INFO"
            if sev and not covered(rq_sev, sev):
                add(sev, "RUNQ_RUN", f"эпизод Runnable > {lq / ncpu:g}×CPU, мин между первым и последним отсчётом",
                    dur / 60.0, f"≥ {w}",
                    f"{ts(hx.times[s0])} .. {ts(hx.times[e0])}: отсчётов подряд {e0 - s0 + 1}, промежуток {fmt_dur(dur)}; "
                    f"Runnable max {mx:.0f} ({mx / ncpu:.1f}× CPU) при {ncpu} CPU"
                    + (f", busy+steal avg {fmean(load):.0f}%" if load else "") + f"; эпизодов ≥ 2 отсчётов: {len(runs)}"
                    + ("; CPU в эпизоде загружен меньше чем на 50% — понижено до INFO" if low else ""),
                    "мгновенные всплески очереди при простаивающем CPU (пачка потоков, GC, одновременное пробуждение пула): "
                    "устойчивой очереди нет; если процессы привязаны к части CPU (taskset/cpuset) — смотрите cores" if low else
                    "очередь на CPU длиннее числа ядер в окне: задержки планирования потоков Ignite (discovery, "
                    "communication, striped); сопоставьте с логами по времени; детали — proc (пики Runnable), cpu",
                    time=hx.times[s0])
    bl = hx.col("PROC", "Blocked")
    if bl is not None:
        w_eff, c_eff, blbl = blocked_levels(thr, ncpu)  # по умолчанию масштабируется с числом CPU; --thr — как задан
        sev = bl_sev = _sev(percentile(bl, 95), w_eff, c_eff)
        # подтверждение: в снимках с высоким Blocked есть iowait ≥ 5% или диск ≥ 90%
        wt_ = hx.col("CPU_ALL", "Wait%")
        dbm, _who = hx.disk_max_busy()

        def io_corr(i):
            return (wt_ is not None and wt_[i] == wt_[i] and wt_[i] >= 5) or \
                (dbm is not None and dbm[i] == dbm[i] and dbm[i] >= DISK_BUSY_HIGH)

        hi = [i for i in range(hx.n()) if bl[i] == bl[i] and bl[i] >= w_eff]
        corr = [i for i in hi if io_corr(i)]
        if sev and hi and len(corr) < 0.3 * len(hi):
            sev = bl_sev = "INFO"
        add(sev, "BLOCKED_HIGH", "Blocked p95", percentile(bl, 95), f"≥ {w_eff:.0f} (= {blbl}; CRIT ≥ {c_eff:.0f})",
            f"max {fmax(bl):.0f} @ {ts(series_stats(bl, hx.times)['max_time'])}; снимков с Blocked ≥ {w_eff:.0f}: {len(hi)}, "
            f"из них с iowait ≥ 5% или диск ≥ {DISK_BUSY_HIGH:g}%: {len(corr)}",
            "много процессов/потоков ждут I/O (D-state): диск-насыщение, fsync WAL, checkpoint; Blocked — мгновенное значение "
            "в момент снимка, без подтверждения iowait/диском понижается до INFO",
            time=series_stats(bl, hx.times)["max_time"])
        # p95 за длинный период не видит 5–10-минутный эпизод: самый длинный эпизод Blocked ≥ WARN подряд (мгновенная
        # метрика — промежуток между первым и последним отсчётом, как RUNQ_RUN); без подтверждения iowait/диском — INFO
        runs = _timed_runs(hx, bl, w_eff - 1e-9, min_len=2, instant=True)
        if runs:
            s0, e0, mx, dur = max(runs, key=lambda r: r[3])
            w, c = _thr(thr, "BLOCKED_RUN")
            sev = _sev(dur / 60.0, w, c)
            if sev == "CRIT" and mx < c_eff:
                sev = "WARN"
            seg = [i for i in range(s0, e0 + 1) if bl[i] == bl[i] and bl[i] >= w_eff]
            ncorr = sum(1 for i in seg if io_corr(i))
            low = bool(seg) and ncorr < 0.3 * len(seg)
            if sev and low:
                sev = "INFO"
            if sev and not covered(bl_sev, sev):
                add(sev, "BLOCKED_RUN", f"эпизод Blocked ≥ {w_eff:.0f}, мин между первым и последним отсчётом",
                    dur / 60.0, f"≥ {w}",
                    f"{ts(hx.times[s0])} .. {ts(hx.times[e0])}: отсчётов подряд {e0 - s0 + 1}, Blocked max {mx:.0f} "
                    f"(порог {w_eff:.0f} = {blbl}; CRIT — при max ≥ {c_eff:.0f}); с iowait ≥ 5% или диском ≥ "
                    f"{DISK_BUSY_HIGH:g}%: {ncorr} из {len(seg)}; эпизодов ≥ 2 отсчётов: {len(runs)}"
                    + ("; без подтверждения iowait/диском — понижено до INFO" if low else ""),
                    "потоки стоят в D-state в окне: насыщение диска, fsync WAL, checkpoint; сопоставьте с логами Ignite по "
                    "времени; детали — proc (пики Blocked), disk, events" if not low else
                    "Blocked высокий, но iowait и диск в эпизоде не подтверждают ожидание I/O (NFS, cgroup-троттлинг, "
                    "мгновенные пачки потоков)", time=hx.times[s0])
    # --- память (по hx: без первых снимков файлов; калибровка avail — из исходного хоста, её копирует срез) ---
    total = fmax(hx.col("MEM", "memtotal")) if hx.has("MEM") else NAN
    if total == total and total > 0:
        avail = hx.mem_avail_calibrated()
        off = hx.mem_avail_offset()
        pct = 100.0 * fmin(avail) / total
        w, c = _thr(thr, "MEM_AVAIL_LOW")
        add(_sev(pct, w, c, higher_is_worse=False), "MEM_AVAIL_LOW", "min avail (оценка MemAvailable с калибровкой), % RAM", pct, f"≤ {w}",
            f"min {fmt_mb(fmin(avail))} @ {ts(series_stats(avail, hx.times)['min_time'])} из {fmt_mb(total)}"
            + (f"; поправка по MemAvailable на старте −{fmt_mb(off)}" if off > 0
               else f"; без калибровки ({hx.mem_avail_reason() or 'нет MemAvailable в BBBP'})"),
            "мало доступной памяти: риск reclaim/swap/OOM; проверьте размер data regions + heap + page cache",
            time=series_stats(avail, hx.times)["min_time"])
        free = hx.col("MEM", "memfree")
        pctf = 100.0 * fmin(free) / total
        w, c = _thr(thr, "MEM_FREE_LOW")
        sev = _sev(pctf, w, c, higher_is_worse=False)
        corr = _memory_pressure_corroboration(hx)
        if sev and not corr:
            sev = "INFO"  # мало free при большом page cache без признаков давления — штатное поведение Linux
        add(sev, "MEM_FREE_LOW", "min memfree, % RAM", pctf, f"≤ {w}",
            f"min {fmt_mb(fmin(free))} @ {ts(series_stats(free, hx.times)['min_time'])}; page cache без shmem avg {fmt_mb(fmean(_page_cache(hx)))}; "
            f"avail min {fmt_mb(fmin(avail))}; "
            + (f"подтверждение давления: {corr}" if corr else "признаков давления на память нет" + _direct_reclaim_caveat(hx)),
            "memfree у нуля само по себе — норма Linux (память занята page cache); тревожно только вместе с major faults, swap, "
            "падением avail или ростом чтений с диска")
        used = hx.mem_used()
        tr = trend(used, hx.times)
        if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] > 0 and _reliable_trend(tr):
            tte = time_to_limit(series_stats(used, hx.times)["last"], tr["slope_per_h"], total)
            w, c = _thr(thr, "MEM_GROWTH")
            add(_sev(tte, w, c, higher_is_worse=False), "MEM_GROWTH", "часов до исчерпания RAM (used)", tte, f"≤ {w}",
                f"used растёт на {tr['slope_per_h']:.0f} MB/ч (r²={tr['r2']:.2f}), сейчас {fmt_mb(series_stats(used, hx.times)['last'])}",
                "устойчивый рост used: утечка/накопление off-heap, рост page tables, кэш метаданных")
        sw = hx.swap_used()
        if sw is not None and fmax(sw) == fmax(sw):
            pcts = 100.0 * fmax(sw) / total
            w, c = _thr(thr, "SWAP_USED")
            sev = _sev(pcts, w, c) if fmax(sw) > 0 else None
            add(sev, "SWAP_USED", "swap used max, % RAM", pcts, f"> {w}",
                f"max {fmt_mb(fmax(sw))} @ {ts(series_stats(sw, hx.times)['max_time'])}",
                "swap для Ignite недопустим: паузы JVM, таймауты failure detection; отключите swap / уменьшите память процессов")
        stt = hx.col("MEM", "swaptotal")
        if stt is not None and fmax(stt) == 0:
            add("INFO", "NO_SWAP", "swaptotal", 0.0, None, "swap не настроен",
                "нормально для Ignite; при нехватке памяти сработает OOM-killer (ищите в dmesg/messages)")
    # --- VM (по hx: дельты T0001 охватывают неполный интервал) ---
    swp = []
    swp_cnt = 0
    swp_first = None
    for name in ("vm.pswpin", "vm.pswpout"):
        r = resolve_metric(hx, name)
        if r and count_above(r[2], 0):
            idx = [i for i, v in enumerate(r[2]) if v == v and v > 0]
            swp_cnt = max(swp_cnt, len(idx))
            t0 = hx.times[idx[0]]
            swp_first = t0 if swp_first is None or t0 < swp_first else swp_first
            swp.append(f"{name.split('.')[1]}: {len(idx)} снимков, сумма {fsum(r[2]):.0f} страниц, max {fmax(r[2]):.0f} @ {ts(series_stats(r[2], hx.times)['max_time'])}")
    if swp:
        w, c = _thr(thr, "SWAP_ACTIVITY")
        add(_sev(swp_cnt, w, c) or "WARN", "SWAP_ACTIVITY", "снимков с pswpin/pswpout > 0", swp_cnt, f"> {w}",
            "; ".join(swp), "идёт реальная подкачка: критично для латентности Ignite (паузы JVM, таймауты)", time=swp_first)
    dr = resolve_metric(hx, "vm.allocstall")
    dr2 = resolve_metric(hx, "vm.pgscan_direct")
    cnt = 0
    ev = []
    for r in (dr, dr2):
        if r:
            k = count_above(r[2], 0)
            cnt = max(cnt, k)
            if k:
                ev.append(f"{'allocstall' if r is dr else 'pgscan_direct'}: {k} снимков, сумма {fsum(r[2]):.0f}")
    if cnt:
        w, c = _thr(thr, "DIRECT_RECLAIM")
        add(_sev(cnt, w, c) or "WARN", "DIRECT_RECLAIM", "снимков с direct reclaim", cnt, f"> {w}", "; ".join(ev),
            "процессы сами освобождали память (stall): латентность; уменьшите потребление памяти или увеличьте RAM")
    share = _reclaim_share(hx)
    if share == share and share > 0:
        w, c = _thr(thr, "KSWAPD_ACTIVE")
        po = resolve_metric(hx, "vm.pageoutrun")
        kc = resolve_metric(hx, "top.kswapd.cpu")
        ev = []
        if po and count_above(po[2], 0):
            ev.append(f"pageoutrun > 0 в {count_above(po[2], 0)} снимках")
        if kc and count_above(kc[2], 0):
            ev.append(f"kswapd* в TOP (сумма по kswapdN): {count_above(kc[2], 0)} снимков, CPU max {fmax(kc[2]):.1f}%")
        ks = resolve_metric(hx, "vm.kswapd_steal")
        if ks and fsum(ks[2]) > 0:
            ev.append(f"kswapd_steal сумма {fsum(ks[2]):.0f} страниц")
        sev = _sev(share, w, c)
        corr = _memory_pressure_corroboration(hx)
        if sev and not corr:
            sev = "INFO"  # kswapd при потоковом I/O работает постоянно — без подтверждения это не проблема
        add(sev, "KSWAPD_ACTIVE", "доля снимков с активностью kswapd, %", share, f"≥ {w}",
            "; ".join(ev) + ("; подтверждение давления: " + corr if corr else
                             "; признаков давления (major faults, swap, падение avail/cached) нет" + _direct_reclaim_caveat(hx)),
            "фоновый reclaim page cache при потоковом I/O — норма; проблема, если одновременно растут major faults, "
            "чтения с диска или падает avail (данные Ignite вытесняются из кэша)")
    mj = resolve_metric(hx, "vm.pgmajfault")
    if mj:
        p95 = percentile(mj[2], 95)
        w, c = _thr(thr, "MAJFAULT_HIGH")
        add(_sev(p95, w, c), "MAJFAULT_HIGH", "major faults p95, /s", p95, f"≥ {w}",
            f"max {fmax(mj[2]):.0f}/s @ {ts(series_stats(mj[2], hx.times)['max_time'])}",
            "страницы подгружаются с диска (swap или вытесненный код/файлы): память под давлением")
    # --- диски (без первых снимков файлов: T0001 — 1–2 с старта nmon, его же чтения BBBP) ---
    if hx.has("DISKBUSY"):
        dmap = {e["device"]: e for e in hx.device_map()}
        sdts = _snap_dt(hx)
        disk_sev = None  # самое серьёзное из DISK_BUSY / DISK_BUSY_SUSTAINED — эпизодное правило ниже не дублирует его
        for d in hx.physical_disks():
            b = hx.col("DISKBUSY", d)
            if b is None or not clean(b):
                continue
            p95 = percentile(b, 95)
            w, c = _thr(thr, "DISK_BUSY")
            mnt = _disk_mount_label(dmap.get(d, {}))
            sev = _sev(p95, w, c)
            add(sev, "DISK_BUSY", f"busy p95 {d}" + (f" ({mnt})" if mnt else ""), p95, f"≥ {w}",
                f"avg {fmean(b):.0f}%, max {fmax(b):.0f}% @ {ts(series_stats(b, hx.times)['max_time'])}; "
                f"write max {fmax(hx.col('DISKWRITE', d) or [NAN]):.0f} KB/s, read max {fmax(hx.col('DISKREAD', d) or [NAN]):.0f} KB/s",
                "диск загружен: checkpoint/WAL/rebalance/снапшот; для NVMe busy≈100% может быть нормой при высоком IOPS — смотрите латентность и Blocked",
                time=series_stats(b, hx.times)["max_time"])
            share = 100.0 * count_above(b, DISK_BUSY_HIGH) / hx.n()
            w, c = _thr(thr, "DISK_BUSY_SUSTAINED")
            sev2 = _sev(share, w, c)
            add(sev2, "DISK_BUSY_SUSTAINED", f"доля времени busy > {DISK_BUSY_HIGH:g}% {d}", share, f"≥ {w}",
                f"{fmt_dur(time_above(b, DISK_BUSY_HIGH, sdts))} из {fmt_dur(sum(sdts))} (без T0001)", "длительное насыщение диска")
            for s_ in (sev, sev2):
                if s_ and (disk_sev is None or SEV_ORDER[s_] < SEV_ORDER[disk_sev]):
                    disk_sev = s_
        # доля за длинный период не видит 10–20-минутное насыщение: самый длинный эпизод busy > 90 % (disk.busy_max по
        # физическим дискам — тот же ряд и порог, что у эпизодов events)
        dbm_, dwho_ = hx.disk_max_busy()
        runs = _timed_runs(hx, dbm_, DISK_BUSY_HIGH, min_len=2) if dbm_ is not None else []
        if runs:
            s0, e0, mx, dur = max(runs, key=lambda r: r[3])
            w, c = _thr(thr, "DISK_BUSY_RUN")
            sev = _sev(dur / 60.0, w, c)
            if sev and not covered(disk_sev, sev):
                devs = sorted({dwho_[i] for i in range(s0, e0 + 1) if dwho_[i]})
                wt_ = hx.col("CPU_ALL", "Wait%")
                blk_ = hx.col("PROC", "Blocked")
                add(sev, "DISK_BUSY_RUN", f"эпизод busy > {DISK_BUSY_HIGH:g}% физического диска, мин подряд", dur / 60.0,
                    f"≥ {w}",
                    f"{ts(hx.times[s0])} .. {ts(hx.times[e0])}: {', '.join(devs[:4])}{' …' if len(devs) > 4 else ''}, "
                    f"busy max {mx:.0f}%"
                    + (f", iowait max {fmax(wt_[s0:e0 + 1]):.1f}%" if wt_ is not None else "")
                    + (f", Blocked max {fmax(blk_[s0:e0 + 1]):.0f}" if blk_ is not None else "")
                    + f"; эпизодов ≥ 2 снимков: {len(runs)}",
                    "насыщение диска в окне: checkpoint, WAL fsync, rebalance, снапшот; для NVMe busy≈100% бывает и при "
                    "запасе производительности — смотрите латентность (DISK*SERV), iowait и Blocked; детали — disk, events",
                    time=hx.times[s0])
        for sec, lbl in (("DISKREADSERV", "read"), ("DISKWRITESERV", "write")):
            if hx.has(sec):
                for d in hx.physical_disks():
                    a = hx.col(sec, d)
                    if a is None or not clean(a):
                        continue
                    p95 = percentile(a, 95)
                    w, c = _thr(thr, "DISK_LATENCY")
                    add(_sev(p95, w, c), "DISK_LATENCY", f"{lbl} service time p95 {d}, ms", p95, f"≥ {w}",
                        f"max {fmax(a):.1f} ms", "высокая латентность диска: fsync WAL и checkpoint будут медленными")
    # --- ФС (JFSFILE — уровень заполненности, первый снимок корректен: ряды полные, как в fs) ---
    if host.has("JFSFILE"):
        dfrows = {r["mount"]: r for r in host.df()}
        minfo = host.mount_info()
        for mnt in host.cols("JFSFILE"):
            a = host.col("JFSFILE", mnt)
            if a is None or not clean(a):
                continue
            # псевдо-ФС и смонтированные только для чтения (squashfs, ISO, ro-тома) не заполняются записью
            if _pseudo_fs(host, mnt, dfrows) or "ro" in minfo.get(mnt, ("", ""))[1].split(","):
                continue
            last = series_stats(a, host.times)["last"]
            w, c = _thr(thr, "FS_FULL")
            add(_sev(last, w, c), "FS_FULL", f"заполненность {mnt}, %", last, f"≥ {w}",
                f"max {fmax(a):.1f}%, размер {fmt_mb(dfrows.get(mnt, {}).get('size_mb'))}",
                "ФС почти полна: WAL-архив/снапшоты/логи; Ignite при нехватке места останавливает узел")
            tr = trend(a, host.times)
            if _reliable_trend(tr, FS_SLOPE_MIN):
                tte = time_to_limit(last, tr["slope_per_h"], 100.0)
                w, c = _thr(thr, "FS_GROWTH")
                add(_sev(tte, w, c, higher_is_worse=False), "FS_GROWTH", f"часов до 100% {mnt}", tte, f"≤ {w}",
                    f"рост {tr['slope_per_h']:.2f} п.п./ч (r²={tr['r2']:.2f}), сейчас {last:.1f}%",
                    "при таком росте ФС заполнится: проверьте WAL archive, снапшоты, логи")
    # --- сеть ---
    if hx.has("NET"):
        nroles = hx.net_roles()
        if link_mbit:
            # загрузка физических портов (nic, слейвы bond): --link-mbit — скорость одного порта
            cap = link_capacity_kbs(link_mbit)
            ports = [i for i in hx.net_ifaces() if nroles.get(i) == "nic" or nroles.get(i, "").startswith("bond-slave")]
            w, c = _thr(thr, "NET_LINK_UTIL")
            for lbl, d in (("rx", "read"), ("tx", "write")):
                best = None
                for i in ports:
                    a = hx.col("NET", f"{i}-{d}-KB/s")
                    p95 = percentile(a, 95)
                    if p95 == p95 and (best is None or p95 > best[0]):
                        best = (p95, fmax(a), i)
                if best is None:
                    continue
                util = 100.0 * best[0] / cap
                add(_sev(util, w, c), "NET_LINK_UTIL", f"{lbl} p95 {best[2]} / порт {link_mbit:g} Mbit/s, %", util, f"≥ {w}",
                    f"{best[2]} ({nroles[best[2]]}): {lbl} p95 {best[0]:.0f} KB/s, max {best[1]:.0f} KB/s "
                    f"({100.0 * best[1] / cap:.0f}% порта); --link-mbit — скорость одного физического порта",
                    "порт близок к насыщению: rebalance/putAll/backup; средние за интервал nmon скрывают микровсплески: "
                    "заметная загрузка по nmon уже допускает кратковременное насыщение порта")

        def longest(runs):
            return max(runs, key=lambda r: r[1] - r[0])

        for i in hx.net_primary_ifaces():
            ntot = _net_tot(hx, i)
            if ntot is None:
                continue
            q = _net_quiet_runs(hx, ntot, level=_net_level(hx, i))
            if q["zero"]:
                k0, k1, _mn, _d = longest(q["zero"])
                ln = k1 - k0 + 1
                w, c = _thr(thr, "NET_ZERO")
                add(_sev(ln, w, c), "NET_ZERO", f"нулевой трафик {i}, снимков подряд", ln, f"≥ {w}",
                    f"{ts(hx.times[k0])} .. {ts(hx.times[k1])}; rx+tx < {NET_ZERO_KBS:g} KB/s при обычном уровне "
                    f"p75 {q['L']:.0f} KB/s",
                    "интерфейс молчал: изоляция узла/сегментация Ignite, падение линка, остановка узла", time=hx.times[k0])
            if q["drop"]:
                k0, k1, mn, _d = longest(q["drop"])
                ln = k1 - k0 + 1
                w, c = _thr(thr, "NET_DROP")
                add(_sev(ln, w, c), "NET_DROP", f"провал трафика {i} ниже {100 * NET_DROP_SHARE:g}% p75, снимков подряд", ln,
                    f"≥ {w}", f"{ts(hx.times[k0])} .. {ts(hx.times[k1])}; p75 rx+tx {q['L']:.0f} KB/s, порог {q['thr']:.1f} KB/s, "
                              f"минимум в отрезке {mn:.1f} KB/s",
                    "если у остальных узлов трафик в это время обычный — изоляция/остановка узла, падение линка; "
                    "одновременный провал на всех узлах — прекращение нагрузки или сбой сегмента сети (см. cluster)",
                    time=hx.times[k0])
        single = {}  # bond -> _bond_single_active: трафик несёт один слейв (active-backup)
        for i in hx.net_ifaces():
            if not nroles.get(i, "").startswith("bond-slave"):
                continue
            nb = hx.bond_of(i)
            if nb is not None and nb not in single:
                single[nb] = _bond_single_active(hx, nb)
            if nb is not None and single[nb] is not None:
                continue  # молчание резервного слейва — норма; смены активного слейва — ниже, одно замечание на bond
            sq = _slave_quiet(hx, i)
            if sq is None:
                continue
            nb, q, bl, runs = sq
            real = [r for r in runs if not r[4]]
            if real:
                k0, k1, mn, _d, _n = longest(real)
                ln = k1 - k0 + 1
                w, c = _thr(thr, "NET_BOND_MEMBER")
                add(_sev(ln, w, c), "NET_BOND_MEMBER", f"слейв {i} молчал при живом {nb}, снимков подряд", ln, f"≥ {w}",
                    f"{i} (bond {nb}): {ts(hx.times[k0])} .. {ts(hx.times[k1])}; p75 слейва {q['L']:.0f} KB/s, минимум "
                    f"{mn:.1f} KB/s (порог {q['thr']:.1f} KB/s); bond в это время передавал ≥ {100 * NET_DROP_SHARE:g}% своего "
                    f"p75 {bl:.0f} KB/s",
                    "член bond молчал при живом бонде: падение линка/порта коммутатора, LACP; проверьте журнал ядра "
                    "(bonding: link status); на время отказа ёмкость бонда меньше", time=hx.times[k0])
            for k0, k1, mn, _d, _n in (r for r in runs if r[4] and r[1] > r[0]):
                add("INFO", "NET_BOND_MEMBER", f"слейв {i} молчал с начала записи при живом {nb}, снимков подряд",
                    k1 - k0 + 1, None,
                    f"{i} (bond {nb}): {ts(hx.times[k0])} .. {ts(hx.times[k1])}"
                    + (f", трафик несёт с {ts(hx.times[k1 + 1])}" if k1 + 1 < hx.n() else "")
                    + f"; до отрезка трафика ≥ {q['thr']:.1f} KB/s не было; p75 слейва {q['L']:.0f} KB/s",
                    "перехода «работал → замолчал» нет: резервный слейв active-backup, ставший активным позже, или линк, "
                    "поднявшийся во время записи; отказ подтверждайте журналом ядра (bonding: link status)",
                    time=hx.times[k0])
        for nb, segs in single.items():
            if not segs or len(segs) < 2:
                continue
            sw = [(segs[j - 1][0], segs[j][0], hx.times[segs[j][1]]) for j in range(1, len(segs))]
            add("WARN", "NET_BOND_MEMBER", f"смена активного слейва {nb}", len(sw), "≥ 1",
                "; ".join(f"{a_} → {b_} @ {ts(t_)}" for a_, b_, t_ in sw[:5])
                + (f"; всего смен: {len(sw)}" if len(sw) > 5 else "")
                + f"; в ≥ {100 * NET_AB_SHARE:g}% снимков с трафиком {nb} его несёт один слейв (active-backup или LACP с "
                  "одним живым портом); молчание резервного слейва — норма",
                "failover bond: отказ линка/порта прежнего активного слейва или срабатывание miimon/arp_monitor; проверьте "
                "журнал ядра (bonding: link status, new active interface) и порт коммутатора; кадры в момент переключения "
                "могли теряться", time=sw[0][2])
        errs = _net_error_counters(hx)
        if errs:
            w, c = _thr(thr, "NET_ERRORS")

            def rx_sig(e):
                # rx dropped в пределах 0.1 % принятых пакетов — обычно безвредны (уровень INFO)
                return e["rx_dropped"] if not e["rx_packets"] or e["rx_dropped"] >= NET_RX_DROP_SHARE * e["rx_packets"] else 0

            def tx_sig(e):
                # tx dropped (обычно собственные дропы bond) меньше 10 ppm переданных пакетов: счётчик с загрузки, момент
                # неизвестен, чаще всего — кадры при поднятии bond до активации слейвов (уровень INFO)
                return e["tx_dropped"] if not e["tx_packets"] or e["tx_dropped"] >= NET_TX_DROP_SHARE * e["tx_packets"] else 0

            # rx/tx errors (CRC, кабель, трансивер) — абсолютный порог: на десятках миллиардов пакетов это доли ppm, но
            # значимо; дропы — относительно числа пакетов (rx_sig, tx_sig)
            n_err = sum(e["rx_errors"] + e["tx_errors"] for e in errs)
            n_drop = sum(tx_sig(e) + rx_sig(e) for e in errs)
            sev_n = min((s_ for s_ in (_sev(n_err, w, c), _sev(n_drop, w, c)) if s_), key=SEV_ORDER.get, default="INFO")
            n_events = sum(e["rx_errors"] + e["tx_errors"] + e["rx_dropped"] + e["tx_dropped"] for e in errs)
            facts = []
            for x in sorted(errs, key=lambda e: -(e["rx_errors"] + e["tx_errors"] + e["rx_dropped"] + e["tx_dropped"]))[:5]:
                ev = x["rx_errors"] + x["tx_errors"] + x["rx_dropped"] + x["tx_dropped"]
                pk_i = (x["rx_packets"] or 0) + (x["tx_packets"] or 0)
                facts.append(f"{x['name']}{' (собственные, сверх слейвов)' if x['own'] else ''}: errors="
                             f"{x['rx_errors'] + x['tx_errors']}, dropped={x['rx_dropped'] + x['tx_dropped']} "
                             f"(rx {x['rx_dropped']}, tx {x['tx_dropped']})" +
                             (f", {1e6 * ev / pk_i:.2g} ppm от {pk_i} пакетов" if pk_i else ""))
            up = hx.uptime_seconds()
            if up:
                per_day = n_events * 86400.0 / up
                facts.append(f"uptime {up / 86400.0:.1f} сут; в среднем с загрузки ≈ {fmt_num(per_day, 0 if per_day >= 10 else 2)}"
                             f"/сут — распределение во времени неизвестно, рост в окне по BBBP не определить")
            hints = []
            own_tx = [e for e in errs if e["own"] and e["tx_dropped"] and not e["slaves_tx_dropped"]]
            if own_tx and all(not tx_sig(e) for e in own_tx):
                few = all(e["tx_dropped"] < 100 for e in own_tx)
                hints.append(f"собственный tx drop bond при нулях на слейвах, меньше {NET_TX_DROP_SHARE * 1e6:g} ppm "
                             "переданных пакетов — на передачу не влияет: "
                             + ("единичные дропы — обычно кадры, отправленные при поднятии bond до активации слейвов "
                                "(загрузка, перезапуск сети)" if few else
                                "кратковременно не было активного слейва/агрегатора (флап линка, LACP, перезапуск сети)")
                             + "; момент неизвестен — счётчик с загрузки")
            elif own_tx:
                hints.append("собственный tx drop bond при нулях на слейвах: бонд не смог передать кадры — не было "
                             "активного слейва/агрегатора (флап линка, LACP); момент неизвестен — счётчик с загрузки")
            if any(e["rx_dropped"] for e in errs):
                hints.append("rx dropped часто безвредны (кадры на резервном слейве, неизвестные протоколы); при росте — "
                             "нехватка кольцевого буфера/softirq")
            if any(e["rx_errors"] + e["tx_errors"] and e["role"] in ("nic", "bond-slave", "bond-slave (по трафику)", "-")
                   for e in errs):
                hints.append("rx/tx errors на физическом NIC — CRC/кабель/трансивер/порт коммутатора (ethtool -S)")
            hints.append("накопительные счётчики с загрузки ОС (BBBP на старте nmon): момент событий неизвестен — "
                         "сверьте журнал ядра (bonding, link status, NIC) за время инцидента")
            add(sev_n, "NET_ERRORS", "ошибки+дропы (накопительно с загрузки)", n_events,
                f"errors или dropped ≥ {w:g} (rx dropped < {NET_RX_DROP_SHARE:.1%} принятых и tx dropped < "
                f"{NET_TX_DROP_SHARE * 1e6:g} ppm переданных пакетов не учитываются); ниже — INFO",
                "; ".join(facts), "; ".join(hints))
        if hx.has("NETERROR"):
            dts = _snap_dt(hx)
            ser = [(c_, own, _integrate(hx, arr, dts)) for c_, _i, arr, own in _neterror_series(hx)]
            ser = sorted([x for x in ser if x[2] == x[2] and x[2] > 0], key=lambda x: -x[2])
            ntot = sum(x[2] for x in ser)
            if ntot > 0:
                w, c = _thr(thr, "NET_ERRORS")
                add(_sev(ntot, w, c) or "INFO", "NET_ERRORS", "NETERROR: ≈ событий за период (Σ rate × шаг)", ntot,
                    f"≥ {w} (ниже — INFO)",
                    "; ".join(f"{c_}{' (сверх слейвов)' if own else ''} ≈ {ev:.0f}" for c_, own, ev in ser[:5]) +
                    (f"; ещё колонок: {len(ser) - 5}" if len(ser) > 5 else ""),
                    "сетевые ошибки в период наблюдения; по времени — timeline --metrics raw.NETERROR.<колонка>")
    # --- java / TOP --- (жизненный цикл JVM — паузы, исчезновение, старт, перезапуск — по полному ряду: при окне
    # --from/--to/--around край окна не выглядит как гибель или старт JVM; выдаётся то, что захватывает окно)
    if any(host.top):
        jp = host.java_procs()
        life = _java_life(host, jp)
        base, top_b, bjp, roles, lo, hi = life["base"], life["top_b"], life["jp"], life["roles"], life["lo"], life["hi"]
        win = base is not host
        pc_txt = fmt_mb(fmean(_page_cache(host))) if host.has("MEM") else "-"  # один раз на хост, а не на каждый PID
        aux_txt = "вспомогательный java (малая RSS или короткая жизнь)"
        if not jp:
            if bjp:
                seen = sorted(bjp.items(), key=lambda kv: kv[1][0][0])
                add("INFO", "JAVA_ABSENT", "java в TOP окна", 0, None,
                    "в окне процесс java не виден в TOP; по полному ряду: "
                    + "; ".join(f"java[{pid}] в TOP {ts(base.times[lst[0][0]])} .. {ts(base.times[lst[-1][0]])}" for pid, lst in seen[:3])
                    + (f"; ещё PID: {len(seen) - 3}" if len(seen) > 3 else ""),
                    "окно попало на время, когда JVM не работала или не потребляла CPU выше порога TOP "
                    "(см. JAVA_GONE, JAVA_START, JAVA_RESTART)")
            else:
                add("INFO", "JAVA_ABSENT", "java в TOP", 0, None, "процесс java не найден ни в одном снимке",
                    "Ignite на узле не запущен либо потреблял < порога TOP")
        for pid, lst in jp.items():
            main = roles.get(pid, True)
            idxs = [i for i, _ in lst]
            rss = [p.rss / 1024.0 for _, p in lst if p.rss == p.rss]
            anon = [(p.rss - p.shlib) / 1024.0 for _, p in lst if p.rss == p.rss and p.shlib == p.shlib]
            thr_ = [p.threads for _, p in lst if p.threads == p.threads]
            cpu = [p.cpu for _, p in lst]
            usr = [p.usr for _, p in lst]
            sy = [p.sys for _, p in lst]
            times = [host.times[i] for i in idxs]
            rss_times = [host.times[i] for i, p in lst if p.rss == p.rss]
            if total == total and rss:
                ref = anon if anon else rss
                pct = 100.0 * max(ref) / total
                w, c = _thr(thr, "JAVA_RSS")
                sev = _sev(pct, w, c)
                if sev:
                    add(sev, "JAVA_RSS", f"{'анонимная RSS' if anon else 'RSS'} java[{pid}] max, % RAM", pct, f"≥ {w}",
                        f"RSS max {fmt_mb(max(rss))}" + (f", из них file/shmem (ShdLib) {fmt_mb(max(rss) - max(anon))}" if anon else "") +
                        f" из {fmt_mb(total)}; page cache без shmem avg {pc_txt}",
                        "JVM занимает почти всю RAM: сверьте с планом (heap + data regions + metaspace); page cache для WAL/checkpoint "
                        "остаётся мало, растёт риск OOM-killer при любом всплеске")
                tr = trend(rss, rss_times)
                if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] > 0 and _reliable_trend(tr):
                    tte = time_to_limit(rss[-1], tr["slope_per_h"], total)
                    w, c = _thr(thr, "JAVA_RSS_GROWTH")
                    add(_sev(tte, w, c, higher_is_worse=False), "JAVA_RSS_GROWTH", f"часов до RAM при росте RSS java[{pid}]", tte, f"≤ {w}",
                        f"RSS растёт {tr['slope_per_h']:.0f} MB/ч (r²={tr['r2']:.2f}), сейчас {fmt_mb(rss[-1])}",
                        "устойчивый рост RSS: off-heap/утечка/рост heap до Xmx (нормально в начале работы)")
            if thr_:
                w, c = _thr(thr, "JAVA_THREADS")
                add(_sev(max(thr_), w, c), "JAVA_THREADS", f"threads java[{pid}] max", max(thr_), f"≥ {w}",
                    f"начало {thr_[0]:.0f}, конец {thr_[-1]:.0f}", "очень много потоков: пулы Ignite/клиентские соединения/утечка потоков")
            # рост потоков: медиана конца периода vs медиана начала, только основной JVM; у процесса, появившегося
            # после начала данных TOP (старт/перезапуск), разгон пулов после старта отбрасывается — разгон определяется
            # по полному ряду, поэтому окно, начатое сразу после перезапуска, его тоже не учитывает
            if main and len(thr_) >= 10:
                tv = [(host.times[i], p.threads) for i, p in lst if p.threads == p.threads]
                bl = bjp.get(pid, lst)
                ramp = bool(top_b) and bl[0][0] > top_b[0]
                if ramp:
                    bt = [base.times[i] for i, p in bl if p.threads == p.threads]
                    t_ramp = bt[min(len(bt), max(5, len(bt) // 10)) - 1]  # конец разгона: первые max(5, 10 %) значений
                    tv = [x for x in tv if x[0] > t_ramp]
                k = max(3, len(tv) // 20)
                vals_ = [v for _, v in tv]
                b0 = fmedian(vals_[:k])
                if len(tv) >= 2 * k and b0 > 0:
                    e0 = fmedian(vals_[-k:])
                    ip = argmax(vals_)
                    peak, tp = vals_[ip], tv[ip][0]
                    growth = 100.0 * (e0 - b0) / b0
                    w, c = _thr(thr, "JAVA_THREADS_GROWTH")
                    ev = (f"база {b0:.0f} (медиана первых {k}), к концу {e0:.0f} (медиана последних {k}), пик {peak:.0f} @ {ts(tp)}"
                          + ("; разгон после старта процесса не учитывается" if ramp else ""))
                    if _sev(growth, w, c):
                        add(_sev(growth, w, c), "JAVA_THREADS_GROWTH", f"рост threads java[{pid}] к концу периода, %", growth,
                            f"≥ {w}", ev, "устойчивый рост числа потоков к концу периода: новые соединения/пулы, возможна утечка потоков")
                    elif 100.0 * (peak - b0) / b0 >= w:
                        add("INFO", "JAVA_THREADS_GROWTH", f"пик threads java[{pid}] относительно базы, %", 100.0 * (peak - b0) / b0,
                            f"≥ {w}", f"кратковременный всплеск числа потоков (пик {peak:.0f} @ {ts(tp)}, к концу {e0:.0f}); база {b0:.0f}",
                            "число потоков вернулось к обычному уровню: пачка соединений/задач (клиенты, rebalance, запросы)",
                            time=tp)
            # доля sys: только основной JVM с заметной нагрузкой (у простаивающей JVM доля sys высока сама по себе);
            # WARN/CRIT — только если ядро JVM занимает заметную долю ёмкости CPU узла (как CPU_SYS_SHARE)
            if main and len(lst) >= 3 and fsum(usr) + fsum(sy) > 0:
                share = 100.0 * fsum(sy) / (fsum(usr) + fsum(sy))
                w, c = _thr(thr, "JAVA_SYS_SHARE")
                sev = _sev(share, w, c)
                cpu_avg = fmean(cpu)
                low = cpu_avg == cpu_avg and cpu_avg < JAVA_SYS_SHARE_MIN_CPU
                cap = fmean(sy) / ncpu if ncpu else NAN  # sys JVM в % ёмкости всех CPU узла
                small = cap == cap and cap < JAVA_SYS_SHARE_MIN_CAP
                if sev:
                    allf = [a + b if (a == a and b == b) else NAN for a, b in ((p.minflt, p.majflt) for _, p in lst)]
                    r_f = pearson(sy, allf)
                    # CPU_ALL Sys% — по тем же снимкам, где процесс виден в TOP (без первых снимков файлов): вклад JVM и
                    # системный Sys% сравниваются за один и тот же период жизни процесса
                    sys_h = host.col("CPU_ALL", "Sys%")
                    firsts_ = host.first_snapshot_indices()
                    sys_all = [sys_h[i] for i in idxs if i not in firsts_] if sys_h is not None else None
                    ev = (f"usr avg {fmean(usr):.0f}%, sys avg {fmean(sy):.0f}% (в % ядра; sys ≈ {fmean(sy) / 100:.2f} ядра"
                          + (f", вклад в системный Sys% ≈ {cap:.1f} п.п. при CPU_ALL Sys% avg {fmt_num(fmean(sys_all), 1)}% "
                             f"за те же снимки (процесс в TOP {ts(times[0])} .. {ts(times[-1])})"
                             if ncpu and sys_all else "")
                          + ")" + (f"; faults (minor+major) avg {fmt_num(fmean(allf), 0)}/s, корреляция %sys с faults "
                                   f"r = {fmt_num(r_f, 2)}" if clean(allf) else ""))
                    if low:
                        sev = "INFO"
                        hint = (f"доля sys высокая, но нагрузка JVM мала: {cpu_avg / 100:.2f} ядра (< {JAVA_SYS_SHARE_MIN_CPU / 100:g}): "
                                "простаивающая JVM проводит время в epoll/futex/таймерах — само по себе не проблема")
                    elif small:
                        sev = "INFO"
                        ev += f"; sys JVM < {JAVA_SYS_SHARE_MIN_CAP:g}% ёмкости CPU — понижено до INFO"
                        hint = (f"доля sys JVM высокая, но ядро JVM занимает {cap:.1f}% ёмкости CPU — профиль нагрузки (page "
                                "faults на mmap/WAL, futex, сеть), не узкое место; значимо, если доля растёт в окне инцидента "
                                "(compare, --from/--to)")
                    elif host.meminfo().get("AnonHugePages", 0) > 0:
                        hint = ("JVM много времени в ядре: page faults (THP: компактация/khugepaged, первое касание памяти без "
                                "AlwaysPreTouch, mmap-файлы), futex-конкуренция, сеть")
                    else:
                        hint = ("JVM много времени в ядре: page faults (первое касание памяти, запись в mmap-файлы, ожидание "
                                "страниц под writeback), futex-конкуренция, сеть")
                    if not low and r_f == r_f and r_f >= 0.7:
                        hint += f"; sys процесса тесно связан с page faults (r = {r_f:.2f})"
                    add(sev, "JAVA_SYS_SHARE", f"доля sys в CPU java[{pid}], %", share, f"≥ {w}", ev, hint)
            med = fmedian(cpu)
            if med == med and med > 20:
                drops = [k for k in range(len(cpu)) if cpu[k] == cpu[k] and cpu[k] < 0.1 * med]
                if drops:
                    w, c = _thr(thr, "JAVA_CPU_DROP")
                    sev = _sev(len(drops), w, c)
                    add(sev if main or not sev else "INFO", "JAVA_CPU_DROP", f"снимков с CPU java[{pid}] < 10% медианы", len(drops), f"≥ {w}",
                        f"медиана {med:.0f}%, первый провал @ {ts(times[drops[0]])}" + ("" if main else f"; {aux_txt}"),
                        "резкое падение активности JVM: пауза (GC/safepoint), блокировка на I/O, остановка узла" if main else
                        "провал CPU утилиты/клиента java — не узла Ignite", time=times[drops[0]])
        # отсутствие в TOP подряд между появлениями PID — паузы, захватывающие окно; длина — по полному ряду
        w, c = _thr(thr, "JAVA_ABSENT")
        for pid, bl in bjp.items():
            bidx = [i for i, _ in bl]
            if bidx[-1] < lo or bidx[0] > hi:
                continue
            worst, wa, wb = 0, None, None
            j0 = max(0, bisect.bisect_left(bidx, lo) - 1)  # последнее появление до окна — его пауза может захватить окно
            for a, b in zip(bidx[j0:], bidx[j0 + 1:]):
                if a > hi:
                    break
                miss = _top_count(top_b, a, b)
                if miss > worst and _top_count(top_b, max(a, lo - 1), min(b, hi + 1)):
                    worst, wa, wb = miss, a, b
            if worst:
                main = roles.get(pid, True)
                sev = _sev(worst, w, c)
                ev = f"после {ts(base.times[wa])}"
                if win and (wa < lo or wb > hi):
                    ev += (f" ({'до начала окна' if wa < lo else 'в окне'}); снова в TOP {ts(base.times[wb])}"
                           f"{' (вне окна)' if wb > hi else ''}; значение — снимков TOP без процесса подряд по полному ряду")
                add(sev if main or not sev else "INFO", "JAVA_ABSENT", f"java[{pid}] не виден в TOP подряд, снимков", worst, f"≥ {w}",
                    ev + ("" if main else f"; {aux_txt}: отсутствие в TOP — простой ниже порога TOP"),
                    "процесс не потреблял CPU (пауза/зависание) или был остановлен" if main else
                    "утилита/клиент java простаивает — не узел Ignite", time=base.times[wa])
        changes = _life_changes(life, host)
        if changes:
            def edge(r):
                if not win:
                    return ""
                return (("; старый PID вне окна" if r[2] < host.times[0] else "")
                        + ("; новый PID вне окна" if r[4] > host.times[-1] else ""))
            main_ch = [r for r in changes if r[8] == "основной"]
            aux_ch = [r for r in changes if r[8] != "основной"]
            if main_ch:
                add("CRIT", "JAVA_RESTART", "смена PID основного процесса java", len(main_ch), "≥ 1",
                    "; ".join(f"{r[1]}→{r[3]} @ {ts(r[4])} (простой {r[5]}, RSS нового {fmt_mb(r[6])}{edge(r)})" for r in main_ch[:5]),
                    "процесс Ignite перезапускался: ищите причину в логах (OOM, segmentation, kill)", time=main_ch[0][4])
            if aux_ch:
                add("INFO", "JAVA_RESTART", "смена PID вспомогательного java-процесса (малая RSS или короткая жизнь)", len(aux_ch), None,
                    "; ".join(f"{r[1]}→{r[3]} @ {ts(r[4])}" for r in aux_ch[:5]),
                    "короткоживущие java (control.sh, утилиты, клиенты) — не перезапуск узла Ignite", time=aux_ch[0][4])
        # основной JVM исчез до конца данных без перезапуска / впервые появился после начала данных TOP — по полному
        # ряду (тот же PID после окна — пауза, JAVA_ABSENT; работавший до окна — не старт)
        olds, news = {r[1] for r in life["changes"]}, {r[3] for r in life["changes"]}
        w, c = _thr(thr, "JAVA_GONE")
        for pid, bl in bjp.items():
            if not roles.get(pid, True):
                continue
            first_i, last_i = bl[0][0], bl[-1][0]
            tail = len(top_b) - bisect.bisect_right(top_b, last_i)
            if pid not in olds and tail > 0 and tail >= w and _top_count(top_b, max(last_i, lo - 1), hi + 1):
                alive = [str(q) for q, L in bjp.items() if q != pid and roles.get(q, True) and L[-1][0] > last_i]
                add(_sev(tail, w, c), "JAVA_GONE", f"java[{pid}] исчез из TOP до конца данных, снимков", tail, f"≥ {w}",
                    f"последний раз {ts(base.times[last_i])}{' (до начала окна)' if last_i < lo else ''}, далее {tail} "
                    f"снимков TOP без него (до {ts(base.times[top_b[-1]])}{' — конец данных' if win else ''})"
                    + ("; повторная гибель: это новый процесс после перезапуска (JAVA_RESTART)" if pid in news else "")
                    + (f"; другие основные java продолжали работать: {', '.join(alive)}" if alive else ""),
                    "JVM завершилась или была убита (OOM-killer, kill, crash) либо зависла без потребления CPU и не "
                    "перезапускалась в окне данных — проверьте журнал ядра (OOM-killer) и логи Ignite", time=base.times[last_i])
            head = bisect.bisect_left(top_b, first_i)
            if pid not in news and head > 0 and head >= w and lo <= first_i <= hi:
                add("INFO", "JAVA_START", f"java[{pid}] впервые виден в TOP после начала данных", head, None,
                    f"впервые {ts(base.times[first_i])}, через {fmt_dur((base.times[first_i] - base.times[top_b[0]]).total_seconds())} "
                    f"после начала данных TOP ({head} снимков TOP без него)",
                    "JVM запущена во время записи (или до этого не потребляла CPU выше порога TOP); предыдущий процесс "
                    "в данных не виден", time=base.times[first_i])
    # --- конфигурация ---
    mi = host.meminfo()
    if mi:
        thp = mi.get("AnonHugePages", 0) / 1024.0
        if thp > 0:
            add("INFO", "THP_ACTIVE", "AnonHugePages на старте, MB", thp, "> 0", f"{fmt_bytes_kb(mi['AnonHugePages'])}",
                "Transparent Huge Pages используются: возможны всплески sys% при компактации (khugepaged); "
                "для Ignite обычно рекомендуют THP=madvise/never")
        if mi.get("MemTotal"):
            ratio = mi.get("Committed_AS", 0) / mi["MemTotal"]
            w, c = _thr(thr, "OVERCOMMIT")
            add(_sev(ratio, w, c) if ratio >= w else None, "OVERCOMMIT", "Committed_AS / MemTotal", ratio, f"≥ {w}",
                f"Committed_AS {fmt_bytes_kb(mi.get('Committed_AS', 0))}", "обещано больше памяти, чем есть: риск OOM при фактическом использовании")
        if mi.get("CommitLimit", 0) > 0 and "Committed_AS" in mi:
            # CommitLimit — граница выделения при vm.overcommit_memory=2; режим в BBBP не виден, поэтому WARN/CRIT —
            # только при косвенном признаке режима 2: CommitLimit отличается от значения по умолчанию
            # ((MemTotal − hugetlb) × 50 % + swap, т. е. изменены vm.overcommit_ratio / overcommit_kbytes)
            cl, cas = mi["CommitLimit"], mi["Committed_AS"]
            ratio = cas / cl
            w, c = _thr(thr, "COMMIT_LIMIT")
            if ratio >= w:
                hugetlb = mi["Hugetlb"] if "Hugetlb" in mi else mi.get("HugePages_Total", 0) * mi.get("Hugepagesize", 0)
                memtotal = mi.get("MemTotal", 0)
                default_cl = (memtotal - hugetlb) * 0.5 + mi.get("SwapTotal", 0)
                changed = memtotal > 0 and abs(cl - default_cl) > 0.02 * memtotal
                # при vm.overcommit_memory=2 ядро не даёт Committed_AS превысить CommitLimit: заметное превышение — режим
                # 0/1 (лимит не действует) или лимит уменьшен после выделений; признаком режима 2 оно не служит
                over = ratio > 1.01
                add(_sev(ratio, w, c) if changed and not over else "INFO", "COMMIT_LIMIT", "Committed_AS / CommitLimit",
                    ratio, f"≥ {w}",
                    f"отношение {ratio:.3f}: Committed_AS {fmt_bytes_kb(cas)}, CommitLimit {fmt_bytes_kb(cl)}, "
                    f"запас {fmt_bytes_kb(cl - cas)}; "
                    + ("Committed_AS выше CommitLimit — при vm.overcommit_memory=2 это возможно только после уменьшения "
                       "лимита (swapoff, изменение sysctl, резерв hugepages); вероятнее режим 0/1, где CommitLimit не "
                       "ограничивает выделение; " if over else
                       f"CommitLimit отличается от значения по умолчанию {fmt_bytes_kb(default_cl)} (изменены vm.overcommit_ratio/"
                       f"overcommit_kbytes — признак режима vm.overcommit_memory=2); " if changed else "")
                    + "значение на момент старта nmon",
                    "при vm.overcommit_memory=2 выделение сверх CommitLimit завершается ENOMEM (unable to create native thread, "
                    "ошибка выделения off-heap); при 0/1 — информативно; проверьте sysctl vm.overcommit_memory")
    # --- составные сигнатуры (Ignite); дисковые — без первых снимков файлов (hx) ---
    blk = hx.col("PROC", "Blocked")
    wtc = hx.col("CPU_ALL", "Wait%")
    dbmax, dwho = hx.disk_max_busy()
    if blk is not None and wtc is not None and dbmax is not None:
        hits = [i for i in range(hx.n()) if blk[i] == blk[i] and wtc[i] == wtc[i] and dbmax[i] == dbmax[i]
                and blk[i] >= 5 and wtc[i] >= 5 and dbmax[i] >= 90]
        if hits:
            w, c = _thr(thr, "IO_STALL")
            add(_sev(len(hits), w, c), "IO_STALL", "снимков с сигнатурой I/O-stall", len(hits), f"≥ {w}",
                f"первый @ {ts(hx.times[hits[0]])} (диск {dwho[hits[0]]}), всего {len(hits)} из {hx.n()}; "
                f"пример: Blocked {blk[hits[0]]:.0f}, iowait {wtc[hits[0]]:.1f}%, busy {dbmax[hits[0]]:.0f}%",
                "потоки стоят в D-state на переполненном диске: checkpoint/WAL fsync/снапшот; сопоставьте с логами Ignite "
                "(Checkpoint started/finished, throttling, long fsync)", time=hx.times[hits[0]])
    if hx.has("DISKBUSY"):
        best_dev, best_w = None, -1.0
        for d in hx.physical_disks():
            b = hx.col("DISKBUSY", d)
            bs = hx.col("DISKBSIZE", d)
            wr_ = hx.col("DISKWRITE", d)
            if b is None or not clean(b):
                continue
            if wr_ is not None and fmean(wr_) > best_w:
                best_dev, best_w = d, fmean(wr_)
            w, c = _thr(thr, "DISK_SMALL_IO")
            iosz = _io_size(hx.col("DISKREAD", d), wr_, hx.col("DISKXFER", d))
            if iosz != iosz and bs is not None:
                iosz = fmean(bs)
            if percentile(b, 95) >= w and iosz == iosz and iosz <= 16:
                add("INFO", "DISK_SMALL_IO", f"{d}: busy p95 при мелких операциях", percentile(b, 95), f"≥ {w}",
                    f"средний IO {iosz:.1f} KB (Σ(read+write)/Σ IOPS), IOPS avg {fmean(hx.col('DISKXFER', d)):.0f}",
                    "профиль мелких синхронных записей (WAL fsync / случайные страницы checkpoint): латентность важнее пропускной способности")
        if best_dev:
            wr_ = hx.col("DISKWRITE", best_dev)
            pr = periodicity(wr_, hx.times, step)
            if pr["regular"]:
                per = pr["period"]
                if 135 <= per <= 225:
                    hint = "совпадает с checkpointFrequency Ignite по умолчанию (180 с) — сверьте с логами Checkpoint started/finished"
                else:
                    hint = ("период отличается от 180 с по умолчанию: сверьте с настройкой checkpointFrequency либо с другими "
                            "периодическими задачами (снапшоты, архивирование WAL, бэкап, ротация логов)")
                tol = max(0.25 * per, step)
                add("INFO", "CHECKPOINT_PERIOD", f"{best_dev}: период регулярных всплесков записи, с", per, None,
                    f"{fmt_dur(per)} между пиками, {pr['npeaks']} пиков ≥ p90, {100 * pr['share_within']:.0f}% интервалов "
                    f"в пределах ±{tol:.0f} с; write max {fmax(wr_):.0f} KB/s", hint)
    if any(host.top):
        thp_procs = defaultdict(list)
        for procs in host.top:
            for p in procs:
                if re.match(r"^(khugepaged|kcompactd)", p.cmd):
                    thp_procs[p.cmd].append(p.cpu)
        if thp_procs:
            add("INFO", "THP_COMPACTION", "khugepaged/kcompactd в TOP", sum(len(v) for v in thp_procs.values()), None,
                "; ".join(f"{k}: {len(v)} снимков, CPU max {fmax(v):.1f}%" for k, v in thp_procs.items()),
                "ядро занимается компактацией/THP: возможны задержки аллокаций и всплески sys%; рассмотрите THP=madvise/never")
    return F


def _filter_sev(F, args):
    if not _opt(args, "show_info", True):
        F = [f for f in F if f.severity != "INFO"]
    min_sev = _opt(args, "min_severity", None)
    if min_sev:
        lim = SEV_ORDER.get(min_sev.upper(), 9)
        F = [f for f in F if SEV_ORDER.get(f.severity, 9) <= lim]
    return F


def _worst(F):
    """Код возврата по замечаниям: 2 при CRIT, 1 при WARN, иначе 0."""
    sevs = {f.severity for f in F}
    return 2 if "CRIT" in sevs else (1 if "WARN" in sevs else 0)


def _filter_note(full, shown):
    """Примечание о скрытых фильтром --no-info/--min-severity замечаниях (None, если скрытых нет)."""
    if len(shown) == len(full):
        return None
    return (f"показано {len(shown)} из {len(full)} замечаний (--no-info/--min-severity); "
            f"итог и код возврата — по всем замечаниям")


def analyze_health(host, args=None):
    rep = Report("Проверка здоровья (правила и пороги)", host.name)
    thr = _opt(args, "thresholds", None)
    full = health_checks(host, thr, link_mbit=_opt(args, "link_mbit", None))
    rep.worst = _worst(full)  # код возврата — по всем замечаниям, фильтр severity влияет только на вывод
    F = _filter_sev(full, args)
    counts = defaultdict(int)
    for f in full:
        counts[f.severity] += 1
    rep.kv("Итог", [("CRIT", counts["CRIT"]), ("WARN", counts["WARN"]), ("INFO", counts["INFO"]),
                     ("период", f"{ts(host.start())} .. {ts(host.end())} ({fmt_dur(host.duration())}, {host.n()} снимков)")])
    rep.findings("Замечания", F, note="; ".join(x for x in ("пороги по умолчанию можно переопределить: --thr CODE=WARN[,CRIT]",
                                                           _filter_note(full, F)) if x))
    return rep


# Таймлайн report: стресс-метрики агрегируются по max, остальные (активность, память) — по mean
REPORT_TL_MAX = ("cpu.wait", "proc.runq", "proc.blocked", "disk.busy_max")


def analyze_report(host, args=None):
    """Полный обзор: ключевые показатели + замечания."""
    rep = Report("Сводный отчёт", host.name)
    step = host.step()
    ncpu = host.ncpus()
    # статистики рядов — без первого снимка каждого файла/запуска (T0001 охватывает ~1 с на старте nmon: ложные max);
    # период, число снимков и суммы «за период» (приращения VM) — по всем снимкам
    hx = host.without_first()
    kv = [("период", f"{ts(host.start())} .. {ts(host.end())} ({fmt_dur(host.duration())}, {host.n()} снимков, шаг {step:.0f}s)"),
          ("CPU / RAM", f"{ncpu} CPU, {fmt_mb(fmax(host.col('MEM', 'memtotal'))) if host.has('MEM') else '-'}"),
          ("OS", host.meta.get("OS", "-"))]
    t1_kept = hx.firsts_kept
    if t1_kept:
        # в выборке только T0001 (неполный интервал): статистики рядов не считаются — пустой ряд
        kv.append(("статистика рядов", f"недоступна: {MSG_T1_KEPT}"))
        hx = host.slice([False] * host.n())
    if host.mem_format_issue():
        kv.append(("память", host.mem_format_issue()))
    n_head = len(kv)
    busy = hx.cpu_busy()
    if busy is not None:
        wt = hx.col("CPU_ALL", "Wait%")
        st = hx.col("CPU_ALL", "Steal%")
        p0 = lambda v: fmt_num(v, 0)  # noqa: E731
        p1 = lambda v: fmt_num(v, 1)  # noqa: E731
        kv.append(("CPU busy avg / p95 / max", f"{p0(fmean(busy))}% / {p0(percentile(busy, 95))}% / {p0(fmax(busy))}% @ {ts(series_stats(busy, hx.times)['max_time'])}"))
        kv.append(("CPU user / sys / wait / steal avg", f"{p1(fmean(hx.col('CPU_ALL', 'User%')))}% / {p1(fmean(hx.col('CPU_ALL', 'Sys%')))}% / "
                                                       f"{p1(fmean(wt))}% / {fmt_num(fmean(st), 2)}%"))
        if hx.cpu_cores and hx.n():
            cm = _core_busy_max(hx)
            kv.append(("макс. ядро busy avg / max (без T0001)", f"{p0(fmean(cm))}% / {p0(fmax(cm))}%"))
    rq, bl = hx.col("PROC", "Runnable"), hx.col("PROC", "Blocked")
    if rq is not None:
        kv.append(("Runnable avg / max; Blocked avg / max", f"{fmt_num(fmean(rq), 1)} / {fmt_num(fmax(rq), 0)}; {fmt_num(fmean(bl), 1)} / {fmt_num(fmax(bl), 0)}"))
    if hx.has("MEM") and not host.mem_format_issue():
        av = hx.mem_avail()
        us = hx.mem_used()
        sw = hx.swap_used()
        kv.append(("память used avg / max", f"{fmt_mb(fmean(us))} / {fmt_mb(fmax(us))}"))
        # поправка avail вычислена в build() по опорному снимку файла BBBP и копируется срезами (hx, окно времени)
        avc = hx.mem_avail_calibrated()
        kv.append(("память avail (оценка MemAvailable) min", f"{fmt_mb(fmin(av))} @ {ts(series_stats(av, hx.times)['min_time'])}"
                   + (f" (с калибровкой по MemAvailable на старте: {fmt_mb(fmin(avc))})"
                      if avc and hx.mem_avail_offset() > 0 else "")))
        kv.append(("page cache без shmem avg (cached avg)", f"{fmt_mb(fmean(_page_cache(hx)))} ({fmt_mb(fmean(hx.col('MEM', 'cached')))})"))
        if sw is not None:
            kv.append(("swap used max", fmt_mb(fmax(sw))))
    for nm, lbl in (("vm.pswpout", "swap out (страниц за период)"), ("vm.pgmajfault", "major faults avg/s")):
        r = resolve_metric(hx if nm == "vm.pgmajfault" else host, nm)
        if r:
            kv.append((lbl, fmean(r[2]) if nm == "vm.pgmajfault" else fsum(r[2])))
    po = resolve_metric(hx, "vm.pageoutrun")
    if po:
        kv.append(("kswapd активен (pageoutrun > 0), снимков", f"{count_above(po[2], 0)} из {hx.n()}"))
    kver = host.kernel_version()
    for nm, lbl, since in (("vm.allocstall", "direct reclaim stalls за период", (4, 10)), ("vm.kswapd_steal", "kswapd_steal за период", (3, 4))):
        r = resolve_metric(host, nm)
        if r:
            v = fsum(r[2])
            if v == 0 and kver >= since:
                kv.append((lbl, f"n/a (ядро {kver[0]}.{kver[1]}: счётчик переименован в /proc/vmstat, nmon его не собирает)"))
            else:
                kv.append((lbl, v))
    if host.has("DISKBUSY"):
        rows = []
        dmap = {e["device"]: e for e in hx.device_map()}  # как в disk: без T0001 (hx)
        for d in hx.physical_disks():
            b = hx.col("DISKBUSY", d)
            if b is None:
                continue
            mnt = _disk_mount_label(dmap.get(d, {}))
            rows.append(f"{d}{' (' + mnt + ')' if mnt else ''}: busy avg {fmt_num(fmean(b), 0)}% p95 {fmt_num(percentile(b, 95), 0)}% max {fmt_num(fmax(b), 0)}%, "
                        f"w max {fmt_num(fmax(hx.col('DISKWRITE', d)) / 1024, 0)} MB/s, r max {fmt_num(fmax(hx.col('DISKREAD', d)) / 1024, 0)} MB/s")
        kv.append(("диски", "; ".join(rows)))
    if hx.has("NET"):
        rt, wtn = hx.net_total("read"), hx.net_total("write")
        if rt is not None:
            kv.append(("сеть rx avg / max; tx avg / max", f"{fmt_num(fmean(rt) / 1024)} / {fmt_num(fmax(rt) / 1024)} MB/s; "
                                                         f"{fmt_num(fmean(wtn) / 1024)} / {fmt_num(fmax(wtn) / 1024)} MB/s"))
    if host.has("JFSFILE"):
        fs = []
        dfrows = {r["mount"]: r for r in host.df()}
        for m in host.cols("JFSFILE"):
            a = host.col("JFSFILE", m)
            if a is not None and clean(a) and series_stats(a, host.times)["last"] >= 70 and not _pseudo_fs(host, m, dfrows):
                fs.append(f"{m} {series_stats(a, host.times)['last']:.0f}%")
        kv.append(("ФС ≥ 70%", ", ".join(fs) or "нет"))
    jp = host.java_procs() if any(host.top) else {}
    if jp:
        # строка на основной JVM (нет основных — до 3 вспомогательных с наибольшим CPU), остальные java — одной строкой;
        # исчезновение — по полному ряду (при окне: тот же PID после окна — не исчез)
        life = _java_life(host, jp)
        jbase, jtop_b, bjp, roles = life["base"], life["top_b"], life["jp"], life["roles"]
        new_of = {r[1]: r[3] for r in life["changes"]}
        cpu_sum = {pid: fsum([p.cpu for _, p in lst]) for pid, lst in jp.items()}
        shown = [pid for pid in jp if roles.get(pid, True)] or sorted(jp, key=lambda q: -cpu_sum[q])[:3]
        for pid, lst in jp.items():
            if pid not in shown:
                continue
            cpu = [p.cpu for _, p in lst]
            rss = clean([p.rss / 1024 for _, p in lst])
            thr_ = clean([p.threads for _, p in lst])
            thr_txt = (f"threads {fmt_num(thr_[0], 0)} → {fmt_num(thr_[-1], 0)} (max {fmt_num(fmax(thr_), 0)})"
                       if thr_ else "threads: нет колонки")
            rss_txt = f"RSS {fmt_mb(rss[0])} → {fmt_mb(rss[-1])} (max {fmt_mb(fmax(rss))})" if rss else "RSS -"
            last_b = bjp.get(pid, lst)[-1][0]
            tail = len(jtop_b) - bisect.bisect_right(jtop_b, last_b)
            gone = (f"; исчез из TOP после {ts(jbase.times[last_b])} ({tail} снимков TOP без него до конца данных"
                    + (f"; перезапуск — новый PID {new_of[pid]}" if pid in new_of else "") + ")") if tail else ""
            kv.append((f"java[{pid}]", f"CPU avg {fmt_num(fmean(cpu), 0)}% max {fmt_num(fmax(cpu), 0)}% (в % ядра); {rss_txt}; "
                                       f"{thr_txt}; виден в {len(lst)} снимках{gone}"))
        rest = [pid for pid in jp if pid not in shown]
        if rest:
            n_top_ = sum(1 for x in host.top if x)
            kv.append(("прочие java (вспомогательные: утилиты/клиенты)",
                       f"{len(rest)} PID, Σ %CPU / снимков с TOP {fmt_num(fsum([cpu_sum[q] for q in rest]) / max(1, n_top_), 2)}% "
                       f"— подробно: java"))
    if not any(host.top):
        kv.append(("процессы", "в выбранном окне нет снимков с данными TOP (TOP пишется начиная со второго снимка); "
                               "расширьте окно" if host.top_in_files() else "TOP отсутствует (nmon без -t)"))
    else:
        agg_ = defaultdict(list)
        for procs in host.top:
            per_cmd = defaultdict(float)
            for p in procs:
                if p.cpu == p.cpu:
                    per_cmd[cmd_group(p.cmd)] += p.cpu
            for c, v in per_cmd.items():
                agg_[c].append(v)
        n_top_ = sum(1 for x in host.top if x)
        top5 = sorted(agg_.items(), key=lambda kv_: -fsum(kv_[1]))[:6]
        # Σ/снимков — среднее за весь период (снимок без процесса = 0), как «cpu Σ/снимков%» в top/java
        kv.append(("процессы по суммарному CPU (все PID команды вместе)",
                   "; ".join(f"{c} Σ/снимков {fmt_num(fsum(v) / max(1, n_top_), 1)}% (avg когда виден {fmt_num(fmean(v), 0)}%, "
                             f"max {fmt_num(fmax(v), 0)}%, {len(v)} сн.)" for c, v in top5)))
    if t1_kept:  # из показателей по рядам остаются только уровни ФС и сведения о процессах
        kv = kv[:n_head] + [x for x in kv[n_head:] if x[0] in ("ФС ≥ 70%", "процессы")]
    rep.kv("Ключевые показатели", kv, note=MSG_T1_KEPT if t1_kept else
           "статистики рядов — без первого снимка каждого файла/запуска nmon (T0001: неполный "
           "интервал); период, число снимков и суммы «за период» — по всем снимкам")
    full = health_checks(host, _opt(args, "thresholds", None), link_mbit=_opt(args, "link_mbit", None))
    rep.worst = _worst(full)  # код возврата — по всем замечаниям, фильтр severity влияет только на вывод
    F = _filter_sev(full, args)
    rep.findings("Замечания (health)", F, note=_filter_note(full, F))
    # Краткий таймлайн с крупным шагом (ряды без T0001)
    if host.n() > 3 and not t1_kept:
        dur = host.duration()
        step_s = 300 if dur <= 3 * 3600 else (900 if dur <= 12 * 3600 else 3600)
        cols = ["cpu.busy", "cpu.wait", "proc.runq", "proc.blocked", "mem.avail_cal", "disk.busy_max", "disk.write", "disk.read", "net.read", "net.write", "top.java.cpu", "top.java.rss"]
        res = [(c, resolve_metric(hx, c)) for c in cols]
        res = [(c, r) for c, r in res if r]
        if res:
            tt = None
            agg = []
            for c, r in res:
                # стресс-метрики — max (пик в корзине не теряется); активность (CPU, диск, сеть, java) и память — mean:
                # max корзины скрыл бы провал активности (синхронная остановка записи/трафика — сигнатура блокировки)
                tt, vv = downsample(hx.times, r[2], step_s, "max" if c in REPORT_TL_MAX else "mean")
                agg.append(vv)
            rows = [[tt[k]] + [a[k] for a in agg] for k in range(len(tt))]
            labels = [f"{c} [{r[1]}]" if r[1] else c for c, r in res]
            rep.table(f"Таймлайн (шаг {fmt_dur(step_s)}; max для {', '.join(REPORT_TL_MAX)}; mean для остальных)",
                      ["время"] + labels, rows, prec={lab: 0 for lab in labels},
                      note="без первого снимка каждого файла (T0001: неполный интервал); mean — среднее снимков корзины "
                           "(провал активности виден, короткий пик сглажен — пики: timeline --agg max, events); "
                           "mem.avail_cal — avail с поправкой по MemAvailable на старте")
    return rep


# --------------------------------------------------------------------------
# Кластер: сравнение хостов, выбросы, синхронные события
# --------------------------------------------------------------------------

CLUSTER_METRICS = [
    ("cpu.busy", "mean"), ("cpu.busy", "p95"), ("cpu.wait", "mean"), ("cpu.steal", "max"), ("cpu.sys", "mean"),
    ("proc.runq", "p95"), ("proc.blocked", "p95"), ("mem.avail_cal", "min"), ("mem.swap_used", "max"),
    ("disk.busy_max", "p95"), ("disk.write", "max"), ("disk.read", "max"), ("disk.iops", "max"),
    ("net.read", "mean"), ("net.read", "max"), ("net.write", "mean"), ("net.write", "max"),
    ("top.java.cpu", "mean"), ("top.java.rss", "max"), ("top.java.threads", "max"), ("top.java.sys", "mean"),
]
# Минимальное абсолютное отличие от медианы кластера, чтобы выброс был значимым (в единицах метрики; ключ —
# имя метрики или префикс, берётся самый длинный совпавший): п.п. для процентов, MB, KB/s или /s, потоки
CLUSTER_ABS_MIN = {"cpu.": 2.0, "proc.": 1.0, "mem.": 100.0, "disk.": 1000.0, "disk.busy_max": 2.0, "net.": 1000.0,
                   "top.java.cpu": 50.0, "top.java.sys": 50.0, "top.java.rss": 1000.0, "top.java.threads": 20.0}
# ... и для CRIT (вдобавок к отличию ≥ 50 % медианы): при медиане около 0 и MAD = 0 любое значимое отклонение дало бы
# огромный z (steal 2.5 % на одном хосте из 8 — z > 6), поэтому CRIT — только при существенном абсолютном отличии
CLUSTER_CRIT_ABS_MIN = {"cpu.": 5.0, "proc.": 5.0, "mem.": 1024.0, "disk.": 10000.0, "disk.busy_max": 10.0, "net.": 10000.0,
                        "top.java.cpu": 200.0, "top.java.sys": 200.0, "top.java.rss": 4096.0, "top.java.threads": 100.0}
# Выбросы среди хостов: хост с меньшим числом снимков (без T0001) в сравнении не участвует — агрегаты по нескольким
# снимкам несопоставимы с агрегатами за период (то же число — минимум снимков хоста в общем окне)
CLUSTER_OUTLIER_MIN_SNAPS = 10
# CLUSTER_SYNC: медиана по хостам max(значение/фон) (↑) или min (↓) — замечание WARN только при ×≥ 1.25 / ×≤ 0.8
# (синхронные колебания на несколько процентов у ровного ряда — шум), CRIT — при ×≥ 2 / ×≤ 0.5; фон около 0 — условие
# выполнено
CLUSTER_SYNC_RATIO = {"WARN": (1.25, 0.8), "CRIT": (2.0, 0.5)}
# CLUSTER_SYNC, классы компонентов эпизода. Нагрузочные метрики: рост — синхронная распределённая нагрузка, INFO (WARN —
# при стрессе выше WARN health у ≥ половины участников или вместе с провалом активности; CRIT по одной доле хостов не
# выдаётся); провал активности — WARN при доле ≥ CRIT-порога CLUSTER_SYNC, ×≤ 0.5 и ≥ 2 интервалах, CRIT — если ещё
# ×≤ 0.2, ≥ 5 интервалов или стресс. Стресс-метрики (рост) — замечание только при пике выше WARN правила health
CLUSTER_LOAD = ("cpu.busy", "disk.read", "disk.write", "net.read", "net.write", "top.java.cpu")
CLUSTER_STRESS = ("cpu.wait", "proc.blocked", "disk.busy_max", "proc.runq")
CLUSTER_DOWN_RATIO = {"WARN": 0.5, "CRIT": 0.2}
CLUSTER_DOWN_RUN = {"WARN": 2, "CRIT": 5}  # длительность провала, интервалов nmon
CLUSTER_SYNC_WINDOW = 15     # окно фона выбросов (снимков), как в events
CLUSTER_SYNC_MERGE = 1.5     # компоненты с началом в пределах 1.5 интервала — одно событие, одно замечание
CLUSTER_PME_GB = 1.0         # избыток трафика эпизода ≥ 1 GB — не сообщения PME (мегабайты)
CLUSTER_BALANCE = 0.2        # Σ избытка rx < 0.2 Σ избытка tx (или наоборот) — трафик уходит за пределы набора / приходит извне


# CLUSTER_OUTLIER у метрик с правилом health: (правило, плохая сторона, перевод значения в единицы порога: cpu — × число
# CPU, blocked — действующий WARN BLOCKED_HIGH, ram — % от RAM); WARN/CRIT — только если выброс на плохой стороне и
# достигает CLUSTER_OUTLIER_HEALTH_SHARE WARN-порога правила (для «чем меньше, тем хуже» — порог / доля), иначе INFO
CLUSTER_OUTLIER_HEALTH = {"cpu.busy": ("CPU_SATURATION", "up", ""), "cpu.wait": ("CPU_WAIT", "up", ""),
                          "cpu.steal": ("CPU_STEAL", "up", ""), "proc.runq": ("RUNQ_HIGH", "up", "cpu"),
                          "proc.blocked": ("BLOCKED_HIGH", "up", "blocked"), "mem.avail_cal": ("MEM_AVAIL_LOW", "down", "ram"),
                          "mem.swap_used": ("SWAP_USED", "up", "ram"), "disk.busy_max": ("DISK_BUSY", "up", ""),
                          "top.java.rss": ("JAVA_RSS", "up", "ram"), "top.java.threads": ("JAVA_THREADS", "up", "")}
CLUSTER_OUTLIER_HEALTH_SHARE = 0.5


def _outlier_health(h, key, v, med, thr):
    """Выброс метрики с правилом health (CLUSTER_OUTLIER_HEALTH): (значим ли — на плохой стороне и ≥ доли WARN-порога,
    пояснение для INFO) или None, если правила нет или перевести значение нельзя (нет числа CPU / RAM)."""
    spec = CLUSTER_OUTLIER_HEALTH.get(key.split(":")[0])
    if spec is None:
        return None
    rule, side, conv = spec
    lim_w = _thr(thr, rule)[0]
    x, unit = v, ""
    if conv == "cpu":
        n = h.ncpus()
        if not n:
            return None
        lim_w *= n
    elif conv == "blocked":
        lim_w = blocked_levels(thr, h.ncpus())[0]
    elif conv == "ram":
        total = fmax(h.col("MEM", "memtotal")) if h.has("MEM") else NAN
        if not (total == total and total > 0):
            return None
        x, unit = 100.0 * v / total, "% RAM"
    bad = v > med if side == "up" else v < med
    lim = lim_w * CLUSTER_OUTLIER_HEALTH_SHARE if side == "up" else lim_w / CLUSTER_OUTLIER_HEALTH_SHARE
    if not bad:
        return False, "в благоприятную сторону — неоднородность нагрузки"
    if (x >= lim) if side == "up" else (x <= lim):
        return True, ""
    return False, (f"{fmt_num(x, 1)}{unit} {'<' if side == 'up' else '>'} {fmt_num(lim, 1)}{unit} "
                   f"({CLUSTER_OUTLIER_HEALTH_SHARE:.0%} WARN {rule}) — неоднородность в пределах здоровых уровней")


def _outlier_groups(cand, med, n):
    """CLUSTER_OUTLIER: отклонившиеся хосты — группа узлов (разная нагрузка/роль), а не выбросы: их ≥ max(2, 25 %
    хостов), все по одну сторону от медианы и близки друг к другу (разброс меньше половины их расстояния до медианы)."""
    if len(cand) < max(2, math.ceil(0.25 * n)):
        return False
    devs = [v - med for _h, v, _z in cand]
    if not (all(d > 0 for d in devs) or all(d < 0 for d in devs)):
        return False
    vs = [v for _h, v, _z in cand]
    return max(vs) - min(vs) < 0.5 * min(abs(d) for d in devs)


def _cluster_abs_min(metric, table=None):
    """Минимальное абсолютное отличие от медианы для CLUSTER_OUTLIER (table: CLUSTER_ABS_MIN по умолчанию или
    CLUSTER_CRIT_ABS_MIN; самый длинный префикс)."""
    table = CLUSTER_ABS_MIN if table is None else table
    keys = [k for k in table if metric == k or (k.endswith(".") and metric.startswith(k))]
    return table[max(keys, key=len)] if keys else 0.0


def _sync_moved(ser, t0, up, z_thr, bucket, window=15):
    """CLUSTER_SYNC, «первый хост»: отклонился ли хост в ту же сторону уже в снимке, ближайшем к t0 (не дальше
    0.5·bucket), хотя бы на половину порогов выброса: |z| ≥ z_thr/2 и отклонение ≥ ½ max(min_abs, rel_floor·|фон|).
    ser — (времена, значения, min_abs, rel_floor) ряда хоста, по которому искались выбросы."""
    times, arr, ma, rf = ser
    j = bisect.bisect_left(times, t0)
    near = [k for k in (j - 1, j) if 0 <= k < len(times)]
    if not near:
        return False
    j = min(near, key=lambda k: abs((times[k] - t0).total_seconds()))
    if abs((times[j] - t0).total_seconds()) > 0.5 * bucket or arr[j] != arr[j]:
        return False
    b = rolling_base(arr, j, window)
    if b is None:
        return False
    med, scale = b
    dev = arr[j] - med
    if dev == 0 or (dev > 0) != up:
        return False
    z = dev / scale if scale > 0 else math.inf
    return abs(z) >= z_thr / 2 and abs(dev) >= 0.5 * max(ma or 0.0, (rf or 0.0) * abs(med))


def fmedian_dt(times):
    """Медиана моментов времени (для чётного числа — середина двух средних); None, если пусто."""
    t = sorted(x for x in times if x is not None)
    if not t:
        return None
    m = len(t) // 2
    return t[m] if len(t) % 2 else t[m - 1] + (t[m] - t[m - 1]) / 2


def _agg(arr, how):
    if arr is None:
        return NAN
    if how == "mean":
        return fmean(arr)
    if how == "max":
        return fmax(arr)
    if how == "min":
        return fmin(arr)
    if how == "p95":
        return percentile(arr, 95)
    if how == "last":
        c = clean(arr)
        return c[-1] if c else NAN
    return NAN


def _sync_episodes(sp, det_times, bucket, min_hosts, share_min):
    """Эпизоды синхронных выбросов одной метрики и одного направления; sp — [(время, хост, значение, фон)] всех хостов.
    От каждого выброса берётся окно [t, t + 1.5·bucket) — оно поглощает разницу фаз снимков хостов; окна с наибольшим
    числом хостов отбираются жадно, без перекрытий. Окно проходит, если хостов в нём ≥ min_hosts и их доля среди
    хостов со значениями метрики в [t − bucket, t + 2.5·bucket] (det_times: хост -> времена) ≥ share_min %. Прошедшие окна с
    промежутком ≤ bucket объединяются в эпизод; доля эпизода — максимум по окнам, а не объединение хостов за эпизод
    (цепочка случайных одиночных выбросов на большом кластере не накапливается).
    Возвращает [{start, end, k, present, share, spikes}] по возрастанию времени."""
    from bisect import bisect_left, bisect_right
    sp = sorted(sp, key=lambda s: s[0])
    tt = [s[0] for s in sp]
    tol = timedelta(seconds=1.5 * bucket)
    cands = []
    for i, t in enumerate(tt):
        j = bisect_left(tt, t + tol, lo=i)
        hs = {s[1] for s in sp[i:j]}
        if len(hs) >= min_hosts:
            cands.append((t, i, j, len(hs)))
    cands.sort(key=lambda x: (-x[3], x[0]))
    chosen = []
    for cd in cands:
        if all(abs(cd[0] - o[0]) >= tol for o in chosen):
            chosen.append(cd)
    episodes = []
    for t, i, j, k in sorted(chosen):
        lo, hi = t - timedelta(seconds=bucket), t + timedelta(seconds=2.5 * bucket)
        present = max(k, sum(1 for times in det_times.values() if bisect_right(times, hi) > bisect_left(times, lo)))
        share = 100.0 * k / present
        if share < share_min:
            continue
        e = episodes[-1] if episodes else None
        if e and (t - e["win_end"]).total_seconds() <= bucket:
            e["spikes"].extend(sp[i:j])
            e["end"] = max(e["end"], tt[j - 1])
            e["win_end"] = t + tol
            if (share, k) > (e["share"], e["k"]):
                e.update(share=share, k=k, present=present)
        else:
            episodes.append({"start": t, "end": tt[j - 1], "win_end": t + tol, "k": k, "present": present,
                             "share": share, "spikes": list(sp[i:j])})
    return episodes


def analyze_cluster(hosts, args=None):
    rep = Report(f"Кластер: сравнение {len(hosts)} хостов")
    thr = _opt(args, "thresholds", None)
    # Ряды без первого снимка каждого файла/запуска (T0001 охватывает ~1 с на старте nmon: скорости за этот
    # отрезок несопоставимы с интервальными средними и дают ложные max) — для метрик, выбросов и таймлайна;
    # покрытие, окна, разрывы и CLUSTER_COVERAGE — по исходным снимкам
    hx = [h.without_first() for h in hosts]
    # Покрытие
    cov = []
    for h in hosts:
        cov.append([h.name, h.start(), h.end(), h.duration(), h.n(), h.ncpus(),
                    fmax(h.col("MEM", "memtotal")) if h.has("MEM") else NAN, len(h.gaps()), len(h.files)])
    rep.table("Покрытие данными", ["host", "начало", "конец", "длительность", "снимков", "CPU", "RAM", "разрывов", "файлов"], cov,
              prec={"длительность": "dur", "RAM": "mb"})
    starts = [h.start() for h in hosts if h.start()]
    ends = [h.end() for h in hosts if h.end()]
    if starts and ends:
        cs, ce = max(starts), min(ends)
        rep.kv("Окна", [("объединённое окно", f"{ts(min(starts))} .. {ts(max(ends))}"),
                        ("общее окно (есть у всех хостов)", f"{ts(cs)} .. {ts(ce)}" if ce > cs else "нет (периоды не пересекаются)")])
        # Полоса покрытия: 60 корзин, '#' = есть снимки, '.' = нет
        span = (max(ends) - min(starts)).total_seconds()
        if span > 0 and len(hosts) > 1:
            step_min = fmedian([h.step() for h in hosts]) or 60.0
            nb = max(5, min(60, int(span // (2 * step_min))))  # корзина ≥ 2 интервалов, иначе ложные «дыры»
            bw = span / nb
            width = max(len(h.name) for h in hosts)
            lines = [f"{'host'.ljust(width)}  {ts(min(starts))} … {ts(max(ends))} (корзина {fmt_dur(bw)})"]
            for h in hosts:
                flags = [False] * nb
                for t in h.times:
                    k = min(nb - 1, int((t - min(starts)).total_seconds() // bw))
                    flags[k] = True
                lines.append(f"{h.name.ljust(width)}  " + "".join("#" if f else "." for f in flags))
            rep.text("Полоса покрытия по времени", "\n".join(lines))
    # Дрейф конфигурации
    drift = []
    for label, fn in (("CPU", lambda h: h.ncpus()), ("RAM", lambda h: fmt_mb(fmax(h.col("MEM", "memtotal"))) if h.has("MEM") else "-"),
                      ("kernel", lambda h: h.meta.get("OS", "-")), ("nmon", lambda h: h.meta.get("version", "-")),
                      ("interval", lambda h: h.interval),
                      ("MTU(bond/nic)", lambda h: ",".join(sorted({str(i['mtu']) for i in h.ifconfig() if not _is_loopback(i['name'], i['flags']) and 'RUNNING' in i['flags'] and i['mtu'] == i['mtu']}))),
                      ("swap", lambda h: fmt_mb(fmax(h.col("MEM", "swaptotal"))) if h.has("MEM") else "-"),
                      ("THP (AnonHugePages на старте)", lambda h: ("используется" if h.meminfo().get("AnonHugePages", 0) > 0
                                                                   else "не используется (AnonHugePages = 0)") if h.meminfo() else "-"),
                      ("JVM flags (UARG)", lambda h: next((" ".join(sorted(re.findall(r"-X\S+", full)))
                                                            for _pid, (prog, full, _t) in h.uarg_cmdlines().items() if prog == "java"), "-")),
                      ("CPU model", lambda h: h.lscpu().get("Model name", "-"))):
        vals = defaultdict(list)
        for h in hosts:
            vals[str(fn(h))].append(h.name)
        if len(vals) > 1:
            drift.append([label, len(vals), "; ".join(f"{k}: {len(v)} ({', '.join(v[:3])}{'…' if len(v) > 3 else ''})" for k, v in vals.items())])
    if drift:
        rep.table("Различия конфигурации между хостами", ["параметр", "вариантов", "значения (хостов)"], drift)
    # Сводная таблица метрик
    cols = [f"{m}:{a}" for m, a in CLUSTER_METRICS]
    matrix = {}
    rows = []
    unit_of = {}
    # хосты, у которых в выборке только первые снимки файлов (T0001: исключить нечего, without_first вернул их же) —
    # значения за неполный интервал (скорости диска/сети за 1–2 с старта, чтения BBBP): в таблицу и таймлайн не идут
    t1only = [h.name for h, x in zip(hosts, hx) if x.firsts_kept]
    for h, x in zip(hosts, hx):
        row = [h.name]
        for m, a in CLUSTER_METRICS:
            r = resolve_metric(x, m) if not x.firsts_kept else None
            v = _agg(r[2], a) if r else NAN
            if r and r[1]:
                unit_of[f"{m}:{a}"] = r[1]
            row.append(v)
            matrix.setdefault(f"{m}:{a}", []).append(v)
        rows.append(row)
    # Выбросы — в общем окне всех хостов (по рядам без T0001): иначе max/min хоста, начавшего запись раньше,
    # приходились бы на время, когда у остальных данных нет. Хосты с < CLUSTER_OUTLIER_MIN_SNAPS снимков в сравнении не
    # участвуют (NaN). Окно берётся, если у каждого из остальных в нём не меньше max(10, 10 % его снимков); все
    # агрегаты считаются в нём
    usable = [x.n() >= CLUSTER_OUTLIER_MIN_SNAPS for x in hx]
    ux = [x for x, ok in zip(hx, usable) if ok]
    out_matrix = {key: [v if ok else NAN for v, ok in zip(vals, usable)] for key, vals in matrix.items()}
    common = None
    if len(ux) >= 4 and max(x.start() for x in ux) < min(x.end() for x in ux):
        cs, ce = max(x.start() for x in ux), min(x.end() for x in ux)
        masks = [[cs <= t <= ce for t in x.times] if ok else None for x, ok in zip(hx, usable)]
        if all(sum(mk) >= max(CLUSTER_OUTLIER_MIN_SNAPS, 0.1 * x.n()) for mk, x in zip(masks, hx) if mk is not None):
            common = (cs, ce)
            if not all(all(mk) for mk in masks if mk is not None):
                out_matrix = {}
                for x, mk in zip(hx, masks):
                    xc = x.slice(mk) if mk is not None else None
                    for m, a in CLUSTER_METRICS:
                        r = resolve_metric(xc, m) if xc is not None else None
                        out_matrix.setdefault(f"{m}:{a}", []).append(_agg(r[2], a) if r else NAN)
    few = [h.name for h, ok in zip(hosts, usable) if not ok]
    out_note = ((f"в общем окне по рядам без первых снимков файлов (T0001) {ts(common[0])} .. {ts(common[1])}" if common else
                 "по полному периоду каждого хоста: общего окна нет или оно слишком короткое — периоды несопоставимы: "
                 "max/min не сравниваются, замечания не выше WARN")
                + (f"; хосты с < {CLUSTER_OUTLIER_MIN_SNAPS} снимков (без T0001) не сравниваются: {', '.join(few)}" if few else ""))
    sortkey = _opt(args, "sort", None)
    if sortkey:
        if sortkey not in cols:
            raise SystemExit(f"ERROR: --sort: неизвестная колонка {sortkey!r}; доступны: {', '.join(cols)}")
        k = cols.index(sortkey) + 1
        rows.sort(key=lambda r: -(r[k] if r[k] == r[k] else -1e18))
    labels = [f"{c} [{unit_of[c]}]" if c in unit_of else c for c in cols]
    rep.table("Метрики по хостам", ["host"] + labels, rows,
              prec={lab: 0 for lab, c in zip(labels, cols) if c.split(":")[0].startswith(("disk.", "net.", "mem.", "top.java.rss", "top.java.threads", "proc."))},
              note="mean/p95/max/min — по всему периоду каждого хоста (в пределах --from/--to, если заданы), без первого "
                   "снимка каждого файла (T0001: неполный интервал)"
                   + (f"; нет значений у хостов, где в выборке только первые снимки файлов ({', '.join(t1only)}): "
                      f"{MSG_T1_KEPT}" if t1only else "")
                   + (f"; выбросы — {out_note}" if len(ux) >= 4 else "")
                   + "; mem.avail_cal — avail с поправкой по MemAvailable на старте; сортировка: --sort <метрика:агрегат>, "
                     "например cpu.busy:p95 или net.write:mean (объём трафика; :max — пик)")
    F = []
    out_rows = []
    w, c = _thr(thr, "CLUSTER_OUTLIER")
    groups = []
    if len(ux) >= 4:
        per_host = defaultdict(list)  # хост -> выбросы его метрик (одно замечание на хост)
        for key, vals in out_matrix.items():
            if common is None and key.endswith((":max", ":min")):
                continue  # несопоставимые периоды: пик одного хоста мог прийтись на время, когда у других данных нет
            zs = robust_z(vals)
            med = fmedian(vals)
            amin = _cluster_abs_min(key.split(":")[0])
            cmin = _cluster_abs_min(key.split(":")[0], CLUSTER_CRIT_ABS_MIN)
            cand = []
            for h, v, z in zip(hosts, vals, zs):
                if z != z or v != v or abs(z) < w:
                    continue
                # значимость: отличие от медианы не меньше 10% и не меньше минимального абсолютного (CLUSTER_ABS_MIN)
                if abs(v - med) < max(0.10 * abs(med), amin):
                    continue
                cand.append((h, v, z))
            if not cand:
                continue
            if _outlier_groups(cand, med, len(ux)):
                # не выбросы, а две группы узлов (например, разные роли/нагрузка)
                groups.append([key, len(cand), len(ux), med, sorted(h.name for h, _, _ in cand)])
                continue
            for h, v, z in cand:
                dev = v - med
                pct = 100.0 * dev / abs(med) if med else NAN
                # CRIT — только при большом отличии: ≥ 50% медианы (крупный |z| при отличии на 10–30% бывает и у
                # однородного кластера — масштаб по 4–8 почти равным значениям мал) и ≥ CLUSTER_CRIT_ABS_MIN (при
                # медиане около 0); без общего окна периоды несопоставимы — не выше WARN
                sev = "CRIT" if (common is not None and abs(z) >= c and abs(dev) >= max(0.5 * abs(med), cmin)) else "WARN"
                # у метрики есть правило health: выброс в благоприятную сторону или далеко от его WARN-порога —
                # неоднородность нагрузки в пределах здоровых уровней (INFO)
                hl = _outlier_health(h, key, v, med, thr)
                if hl is not None and not hl[0]:
                    sev = "INFO"
                out_rows.append([h.name, key, v, med, pct, z, sev])
                per_host[h.name].append({"key": key, "v": v, "med": med, "pct": pct, "z": z, "sev": sev, "dev": dev,
                                         "note": hl[1] if hl is not None else "", "p": 0 if abs(med) >= 1000 else 1})
        for hn in sorted(per_host):
            lst = sorted(per_host[hn], key=lambda d: (SEV_ORDER.get(d["sev"], 9), -abs(d["z"])))
            top = lst[0]

            def one(d):
                diff = f"на {abs(d['pct']):.0f} %" if d["pct"] == d["pct"] else f"на {fmt_num(abs(d['dev']), d['p'])} (медиана 0)"
                return (f"{d['key']} = {fmt_num(d['v'], d['p'])} {'выше' if d['dev'] > 0 else 'ниже'} медианы кластера "
                        f"({fmt_num(d['med'], d['p'])}) {diff}, z={d['z']:.1f} [{d['sev']}" + (f": {d['note']}" if d["note"] else "")
                        + "]")

            if all(d["sev"] == "INFO" for d in lst):
                hint = ("неоднородность нагрузки в пределах здоровых уровней: узел нагружен иначе остальных (распределение "
                        "партиций, клиентов, роль) — к сведению")
            elif any(d["key"].startswith("net.") and d["dev"] < 0 and d["sev"] != "INFO" for d in lst):
                hint = "узел обменивается меньше остальных: распределение партиций/baseline/клиентская нагрузка"
            else:
                hint = "узел отличается от остальных: смотрите его подробно (report/at)"
            F.append(Finding(top["sev"], "CLUSTER_OUTLIER", hn, top["key"], top["v"], f"|z| ≥ {w}",
                             (f"выбросов метрик: {len(lst)}; " if len(lst) > 1 else "") + "; ".join(one(d) for d in lst)
                             + f"; агрегаты {out_note}", hint,
                             extra={"components": [{"metric": d["key"], "value": d["v"], "median": d["med"], "pct": d["pct"],
                                                    "z": d["z"], "severity": d["sev"]} for d in lst]}))
        out_rows.sort(key=lambda r: -abs(r[5]))
        rep.table("Выбросы среди хостов (робастный z по медиане/MAD, отличие ≥ 10% и ≥ минимального абсолютного)",
                  ["host", "метрика", "значение", "медиана кластера", "отличие %", "z", "уровень"],
                  out_rows[:40], total=len(out_rows), prec={"значение": 1, "медиана кластера": 1, "отличие %": 0, "z": 1},
                  note=f"агрегаты {out_note}; WARN — |z| ≥ {w}, CRIT — |z| ≥ {c}, отличие ≥ 50% медианы и не меньше "
                       f"минимального для CRIT (cpu.* — {CLUSTER_CRIT_ABS_MIN['cpu.']:g} п.п., proc.* — "
                       f"{CLUSTER_CRIT_ABS_MIN['proc.']:g}, mem.* — {CLUSTER_CRIT_ABS_MIN['mem.']:g} MB, disk.*/net.* — "
                       f"{CLUSTER_CRIT_ABS_MIN['disk.']:g}; раздел 4 руководства); у метрик с правилом health ("
                       + ", ".join(f"{m} — {r}" for m, (r, _s, _c) in CLUSTER_OUTLIER_HEALTH.items())
                       + f") — INFO, если выброс в благоприятную сторону или не достигает "
                         f"{CLUSTER_OUTLIER_HEALTH_SHARE:.0%} WARN-порога правила (неоднородность в пределах здоровых "
                         f"уровней); замечание CLUSTER_OUTLIER — одно на хост, со всеми его выбросами")
        if groups:
            rep.table("Метрики, по которым узлы делятся на группы (≥ max(2, 25 %) хостов отклоняются в одну сторону и близки "
                      "друг к другу — не выброс, а разная нагрузка/роль)",
                      ["метрика", "хостов отклоняется", "всего", "медиана", "хосты"], groups, prec={"медиана": 1, "хосты": "list"},
                      note="группа — если разброс значений отклонившихся хостов меньше половины их расстояния до медианы; "
                           "иначе каждый — отдельный выброс")
    elif len(hosts) >= 4:
        rep.text("Выбросы среди хостов", f"меньше 4 хостов с ≥ {CLUSTER_OUTLIER_MIN_SNAPS} снимками (без первых снимков "
                                         f"файлов) — периоды хостов слишком короткие, сравнение хостов не выполняется"
                                         + (f" (мало снимков: {', '.join(few)})" if few else ""))
    else:
        rep.text("Выбросы среди хостов", "меньше 4 хостов — статистика выбросов не считается")
    # Синхронные эпизоды: всплески/плато ↑ и провалы ↓ у нескольких хостов в пределах ~интервала nmon;
    # bucket — медианный интервал nmon хостов (окно совпадения, порог «первого» и длительность — от него)
    bucket = fmedian([h.step() for h in hosts]) or 60.0
    win = CLUSTER_SYNC_WINDOW
    metrics = _opt(args, "metrics", None) or ["cpu.busy", "cpu.wait", "proc.blocked", "disk.busy_max", "disk.write", "disk.read", "net.read", "net.write", "top.java.cpu"]
    zv = _opt(args, "z", None)
    z_thr = 4.0 if zv is None else float(zv)
    link_mbit = _opt(args, "link_mbit", None)
    # о неизвестных/отсутствующих метриках предупреждаем, только если их задали явно (набор по умолчанию может
    # быть неполным в старых nmon или урезанных файлах), как в events
    unknown = {m for m in metrics if all(resolve_metric(h, m) is None for h in hosts)} if _opt(args, "metrics", None) else set()
    for m in sorted(unknown):
        warn(f"cluster: метрика {m!r} неизвестна или отсутствует у всех хостов (список: команда metrics)")
    spikes = defaultdict(list)  # (метрика, '↑'|'↓') -> [(время, хост, значение, фон)]
    det_times = defaultdict(dict)  # метрика -> хост -> времена снимков со значением метрики (знаменатель доли)
    det_ser = {}  # (метрика, хост) -> (времена, значения, min_abs, rel_floor) — для проверки «первого хоста»
    part = {}  # (метрика, хост) -> (времена, значения, индексы выбросов/плато (не фон), длительности снимков, min_abs, ед.)
    full_of = {}  # хост -> ряд без T0001 по всему периоду (фон не обрезается окном --from/--to)
    n_det = 0
    for h, x in zip(hosts, hx):
        # фон — по полному ряду хоста без T0001, а не только по окну --from/--to/--around (при узком окне вокруг
        # инцидента медиана окна загрязнена самим инцидентом); в результат идут выбросы внутри окна
        bx = x if h.unfiltered is None else h.unfiltered.without_first()
        n_det = max(n_det, bx.n())
        if not h.times:
            continue
        full_of[h.name] = bx
        dts = _snap_dt(bx)
        pos = {t: k for k, t in enumerate(bx.times)}
        mins = event_min_abs(bx)
        for m in metrics:
            r = resolve_metric(bx, m)
            if not r:
                continue
            arr = r[2]
            det_times[m][h.name] = [t for t, v in zip(bx.times, arr) if v == v]
            ma, rf = event_floor(m, r[1], mins)
            det_ser[(m, h.name)] = (bx.times, arr, ma, rf)
            dirn = event_direction(m)
            # всплески короче ≈ win/2 снимков — центрированный фон (как events); плато длиннее — «хвостовой» фон до
            # начала эпизода (trailing_shifts): внутри длинного плато центрированная медиана сама становится уровнем
            shifts, excl = trailing_shifts(arr, window=win, z_thr=z_thr, min_abs=ma, direction=dirn, rel_floor=rf, min_len=3)
            pts = {}
            for t, v, base, _z in rolling_spikes(arr, bx.times, window=win, z_thr=z_thr, min_abs=ma, direction=dirn,
                                                 rel_floor=rf):
                excl.add(pos[t])
                if h.start() <= t <= h.end() and v != base:
                    pts[t] = (v, base)
            for s, e, base, sgn in shifts:
                for k in range(s, e + 1):
                    t, v = bx.times[k], arr[k]
                    if v == v and sgn * (v - base) > 0 and h.start() <= t <= h.end():
                        pts.setdefault(t, (v, base))
            for t, (v, base) in pts.items():
                # направление — по знаку отклонения от фона (на плоском фоне z = ±inf и у провала)
                spikes[(m, "↑" if v > base else "↓")].append((t, h.name, v, base))
            part[(m, h.name)] = (bx.times, arr, excl, dts, ma, r[1])

    def series_of(m, hn):
        """Ряд метрики хоста для участия и объёма; метрики вне --metrics (баланс rx/tx) — без исключённых выбросов."""
        if (m, hn) not in part:
            bx = full_of[hn]
            r = resolve_metric(bx, m)
            part[(m, hn)] = (bx.times, r[2], set(), _snap_dt(bx), None, r[1]) if r else None
        return part[(m, hn)]

    def level(ser, lo, hi, up):
        """Хост в окне эпизода [lo, hi]: (фон, среднее в эпизоде, пик, избыток Σ(значение − фон)·длительность снимка) или
        None. Фон — медиана win последних конечных значений до окна, не входящих в выбросы/плато хоста (не больше
        8·win снимков назад; если их меньше 5 — и после окна)."""
        times, arr, excl, dts = ser[0], ser[1], ser[2], ser[3]
        a, b = bisect.bisect_left(times, lo), bisect.bisect_right(times, hi)
        inside = [k for k in range(a, b) if arr[k] == arr[k]]
        if not inside:
            return None
        ref = []
        for k in range(a - 1, max(-1, a - 1 - 8 * win), -1):
            if arr[k] == arr[k] and k not in excl:
                ref.append(arr[k])
                if len(ref) >= win:
                    break
        if len(ref) < 5:
            for k in range(b, min(len(arr), b + 8 * win)):
                if arr[k] == arr[k] and k not in excl:
                    ref.append(arr[k])
                    if len(ref) >= win:
                        break
        if len(ref) < 3:
            return None
        base = fmedian(ref)
        vals = [arr[k] for k in inside]
        return (base, sum(vals) / len(vals), max(vals) if up else min(vals),
                sum((arr[k] - base) * dts[k] for k in inside))

    def joins(ma, base, lvl, up):
        """Участник эпизода: среднее хоста в эпизоде против фона до него — ×≥ 1.25 (↑) / ×≤ 0.8 (↓) (CLUSTER_SYNC_RATIO
        WARN); рост — ещё и не меньше минимального отклонения выброса (при нулевом фоне — только оно); провал — при фоне
        не ниже EVENT_DROP_FLOOR минимального (почти пустой диск/интерфейс провалиться не может)."""
        up_r, down_r = CLUSTER_SYNC_RATIO["WARN"]
        if up:
            return lvl - base >= (ma or 0.0) and lvl > base and (base <= 0 or lvl >= up_r * base)
        return base > 0 and (not ma or base >= EVENT_DROP_FLOOR * ma) and lvl <= down_r * base

    stress_cache = {}

    def stress_at(hn, lo, hi):
        """Стресс хоста в окне [lo, hi] — метрика выше WARN правил health (cpu.wait > CPU_WAIT, proc.blocked ≥ WARN
        BLOCKED_HIGH, disk.busy_max > 90 %, proc.runq > RUNQ_HIGH × CPU; при --link-mbit — загрузка порта ≥ WARN
        NET_LINK_UTIL) — или None."""
        bx = full_of[hn]
        if hn not in stress_cache:
            lv = episode_levels(thr, bx.ncpus())
            ser = []
            for m in CLUSTER_STRESS:
                r = resolve_metric(bx, m)
                if r and m in lv:
                    ser.append((m, r[2], lv[m][0], m == "proc.blocked"))
            if link_mbit and bx.has("NET"):
                cap = link_capacity_kbs(link_mbit)
                roles = bx.net_roles()
                cols = [bx.col("NET", f"{i}-{d}-KB/s") for i in bx.net_ifaces()
                        if roles.get(i) == "nic" or roles.get(i, "").startswith("bond-slave") for d in ("read", "write")]
                cols = [a for a in cols if a is not None]
                if cols and cap > 0:
                    util = [max((a[k] for a in cols if a[k] == a[k]), default=NAN) * 100.0 / cap for k in range(bx.n())]
                    ser.append(("загрузка порта", util, _thr(thr, "NET_LINK_UTIL")[0], True))
            stress_cache[hn] = ser
        a, b = bisect.bisect_left(bx.times, lo), bisect.bisect_right(bx.times, hi)
        for m, arr, lim, ge in stress_cache[hn]:
            mx = fmax(arr[a:b]) if b > a else NAN
            if mx == mx and (mx >= lim if ge else mx > lim):
                return m
        return None

    w, c = _thr(thr, "CLUSTER_SYNC")
    min_hosts = max(3, math.ceil(0.2 * len(hosts))) if len(hosts) >= 3 else 2
    half = timedelta(seconds=0.5 * bucket)
    comps = []  # компоненты (метрика + направление) эпизодов, прошедшие прямой подсчёт участников
    for (m, sign), sp in spikes.items():
        up = sign == "↑"
        cls = ("load_up" if up else "activity_down") if m in CLUSTER_LOAD else \
            ("stress_up" if m in CLUSTER_STRESS and up else "other")
        for e in _sync_episodes(sp, det_times[m], bucket, min_hosts, w):
            # участие — прямо по ряду каждого хоста: снимки, интервал которых больше чем наполовину внутри эпизода
            # (время снимка в [начало − ½ интервала, конец + ½ интервала]), против фона до эпизода — не по тому,
            # прошёл ли отдельный снимок z-тест
            lo, hi = e["start"] - half, e["end"] + half
            per = {}
            for hn in det_times[m]:
                r_ = level(part[(m, hn)], lo, hi, up)
                if r_:
                    per[hn] = r_
            joined = {hn: r_ for hn, r_ in per.items() if joins(part[(m, hn)][4], r_[0], r_[1], up)}
            k = len(joined)
            if k < min_hosts or 100.0 * k / len(per) < w:
                continue
            first = {}  # хост -> его первый выброс в эпизоде
            for t, hn, _v, _b in e["spikes"]:
                if hn in joined and (hn not in first or t < first[hn]):
                    first[hn] = t
            order = sorted(first.items(), key=lambda kv_: (kv_[1], kv_[0]))
            # «первый» — только если хост опередил всех остальных не меньше чем на 0.9 интервала (значения nmon —
            # средние за предыдущий интервал, опережение на секунды о порядке событий ничего не говорит) и у остальных
            # в его снимке ещё нет отклонения того же знака (z по порогу пересекается в разное время, а изменение
            # могло начаться у всех в одном интервале)
            lead = order[0] if len(order) > 1 and (order[1][1] - order[0][1]).total_seconds() >= 0.9 * bucket else None
            if lead and any(_sync_moved(det_ser[(m, hn)], lead[1], up, z_thr, bucket) for hn in first if hn != lead[0]):
                lead = None
            ratios = [r_[1] / r_[0] for r_ in joined.values() if r_[0] > 0]
            unit = part[(m, next(iter(joined)))][5]
            dur = (e["end"] - e["start"]).total_seconds() + bucket  # с начала интервала первого снимка
            peaks = {hn: r_[2] for hn, r_ in joined.items()}
            comps.append({
                "metric": m, "name": f"{m}{sign}", "up": up, "cls": cls, "start": e["start"], "end": e["end"],
                "lo": lo, "hi": hi, "dur": dur, "n_iv": dur / bucket, "k": k, "present": len(per),
                "share": 100.0 * k / len(per), "ratio": fmedian(ratios) if ratios else NAN,
                "base": fmedian([r_[0] for r_ in joined.values()]), "level": fmedian([r_[1] for r_ in joined.values()]),
                "peak": fmedian(list(peaks.values())), "unit": unit,
                # избыточный (или недостающий) объём по всем хостам с данными: Σ(значение − фон)·длительность, KB -> GB
                "volume": sum(r_[3] for r_ in per.values()) / 1048576.0 if unit == "KB/s" else None,
                "hosts": sorted(joined), "lead": lead, "peaks": peaks,
                "stress": {hn: s_ for hn in joined for s_ in [stress_at(hn, lo, hi)] if s_},
                "kind": "плато" if dur / bucket > win // 2 else ("всплеск" if up else "провал")})

    def comp_sev(cp):
        """Уровень компонента и критерий, который его дал (печатается в замечании)."""
        k, ns, rr = cp["k"], len(cp["stress"]), cp["ratio"]
        stress = ns >= 0.5 * k
        st_txt = f"стресс выше WARN health у {ns} из {k} хостов ({', '.join(sorted(set(cp['stress'].values())))})"
        if len(hosts) < 3:
            return None, ""
        if cp["cls"] == "load_up":
            if stress:
                return "WARN", f"рост нагрузки и {st_txt} → WARN"
            return "INFO", "синхронный рост нагрузки без стресса → INFO"
        if cp["cls"] == "activity_down":
            dw, dc = CLUSTER_DOWN_RATIO["WARN"], CLUSTER_DOWN_RATIO["CRIT"]
            nw, nc = CLUSTER_DOWN_RUN["WARN"], CLUSTER_DOWN_RUN["CRIT"]
            base = f"провал ×≤ {dw:g} у ≥ {c:g}% хостов"
            if cp["share"] >= c and cp["n_iv"] >= nw - 1e-6 and rr == rr and rr <= dw:
                why = [s_ for s_, ok in ((f"×{rr:.2f} ≤ {dc:g}", rr <= dc),
                                         (f"{cp['n_iv']:.0f} интервалов ≥ {nc}", cp["n_iv"] >= nc - 1e-6),
                                         (st_txt, stress)) if ok]
                return ("CRIT", f"{base}, {'; '.join(why)} → CRIT") if why else \
                    ("WARN", f"{base}, ≥ {nw} интервалов → WARN")
            return "INFO", f"провал слабее WARN ({base}, ≥ {nw} интервалов) → INFO"
        if cp["cls"] == "stress_up":
            hi_n = 0
            for hn, pk in cp["peaks"].items():
                lv = episode_levels(thr, full_of[hn].ncpus()).get(cp["metric"])
                if lv and (pk >= lv[0] if cp["metric"] == "proc.blocked" else pk > lv[0]):
                    hi_n += 1
            if hi_n < 0.5 * k:
                return None, f"пик ниже WARN health у {k - hi_n} из {k} хостов — только строка таблицы"
            sev = _sev(cp["share"], w, c)
            if sev == "CRIT" and rr == rr and rr < CLUSTER_SYNC_RATIO["CRIT"][0]:
                sev = "WARN"
            return sev, f"пик выше WARN health у {hi_n} из {k} хостов, доля хостов ≥ {c if sev == 'CRIT' else w:g}% → {sev}"
        sev = _sev(cp["share"], w, c)
        up_c, down_c = CLUSTER_SYNC_RATIO["CRIT"]
        if sev == "CRIT" and rr == rr and not (rr >= up_c if cp["up"] else rr <= down_c):
            sev = "WARN"
        return sev, f"доля хостов ≥ {c if sev == 'CRIT' else w:g}%" + (f" и ×{'≥' if cp['up'] else '≤'} "
                                                                   f"{up_c if cp['up'] else down_c:g}" if sev == "CRIT" else "") + f" → {sev}"

    for cp in comps:
        cp["sev"], cp["why"] = comp_sev(cp)
    # компоненты с началом в пределах CLUSTER_SYNC_MERGE интервала — одно событие и одно замечание; рост нагрузки
    # вместе с провалом активности — WARN (смена профиля нагрузки или блокировка операций)
    def together(a, b):
        """Одно событие: начала в пределах CLUSTER_SYNC_MERGE интервала или эпизоды перекрываются не меньше чем на
        половину более длинного (плато разных метрик с началом в разных снимках)."""
        if abs((a["start"] - b["start"]).total_seconds()) <= CLUSTER_SYNC_MERGE * bucket:
            return True
        ov = (min(a["end"], b["end"]) - max(a["start"], b["start"])).total_seconds() + bucket
        return ov >= 0.5 * max(a["dur"], b["dur"])

    groups = []
    for cp in sorted((cp for cp in comps if cp["sev"]), key=lambda cp: (cp["start"], cp["name"])):
        g = groups[-1] if groups else None
        if g and all(o["name"] != cp["name"] for o in g) and any(together(cp, o) for o in g):
            g.append(cp)
        else:
            groups.append([cp])

    def excess(m, hosts_, lo, hi):
        """Σ по хостам избытка метрики (KB/s) в окне [lo, hi] над фоном до окна, GB; None — нет данных."""
        tot, got = 0.0, False
        for hn in hosts_:
            ser = series_of(m, hn)
            r_ = level(ser, lo, hi, True) if ser else None
            if r_:
                tot += r_[3]
                got = True
        return tot / 1048576.0 if got else None

    for g in groups:
        downs = [cp for cp in g if cp["cls"] == "activity_down"]
        for cp in g:
            if cp["cls"] == "load_up" and cp["sev"] == "INFO" and downs:
                cp["sev"], cp["why"] = "WARN", f"рост нагрузки вместе с провалом {', '.join(d['name'] for d in downs)} → WARN"
        top = min(g, key=lambda cp: (SEV_ORDER.get(cp["sev"], 9), -cp["share"], cp["start"]))
        start, end = min(cp["start"] for cp in g), max(cp["end"] for cp in g)
        lo, hi = min(cp["lo"] for cp in g), max(cp["hi"] for cp in g)
        dur = (end - start).total_seconds() + bucket
        net_up = [cp for cp in g if cp["metric"].startswith("net.") and cp["up"]]
        bal = None
        if net_up and full_of:
            tx, rx = excess("net.write", full_of, lo, hi), excess("net.read", full_of, lo, hi)
            if tx is not None and rx is not None:
                bal = (tx, rx)
        hints = []
        if bal:
            tx, rx = bal
            if tx > 0 and rx < CLUSTER_BALANCE * tx:
                hints.append(f"Σ избытка tx {tx:.1f} GB ≫ Σ избытка rx {rx:.1f} GB: трафик уходит за пределы анализируемых "
                             f"хостов (клиенты, внешние системы, узлы без данных nmon); rebalance между этими узлами исключён")
            elif rx > 0 and tx < CLUSTER_BALANCE * rx:
                hints.append(f"Σ избытка rx {rx:.1f} GB ≫ Σ избытка tx {tx:.1f} GB: трафик приходит извне анализируемых "
                             f"хостов (клиенты, загрузка данных, узлы без данных nmon)")
            else:
                hints.append(f"Σ избытка tx {tx:.1f} GB ≈ Σ избытка rx {rx:.1f} GB: обмен внутри набора хостов — "
                             f"rebalance, снапшот, репликация между узлами")
            if max(tx, rx) >= CLUSTER_PME_GB:
                hints.append(f"объём {max(tx, rx):.1f} GB несовместим с сообщениями PME (их объём — мегабайты)")
        if any(cp["metric"].startswith("disk.") and cp["up"] for cp in g):
            hints.append("синхронная запись/чтение дисков: checkpoint по расписанию, снапшот, массовая загрузка, rebalance")
        if any(cp["metric"] in ("cpu.busy", "top.java.cpu") and cp["up"] for cp in g):
            hints.append("синхронная вычислительная нагрузка: массовые запросы, rebalance, GC")
        if downs:
            if bal and max(bal) >= CLUSTER_PME_GB:
                hints.append(f"провал {', '.join(d['name'] for d in downs)} на фоне массовой передачи — не остановка узлов: смена "
                             "профиля нагрузки или блокировка обновлений; сверить с логами Ignite (exchange, rebalance, "
                             "snapshot, клиентские запросы)")
            else:
                hints.append("одновременный провал активности узлов: блокировка операций (PME/exchange — короткий эпизод "
                             "малого объёма), пауза клиентской нагрузки, сетевое событие — сверить с логами Ignite и GC")
        if any(cp["cls"] == "stress_up" for cp in g):
            hints.append("синхронный стресс: общий ресурс (СХД, сеть, гипервизор) или кластерная операция (checkpoint, "
                         "rebalance, снапшот)")
        if not hints:
            hints.append("синхронное отклонение на нескольких узлах — сверить с логами Ignite по времени")

        def comp_ev(cp):
            p = 0 if cp["unit"] in ("KB/s", "MB", "/s") else 1
            s_ = (f"{cp['name']} [{cp['sev']}; {cp['kind']}, {fmt_dur(cp['dur'])}]: {cp['k']} из {cp['present']} хостов, "
                  f"×{fmt_num(cp['ratio'], 2)}, фон → в эпизоде {fmt_num(cp['base'], p)} → {fmt_num(cp['level'], p)} "
                  f"{cp['unit']} (Δ {fmt_num(cp['level'] - cp['base'], p)})")
            if cp["volume"] is not None:
                s_ += f", {'выше' if cp['volume'] >= 0 else 'ниже'} фона на {abs(cp['volume']):.1f} GB"
            if cp["lead"]:
                s_ += f", первый {cp['lead'][0]} @ {ts(cp['lead'][1])}"
            return s_

        hs = sorted({hn for cp in g for hn in cp["hosts"]})
        F.append(Finding(top["sev"], "CLUSTER_SYNC", "*", " + ".join(cp["name"] for cp in g), top["share"], top["why"],
                         f"{ts(start)} .. {ts(end)} ({fmt_dur(dur)}); " + "; ".join(comp_ev(cp) for cp in g)
                         + f"; хосты: {', '.join(hs[:6])}{'…' if len(hs) > 6 else ''}"
                         + ("" if any(cp["lead"] for cp in g) else "; первый: одновременно (в пределах интервала nmon)"),
                         "; ".join(hints), time=start,
                         extra={"ratio": top["ratio"], "duration_s": dur, "base": top["base"], "peak": top["peak"],
                                "level": top["level"], "unit": top["unit"], "volume": top["volume"],
                                "balance_gb": {"tx": bal[0], "rx": bal[1]} if bal else None,
                                "components": [{"metric": cp["name"], "severity": cp["sev"], "criterion": cp["why"],
                                                "kind": cp["kind"], "start": cp["start"], "end": cp["end"],
                                                "duration_s": cp["dur"], "hosts": cp["k"], "present": cp["present"],
                                                "share": cp["share"], "ratio": cp["ratio"], "base": cp["base"],
                                                "level": cp["level"], "peak": cp["peak"], "unit": cp["unit"],
                                                "volume": cp["volume"]} for cp in g]}))
    srows = [[cp["start"], cp["end"], cp["dur"], cp["name"], cp["kind"], cp["sev"] or "-", cp["k"], cp["share"], cp["ratio"],
              cp["base"], cp["level"], cp["unit"], cp["volume"] if cp["volume"] is not None else NAN,
              f"{cp['lead'][0]} @ {cp['lead'][1].strftime('%H:%M:%S')}" if cp["lead"] else "одновременно", cp["hosts"]]
             for cp in comps]
    srows.sort(key=lambda r: (r[0], r[3]))
    title = "Синхронные выбросы (эпизоды: всплеск или плато ↑, провал ↓ у нескольких хостов в пределах интервала nmon)"
    if srows or n_det >= 5:
        filtered = [h for h in hosts if h.unfiltered is not None]
        rep.table(title, ["начало", "конец", "длительность", "метрика", "тип", "уровень", "хостов", "% хостов",
                          "×значение/фон", "фон", "в эпизоде", "ед.", "объём, GB", "первый", "хосты"],
                  srows[:60], total=len(srows),
                  prec={"длительность": "dur", "% хостов": 0, "×значение/фон": 2, "фон": 0, "в эпизоде": 0, "объём, GB": 1,
                        "хосты": "list"},
                  note=f"кандидаты: выбросы хостов (как в events: центрированный фон ±{win // 2} снимков; плато длиннее — по "
                       f"«хвостовому» фону {win} снимков до начала, эпизод длится, пока отклонение ≥ половины начального) "
                       f"совпадают, если попали в окно {fmt_dur(1.5 * bucket)} от первого (допуск на фазу снимков); подряд идущие "
                       f"окна — один эпизод; участники считаются прямо: среднее хоста в эпизоде против фона до него "
                       f"(×≥ {CLUSTER_SYNC_RATIO['WARN'][0]:g} для ↑, ×≤ {CLUSTER_SYNC_RATIO['WARN'][1]:g} для ↓ и не меньше "
                       f"минимального отклонения); нужно ≥ {min_hosts} хостов и ≥ {w:g}% хостов с данными; ×значение/фон, фон и "
                       f"«в эпизоде» — медианы по участникам; объём — Σ по хостам (значение − фон) × длительность снимка "
                       f"(net/disk; < 0 — недостача); уровень: рост нагрузки — INFO (WARN при стрессе выше WARN health у ≥ "
                       f"половины участников или вместе с провалом активности), провал активности — WARN при ×≤ "
                       f"{CLUSTER_DOWN_RATIO['WARN']:g}, ≥ {c:g}% хостов, ≥ {CLUSTER_DOWN_RUN['WARN']} интервалов, CRIT — "
                       f"ещё ×≤ {CLUSTER_DOWN_RATIO['CRIT']:g}, ≥ {CLUSTER_DOWN_RUN['CRIT']} интервалов или стресс; стресс-"
                       f"метрики — только при пике выше WARN health («-» — только строка таблицы); компоненты с началом в "
                       f"пределах {CLUSTER_SYNC_MERGE:g} интервала — одно замечание CLUSTER_SYNC; длительность — с начала "
                       f"интервала первого снимка (интервал nmon {fmt_dur(bucket)}); «первый» — хост, опередивший остальных "
                       f"≥ 0.9 интервала ({fmt_dur(0.9 * bucket)}), если у остальных в его снимке ещё нет отклонения того же "
                       f"знака, иначе одновременно; надёжно только при синхронных часах"
                       + (f"; фон — по полному ряду, показаны эпизоды в окне {ts(min(h.start() for h in filtered))} .. "
                          f"{ts(max(h.end() for h in filtered))}" if filtered else ""))
    else:
        rep.text(title, f"в окне {n_det} снимков — мало для поиска выбросов")
    # Кластерный таймлайн: агрегаты по корзинам времени (ряды без T0001)
    if starts and ends:
        span = (max(ends) - min(starts)).total_seconds()
        step_s = 300 if span <= 3 * 3600 else (900 if span <= 12 * 3600 else 3600)
        spec = [("cpu.busy", "mean"), ("cpu.wait", "mean"), ("proc.blocked", "max"), ("disk.busy_max", "max"),
                ("disk.write", "sum"), ("disk.read", "sum"), ("net.read", "sum"), ("net.write", "sum"), ("top.java.cpu", "sum")]
        acc = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))  # bucket -> metric -> host -> values
        present = defaultdict(set)
        for x in hx:
            if x.firsts_kept:
                continue  # только T0001 (неполный интервал) — не в таймлайн, как и в таблицу метрик
            per = {}
            for m, _a in spec:
                r = resolve_metric(x, m)
                if r:
                    per[m] = r[2]
            for i, t in enumerate(x.times):
                k = bucket_start(t, step_s)
                present[k].add(x.name)
                for m, vals in per.items():
                    v = vals[i]
                    if v == v:
                        acc[k][m][x.name].append(v)
        trows = []
        for k in sorted(present):
            row = [k, len(present[k])]
            for m, a in spec:
                per_host = [sum(v) / len(v) for v in acc[k].get(m, {}).values() if v]  # среднее по снимкам корзины на хост
                if not per_host:
                    row.append(NAN)
                elif a == "mean":
                    row.append(sum(per_host) / len(per_host))
                elif a == "max":
                    row.append(max(max(v) for v in acc[k][m].values() if v))
                else:
                    row.append(sum(per_host))  # сумма средних по хостам, у которых есть значение метрики
            trows.append(row)
        rep.table(f"Кластерный таймлайн (шаг {fmt_dur(step_s)}): mean по хостам для cpu, max для blocked/busy, сумма по хостам для disk/net/java",
                  ["время", "хостов"] + [f"{m}:{a}" for m, a in spec], trows,
                  prec={f"{m}:{a}": 0 for m, a in spec},
                  note="mean и sum: по каждому хосту сначала берётся среднее по его снимкам в корзине, затем mean или сумма "
                       "по хостам, у которых метрика есть; max (blocked, busy) — максимум по всем снимкам корзины всех хостов; "
                       "без первого снимка каждого файла (неполный интервал)"
                       + (f"; без хостов, где в выборке только первые снимки файлов: {', '.join(t1only)}" if t1only else ""))
    # Покрытие: хост без данных, пока у заметной части остальных они есть. Опора — не максимум по кластеру: один хост,
    # записанный дольше (nmon работал дольше, файл скопирован позже), не делает «упавшими» все остальные
    w, c = _thr(thr, "CLUSTER_COVERAGE")
    covrows = []
    live = [h for h in hosts if h.times]
    med_start = fmedian_dt([h.start() for h in live])
    med_end = fmedian_dt([h.end() for h in live])
    for h in live:
        step = h.step()
        others = [o for o in live if o is not h]
        later = [o for o in others if (o.end() - h.end()).total_seconds() >= w * step]
        need = max(2, math.ceil(0.5 * len(others))) if len(live) >= 3 else max(1, len(others))
        if others and len(later) >= need:
            ref = fmedian_dt([o.end() for o in later])
            early = (ref - h.end()).total_seconds() / step
            sev = _sev(early, w, c)
            F.append(Finding(sev, "CLUSTER_COVERAGE", h.name, "данные закончились раньше других, снимков", early, f"≥ {w}",
                             f"конец {ts(h.end())}; данные есть у {len(later)} из {len(others)} остальных хостов до "
                             f"{ts(ref)} (медиана их концов)", "узел/nmon остановился раньше остальных: падение узла?",
                             time=h.end()))
            covrows.append([h.name, "конец раньше", h.end(), early])
        elif med_end is not None and (med_end - h.end()).total_seconds() >= w * step:
            covrows.append([h.name, "конец раньше медианы", h.end(), (med_end - h.end()).total_seconds() / step])
        if med_end is not None and (h.end() - med_end).total_seconds() >= w * step:
            covrows.append([h.name, "конец позже медианы", h.end(), (h.end() - med_end).total_seconds() / step])
        if med_start is not None and (h.start() - med_start).total_seconds() >= w * step:
            covrows.append([h.name, "начало позже медианы", h.start(), (h.start() - med_start).total_seconds() / step])
        for a, b, d, iv in h.gaps():
            covrows.append([h.name, "разрыв", a, d / iv])
    if covrows:
        rep.table("Неполное покрытие", ["host", "вид", "время", "снимков"], covrows[:40], total=len(covrows), prec={"снимков": 0})
    shown = _filter_sev(F, args)  # фильтр severity — только для вывода; код возврата — по всем замечаниям (rep.worst)
    rep.findings("Замечания уровня кластера", shown, note=_filter_note(F, shown))
    # Итоги health по хостам
    hrows = []
    for h in hosts:
        fs = health_checks(h, thr, link_mbit=_opt(args, "link_mbit", None))
        cnt = defaultdict(int)
        codes = defaultdict(list)
        for f in fs:
            cnt[f.severity] += 1
            if f.severity in ("CRIT", "WARN"):
                codes[f.severity].append(f.code)
        hrows.append([h.name, cnt["CRIT"], cnt["WARN"], ", ".join(sorted(set(codes["CRIT"]))), ", ".join(sorted(set(codes["WARN"])))[:120]])
    hrows.sort(key=lambda r: (-r[1], -r[2]))
    rep.table("Health по хостам", ["host", "CRIT", "WARN", "коды CRIT", "коды WARN"], hrows)
    rep.worst = max(_worst(F), 2 if any(r[1] > 0 for r in hrows) else (1 if any(r[2] > 0 for r in hrows) else 0))
    return rep


CORR_MIN_N = 30  # пары с меньшим числом общих точек помечаются «мало точек»


def _corr_pair(host, xs, ys):
    """(r по уровням, r по первым разностям соседних снимков, n общих конечных точек). Разности берутся только для
    соседних снимков, где оба значения обеих метрик конечны и промежуток ≤ 1.5 интервала (без скачков через разрыв)."""
    n = sum(1 for x, y in zip(xs, ys) if x == x and y == y)
    dx, dy = [], []
    for k in range(1, min(len(xs), len(ys), host.n())):
        a0, a1, b0, b1 = xs[k - 1], xs[k], ys[k - 1], ys[k]
        if a0 == a0 and a1 == a1 and b0 == b0 and b1 == b1 \
                and (host.times[k] - host.times[k - 1]).total_seconds() <= 1.5 * host.pair_iv(k - 1):
            dx.append(a1 - a0)
            dy.append(b1 - b0)
    return pearson(xs, ys), pearson(dx, dy), n


def analyze_correlate(host, args=None):
    rep = Report("Корреляции между метриками (Пирсон)", host.name)
    metrics = _opt(args, "metrics", None) or ["cpu.busy", "cpu.sys", "cpu.wait", "proc.runq", "proc.blocked", "proc.pswitch",
                                                "mem.free", "disk.busy_max", "disk.read", "disk.write", "disk.iops", "net.read",
                                                "net.write", "top.java.cpu", "top.java.sys", "vm.pgmajfault", "vm.kswapd_steal"]
    hx = host.without_first()  # T0001 (неполный интервал) даёт ложные пики, связывающие метрики
    res = [(m, r[2]) for m, r in resolve_metrics(hx, metrics, warn_missing=bool(_opt(args, "metrics", None)))
           if len(clean(r[2])) >= 5 and fstdev(r[2]) > 0]
    target = _opt(args, "target", None)
    note = ("корреляция ≠ причинность; r — по уровням: общий суточный тренд нагрузки завышает его для многих пар "
            "метрик нагрузки; r Δ — по изменениям от снимка к снимку (совместные всплески и провалы), надёжнее для "
            "вывода о связи; n — общих конечных точек пары, при n < " + str(CORR_MIN_N) + " — «мало точек»; "
            "без первых снимков файлов (T0001)")
    if target:
        rt = resolve_metric(hx, target)
        if not rt:
            rep.text("", f"метрика {target} недоступна")
            return rep
        if len(clean(rt[2])) < 5 or not fstdev(rt[2]) > 0:
            rep.text(f"Корреляция с {target}", f"метрика-цель {target} постоянна или почти без данных "
                                               f"({len(clean(rt[2]))} значений) — корреляция не определена")
            return rep
        rows = []
        for m, a in res:
            if m == target:
                continue
            r, rd, n = _corr_pair(hx, rt[2], a)
            rows.append([m, r, rd, n, "мало точек" if n < CORR_MIN_N else ""])
        rows.sort(key=lambda r: -abs(r[1]) if r[1] == r[1] else 0)
        rep.table(f"Корреляция с {target}", ["метрика", "r", "r Δ", "n", "примечание"], rows, prec={"r": 2, "r Δ": 2, "n": 0},
                  note=note)
    else:
        pairs = []
        for i in range(len(res)):
            for j in range(i + 1, len(res)):
                r, rd, n = _corr_pair(hx, res[i][1], res[j][1])
                if (r == r and abs(r) >= 0.5) or (rd == rd and abs(rd) >= 0.5):
                    pairs.append([res[i][0], res[j][0], r, rd, n, "мало точек" if n < CORR_MIN_N else ""])
        pairs.sort(key=lambda p: -abs(p[2]) if p[2] == p[2] else 0)
        limit = _opt(args, "limit", 40) or 40
        rep.table("Наиболее связанные пары (|r| ≥ 0.5 или |r Δ| ≥ 0.5)", ["метрика A", "метрика B", "r", "r Δ", "n", "примечание"],
                  pairs[:limit], total=len(pairs), prec={"r": 2, "r Δ": 2, "n": 0},
                  note=note + "; |r Δ| > 0.7 — сильная связь изменений (например, disk.write ↔ cpu.wait)")
    return rep


TOP_EXPORT_COLUMNS = ["time", "pid", "command", "cpu_pct", "usr_pct", "sys_pct", "size_kb", "rss_kb", "restext_kb",
                      "resdata_kb", "shdlib_kb", "minflt", "majflt", "threads", "iowait"]
# колонка export TOP -> имя колонки в заголовке TOP nmon (export --columns принимает оба имени)
TOP_EXPORT_NMON = {"time": "Time", "pid": "PID", "command": "Command", "cpu_pct": "%CPU", "usr_pct": "%Usr",
                   "sys_pct": "%Sys", "size_kb": "Size", "rss_kb": "ResSet", "restext_kb": "ResText", "resdata_kb": "ResData",
                   "shdlib_kb": "ShdLib", "minflt": "MinorFault", "majflt": "MajorFault", "threads": "Threads",
                   "iowait": "IOwaitTime"}


def _export_col_unit(sec, col):
    """Единица колонки секции (для --agg sum): VM — по колонке (nr_* — pages, pgpgin/pgpgout — KB/interval, остальные
    — count/interval), PROC — Runnable/Blocked count, остальные /s; прочие секции — по SECTION_INFO."""
    if sec == "VM":
        return "pages" if col.startswith("nr_") else ("KB/interval" if col in ("pgpgin", "pgpgout") else "count/interval")
    if sec == "PROC":
        return "count" if col in ("Runnable", "Blocked") else "/s"
    return _section_info(sec)[1]


def analyze_export(host, args=None):
    """Выгрузка секции или набора метрик с реальным временем. Если выгружать нечего (нет секции, не подошли
    --columns, нет TOP/UARG, не найдена ни одна метрика) — WARN в stderr и rep.error = True (см. main)."""
    rep = Report("Экспорт", host.name)
    section = _opt(args, "section", None)
    metrics = _opt(args, "metrics", None)
    step_s = parse_duration(_opt(args, "step", None)) if _opt(args, "step", None) else 0
    agg = _opt(args, "agg", "mean") or "mean"
    colsel = _opt(args, "columns", None)
    limit = _opt(args, "limit", None)

    def fail(msg):
        warn(f"{host.name}: {msg}")
        rep.text("", msg)
        rep.error = True
        return rep

    def finish(title, cols, rows, prec, note=None):
        total = len(rows)
        if limit and len(rows) > limit:
            rows = rows[:limit]
        rep.table(title, cols, rows, prec=prec, total=total, note=note)
        return rep

    def aggregate(named):
        """--step/--agg для [(имя, единица, значения)] -> (строки, примечание): общая с timeline aggregate_series."""
        tt, series, _counts, _units, note = aggregate_series(host, named, step_s, agg)
        return [[tt[k]] + [s[k] for s in series] for k in range(len(tt))], note

    if section:
        sec = section.upper()
        if sec in ("TOP", "UARG"):
            if sec == "TOP":
                cols = list(TOP_EXPORT_COLUMNS)
                rows = [[host.times[i], p.pid, p.cmd, p.cpu, p.usr, p.sys, p.size, p.rss, p.text, p.data, p.shlib,
                         p.minflt, p.majflt, p.threads, p.iowait] for i, procs in enumerate(host.top) for p in procs]
                if not rows:
                    return fail("в выбранном окне нет снимков с данными TOP (TOP пишется начиная со второго снимка); "
                                "расширьте окно" if host.top_in_files() else "секция TOP отсутствует (nmon запущен без -t)")
            else:
                cols = ["first_seen", "pid", "prog", "cmdline"]
                rows = [[first, pid, prog, full] for pid, (prog, full, first) in host.uarg_cmdlines().items()]
                if not rows:
                    return fail("в выбранном окне нет строк UARG; расширьте окно" if any(f.uarg for f in host.files)
                                else "секция UARG отсутствует (nmon запущен без -T)")
            if step_s:
                warn(f"{host.name}: --step/--agg к секции {sec} не применяются (строки процессов выгружаются как есть)")
            if colsel:
                # первая колонка (время) остаётся всегда; у TOP подходит и имя колонки nmon (ShdLib = shdlib_kb)
                keep = [k for k, c in enumerate(cols) if k == 0 or any(
                    re.fullmatch(p, c) or (sec == "TOP" and re.fullmatch(p, TOP_EXPORT_NMON.get(c, ""))) for p in colsel)]
                if len(keep) == 1:
                    return fail(f"--columns {' '.join(colsel)}: ни одна колонка {sec} не подошла; есть: {', '.join(cols)}")
                cols = [cols[k] for k in keep]
                rows = [[r[k] for k in keep] for r in rows]
            ints = {"pid", "size_kb", "rss_kb", "restext_kb", "resdata_kb", "shdlib_kb", "minflt", "majflt", "threads", "iowait"}
            return finish(sec, cols, rows, {c: 0 for c in cols if c in ints})
        sec = Host._base_name(sec)
        if sec not in host.series:
            have = sorted(host.series) + [s for s, ok in (("TOP", any(host.top)), ("UARG", any(host.uarg))) if ok]
            return fail(f"секция {sec} отсутствует; есть: {_compact_sections(have)}")
        cols = host.cols(sec)
        if colsel:
            cols = [c for c in cols if any(re.fullmatch(p, c) for p in colsel)]
            if not cols:
                return fail(f"--columns {' '.join(colsel)}: ни одна колонка секции {sec} не подошла; есть: {', '.join(host.cols(sec))}")
        note = None
        if step_s:
            rows, note = aggregate([(c, _export_col_unit(sec, c), host.series[sec][c]) for c in cols])
        else:
            rows = [[host.times[i]] + [host.series[sec][c][i] for c in cols] for i in range(host.n())]
        return finish(sec, ["time"] + cols, rows, {c: 3 for c in cols}, note)
    explicit = bool(metrics)
    metrics = metrics or DEFAULT_TIMELINE
    resolved = resolve_metrics(host, metrics, warn_missing=explicit)
    res = [(m, r[2]) for m, r in resolved]
    if not res:
        return fail(f"ни одна из метрик не найдена в данных: {' '.join(metrics)} (список: команда metrics)")
    if explicit and not any(clean(a) for _, a in res):
        return fail(f"ни у одной из метрик нет значений в данных: {' '.join(metrics)} (список: команда metrics)")
    note = None
    if step_s:
        rows, note = aggregate([(m, r[1], r[2]) for m, r in resolved])
    else:
        rows = [[host.times[k]] + [a[k] for _, a in res] for k in range(host.n())]
    return finish("metrics", ["time"] + [m for m, _ in res], rows, {m: 3 for m, _ in res}, note)


def analyze_bbbp(host, args=None):
    rep = Report("Конфигурация ОС на старте nmon (BBBP)", host.name)
    block = _opt(args, "block", None)
    pat = _opt(args, "grep", None)
    if not block and not pat:
        rep.table("Блоки", ["блок", "строк", "первая строка"],
                  [[c, len(host.bbbp[c]), (host.bbbp[c][0][:80] if host.bbbp[c] else "")] for c in host.bbbp_order])
        rep.text("Подсказка", "укажите --block <имя> (например lscpu, /proc/meminfo, /bin/df-m, /bin/mount, ifconfig) или --grep <regex>")
        return rep
    lim = _opt(args, "limit", 400)
    for c in host.bbbp_order:
        if block and not any(re.search(b, c) for b in block):
            continue
        lines = host.bbbp[c]
        if pat:
            lines = [ln for ln in lines if re.search(pat, ln)]
        if lines:
            shown = lines if not lim else lines[:lim]  # --limit 0 — без ограничения
            rest = len(lines) - len(shown)
            rep.text(c, "\n".join(shown) + (f"\n… ещё {rest} строк" if rest > 0 else ""))
    return rep


AIX_SECTIONS = {"LPAR", "POOLS", "PAGE", "MEMNEW", "MEMUSE", "SEA", "SEACHPHY", "FCREAD", "FCWRITE", "FCXFERIN",
                "FCXFEROUT", "PROCAIO", "IOADAPT", "MEMAMS", "WLMCPU", "WLMMEM", "WLMBIO"}


def _fault_accounting(host):
    """Сверка page faults процессов TOP с системными счётчиками VM — по снимкам, где есть и TOP, и VM pgmajfault
    (и pgfault, если такая колонка есть). Возвращает dict:
      status      — 'retry': Σ TOP MajorFault ≫ VM pgmajfault (≥ 10×, или pgmajfault = 0 при ненулевом TOP), но faults
                    процессов сходятся с VM pgfault (r1 или r2 в [0.85; 1.1]): MajorFault в TOP считает и faults,
                    завершённые после повтора (retry: ожидание страницы/блокировки), а не только чтения с диска;
                    'mismatch': Σ TOP MajorFault ≫ VM pgmajfault, а сверка с pgfault не сходится — колонка ненадёжна;
                    'unverified': Σ TOP MajorFault ≫ VM pgmajfault, а сверить с pgfault нельзя (колонки нет или Σ = 0);
                    'ok': MajorFault в TOP не превышает системный счётчик более чем в 10 раз;
                    'n/a': сверять не с чем (нет TOP или VM pgmajfault);
      snapshots   — число снимков в сверке;
      top_major, top_minor — Σ MajorFault·dt, Σ MinorFault·dt по процессам TOP (событий; dt — фактический шаг снимка
                    _snap_dt, как у приращений VM: после разрыва — длительность разрыва);
      vm_major, vm_faults  — Σ VM pgmajfault, Σ VM pgfault (NaN, если колонки pgfault нет);
      major_ratio — top_major / vm_major (inf при vm_major = 0 и top_major > 0; NaN при 0 / 0);
      r1, r2      — (top_minor + top_major) / vm_faults и (top_minor + 2·top_major) / vm_faults;
      retry_share — top_major / (top_minor + top_major): доля faults процессов TOP, учтённых как MajorFault."""
    out = {"status": "n/a", "snapshots": 0, "top_major": 0.0, "top_minor": 0.0, "vm_major": 0.0, "vm_faults": NAN,
           "major_ratio": NAN, "r1": NAN, "r2": NAN, "retry_share": NAN}
    pgmaj = host.col("VM", "pgmajfault")
    pgf = host.col("VM", "pgfault")
    if pgmaj is None or not any(host.top):
        return out
    dts = _snap_dt(host)
    vm_faults = 0.0
    for i, procs in enumerate(host.top):
        if not procs or pgmaj[i] != pgmaj[i] or (pgf is not None and pgf[i] != pgf[i]):
            continue
        mj = [p.majflt for p in procs if p.majflt == p.majflt]
        if not mj:
            continue  # в TOP нет MajorFault (старый nmon или урезанный заголовок): сверять нечего, а не «0 faults»
        out["snapshots"] += 1
        out["top_major"] += sum(mj) * dts[i]
        out["top_minor"] += sum(p.minflt for p in procs if p.minflt == p.minflt) * dts[i]
        out["vm_major"] += pgmaj[i]
        if pgf is not None:
            vm_faults += pgf[i]
    if not out["snapshots"]:
        return out
    tm, tn, vm = out["top_major"], out["top_minor"], out["vm_major"]
    out["major_ratio"] = tm / vm if vm > 0 else (math.inf if tm > 0 else NAN)
    if pgf is not None:
        out["vm_faults"] = vm_faults
        if vm_faults > 0:
            out["r1"] = (tn + tm) / vm_faults
            out["r2"] = (tn + 2.0 * tm) / vm_faults
    if tn + tm > 0:
        out["retry_share"] = tm / (tn + tm)
    big = tm >= 10.0 * vm if vm > 0 else tm > 0
    if not big:
        out["status"] = "ok"
    elif out["r1"] != out["r1"]:
        out["status"] = "unverified"
    elif any(0.85 <= r <= 1.1 for r in (out["r1"], out["r2"]) if r == r):
        out["status"] = "retry"
    else:
        out["status"] = "mismatch"
    return out


def analyze_check(host, args=None):
    """Качество и согласованность данных: разбор, интервал, секции, «мёртвые» колонки, перекрёстные проверки."""
    rep = Report("Проверка качества данных nmon", host.name)
    issues = []
    n = host.n()
    for fi, f in enumerate(host.files):
        b = os.path.basename(f.path)
        if f.bad_lines:
            issues.append(("WARN", f"{b}: нераспознанных или отброшенных строк: {f.bad_lines}"))
        for w in f.warnings:
            issues.append(("CRIT" if w == MSG_SORTED_MULTIRUN else "WARN", f"{b}: {w}"))
        unknown = sorted(s for s in f.sections if s not in SECTION_INFO and not re.match(r"^CPU\d+$", s)
                         and Host._base_name(s) not in SECTION_INFO and s not in AIX_SECTIONS)
        if unknown:
            issues.append(("INFO", f"{b}: секции без специальной обработки (доступны через raw.<SECTION>.<col> и export): {', '.join(unknown)}"))
        aix = sorted(s for s in f.sections if s in AIX_SECTIONS)
        if aix:
            issues.append(("WARN", f"{b}: секции AIX ({', '.join(aix)}) — файл, вероятно, с AIX; Linux-интерпретация правил неприменима"))
        if f.zzzz and f.zzzz_estimated >= len(f.zzzz):
            issues.append(("WARN", f"{b}: реальные моменты снимков неизвестны (нет строк ZZZZ, время оценено по интервалу): "
                                   f"сопоставление с логами приблизительно, разрывы и заморозки не видны"))
        # снимки без времени (f.untimed) — уже в f.warnings выше
        planned = f.meta.get("snapshots", "")
        try:
            pl = int(planned)
            if 0 < pl < 9999999 and len(f.zzzz) < pl:
                issues.append(("INFO", f"{b}: записано {len(f.zzzz)} снимков из запланированных {pl} (nmon остановлен раньше или ещё писал файл)"))
        except ValueError:
            pass
        if not f.top:
            issues.append(("INFO", f"{b}: {MSG_TOP_HEADER_ONLY}" if f.top_columns else
                           f"{b}: секция TOP отсутствует — nmon без -t; анализ процессов невозможен"))
        elif not f.uarg:
            issues.append(("INFO", f"{b}: UARG отсутствует — nmon без -T; командные строки/флаги JVM недоступны"))
        dup = host.dup_by_file[fi] if fi < len(host.dup_by_file) else 0
        same = host.dup_same_file[fi] if fi < len(host.dup_same_file) else 0
        if same:
            # часы шли назад (перевод часов, шаг NTP): метка снимка совпала с более ранним снимком того же файла
            issues.append(("WARN", f"{b}: {same} снимков отброшено — их время совпало со временем более ранних снимков "
                                   f"этого же файла (часы переведены назад или запуск nmon в файле повторён); данные этих снимков не используются"))
        dup -= same
        if len(host.files) > 1 and f.zzzz and dup > 0.1 * len(f.zzzz):
            pct = f"{dup} из {len(f.zzzz)} снимков ({100.0 * dup / len(f.zzzz):.0f}%)"
            if any(_same_machine(f, g) for g in host.files if g is not f):
                issues.append(("INFO", f"{b}: при объединении файлов хоста отброшено как дубликаты {pct}: файл дублирует "
                                       f"другой файл того же хоста (отпечаток машины совпадает)"))
            else:
                issues.append(("WARN", f"{b}: при объединении файлов хоста отброшено как дубликаты {pct} — если файлы "
                                       f"сняты на разных машинах с одинаковым AAA,host, анализируйте их с --no-merge"))
    if not any(len(f.zzzz) > f.zzzz_estimated for f in host.files) and n < 3:
        issues.append(("CRIT", "нет ни одного снимка с реальным временем (ZZZZ), снимков меньше 3 — данные непригодны"))
    if len(host.files) > 1:
        issues.append(("INFO", f"файлов хоста: {len(host.files)}; отброшено дублирующих снимков при объединении: {host.duplicates_dropped}"))
    # Перезагрузка ОС и смена конфигурации между файлами / запусками nmon (по AAA и BBBP каждого)
    for a, b_ in zip(host.file_info, host.file_info[1:]):
        where = f"запусками nmon в {a['file']} (#{a['run']} → #{b_['run']})" if a["file"] == b_["file"] else \
            f"файлами {a['file']} → {b_['file']}"
        if a["boottime"] and b_["boottime"] and abs((b_["boottime"] - a["boottime"]).total_seconds()) > 120:
            issues.append(("WARN", f"перезагрузка ОС между {where}: boottime {ts(a['boottime'])} → {ts(b_['boottime'])} "
                                   f"(данные: конец {ts(a['end'])} → начало {ts(b_['start'])})"))
        changed = [f"{label} {a[k]} → {b_[k]}" for k, label in (("OS", "OS"), ("cpus", "cpus"), ("memtotal_kb", "MemTotal, kB"))
                   if a[k] and b_[k] and a[k] != b_[k]]
        if changed:
            issues.append(("WARN", f"между {where} изменилась конфигурация: {'; '.join(changed)}"))
    ivd = host.intervals_differ()
    if ivd:
        issues.append(("INFO", MSG_IV_DIFFER + ": " + _iv_list(ivd)))
    if n >= 3:
        deltas = [(host.times[i + 1] - host.times[i]).total_seconds() for i in range(n - 1)]
        med = fmedian(deltas)
        if not ivd and host.interval and abs(med - host.interval) > 0.1 * host.interval:
            issues.append(("WARN", f"фактический медианный шаг {med:.0f}s отличается от заявленного interval={host.interval:.0f}s"))
        # отклонение шага — от номинального интервала соседних снимков (у файлов с разным interval — свой)
        jit = [d for i, d in enumerate(deltas) if abs(d - (host.pair_iv(i) if ivd else med)) > 0.25 * (host.pair_iv(i) if ivd else med)]
        if jit:
            issues.append(("WARN", f"снимков с отклонением шага > 25% от медианы: {len(jit)} из {n - 1} (min {min(deltas):.0f}s, max {max(deltas):.0f}s) — "
                                   f"nmon запаздывал (перегрузка хоста) или файлы склеены"))
    back = sum(f.time_backwards for f in host.files)
    if back:
        issues.append(("WARN", f"в {back} переходах между строками ZZZZ время идёт назад (DST, коррекция NTP, склейка файлов); "
                               f"снимки переупорядочены по времени"))
    _inner, edge = host.split_gaps()
    edge = set(edge)
    for g in host.gaps()[:10]:
        a, b_, d, _iv = g
        issues.append(("WARN", f"разрыв {fmt_dur(d)}: {ts(a)} → {ts(b_)} "
                               + ("(между файлами/запусками nmon: nmon не работал)" if g in edge
                                  else "(заморозка хоста / остановка nmon)")))
    # первые снимки файлов/запусков, которые есть в выборке (не окно в середине файла и не --skip-first)
    firsts = sorted(host.first_snapshot_indices())
    for i in firsts[:10]:
        src = f", {os.path.basename(host.files[host.snap_src[i]].path)}" if len(host.files) > 1 else ""
        issues.append(("INFO", f"первый снимок {ts(host.times[i])} ({host.snap_ids[i]}{src}) охватывает неполный интервал; "
                               f"TOP начинается со следующего снимка; для точных дельт используйте --skip-first"))
    if len(firsts) > 10:
        issues.append(("INFO", f"… и ещё {len(firsts) - 10} первых снимков файлов/запусков"))
    if not firsts and host.firsts_dropped:
        issues.append(("INFO", f"первые снимки файлов/запусков исключены (--skip-first): {host.firsts_dropped}"))
    # Перекрёстные проверки: [проверка, результат, ok, влияет на вердикт]
    checks = []
    u, s_, wv, idv, st = (host.col("CPU_ALL", c) for c in ("User%", "Sys%", "Wait%", "Idle%", "Steal%"))
    if u is not None and idv is not None:
        bad = 0
        for i in range(n):
            parts_i = [x[i] for x in (u, s_, wv, idv, st) if x is not None and x[i] == x[i]]
            if parts_i and abs(sum(parts_i) - 100.0) > 3.0:  # снимок без CPU_ALL (неполный) не считаем
                bad += 1
        checks.append(["CPU_ALL: user+sys+wait+idle+steal ≈ 100%", "ok" if bad == 0 else f"{bad} снимков вне ±3%", bad == 0, True])
    aaa_cpus = host.meta.get("cpus", "")
    ncore = len(host.cpu_cores)
    c_all = host.col("CPU_ALL", "CPUs")
    ncpu_all = int(fmax(c_all)) if c_all is not None and fmax(c_all) == fmax(c_all) else None
    vals = {aaa_cpus or "?", str(ncore) if ncore else "?", str(ncpu_all) if ncpu_all else "?"} - {"?"}
    checks.append(["число CPU: AAA cpus / секций CPUnnn / CPU_ALL CPUs", f"{aaa_cpus} / {ncore} / {ncpu_all}", len(vals) <= 1, True])
    if host.cpu_cores and u is not None:
        busy = host.cpu_busy()
        cm = [NAN] * n
        for i in range(n):
            vs = []
            for core in host.cpu_cores:
                cu, cs = host.col(core, "User%")[i], host.col(core, "Sys%")[i]
                if cu == cu and cs == cs:
                    vs.append(cu + cs)
            cm[i] = sum(vs) / len(vs) if vs else NAN
        diff = fmean([abs(a - b) for a, b in zip(busy, cm) if a == a and b == b])
        checks.append(["среднее busy по CPUnnn ≈ CPU_ALL busy (средняя |разница|, п.п.)", f"{diff:.2f}", diff == diff and diff < 3, True])
    # VM ↔ DISK: без первых снимков файлов — T0001 охватывает неполный интервал; DISK* — скорость,
    # усреднённая за фактический интервал снимка, VM — приращение за него же: DISK × фактический шаг (_snap_dt, после
    # разрыва — его длительность), суммы — по одним и тем же снимкам
    hx = host.without_first()
    dts = _snap_dt(hx)
    for vm_col, dsec, label in (("pgpgout", "DISKWRITE", "VM pgpgout (KB/интервал) ≈ Σ DISKWRITE физических дисков × шаг снимка"),
                                ("pgpgin", "DISKREAD", "VM pgpgin ≈ Σ DISKREAD × шаг снимка")):
        pv = hx.col("VM", vm_col)
        dv = hx.disk_total(dsec)
        if pv is None or dv is None:
            continue
        if hx.firsts_kept:
            # кроме первых снимков файлов в выборке ничего нет: исключить T0001 нельзя, а по нему сверка ложная
            checks.append([f"{label} (отношение)", "мало данных (в выборке только первые снимки файлов — сверять нечего)",
                           True, True])
            continue
        name = f"{label} (отношение; без первых снимков файлов)"
        both = [(p, d * dt) for p, d, dt in zip(pv, dv, dts) if p == p and d == d]
        disk_kb = sum(x for _p, x in both)
        if disk_kb < 10 * 1024:
            checks.append([name, f"мало данных (Σ {dsec} × шаг < 10 MB)", True, True])
            continue
        ratio = round(sum(p for p, _x in both) / disk_kb, 3)  # с порогом сравнивается то же значение, что напечатано
        checks.append([name, f"{ratio:.3f}", 0.7 <= ratio <= 1.3, True])
    dw = host.disk_total("DISKWRITE")
    dr = host.disk_total("DISKREAD")
    # bond ≈ Σ собственных слейвов, rx и tx отдельно (состав — по ifconfig/MAC; подобранный по рядам не проверяется:
    # он выбран по тому же совпадению)
    nroles = host.net_roles()
    members = host._bond_members()
    bonds = [i for i in host.net_ifaces() if nroles.get(i) == "bond"]
    slaves = [i for i in host.net_ifaces() if nroles.get(i, "").startswith("bond-slave")]

    def net_sum(ifaces, d):
        v = [x for x in (fsum(host.col("NET", f"{i}-{d}-KB/s")) for i in ifaces) if x == x]
        return sum(v) if v else NAN

    def bond_rows(label, b_ifaces, s_ifaces, what="слейвов"):
        for lbl, d in (("rx", "read"), ("tx", "write")):
            bsum, ssum = net_sum(b_ifaces, d), net_sum(s_ifaces, d)
            if bsum == bsum and bsum > 0 and ssum == ssum and ssum > 0:
                ratio = round(ssum / bsum, 2)  # с порогом сравнивается то же значение, что напечатано
                checks.append([f"{label} {lbl} ≈ Σ {lbl} {what} (отношение)", f"{ratio:.2f}", 0.8 <= ratio <= 1.2, True])

    if len(bonds) > 1 and any(not any(s in m for m in members.values()) for s in slaves):
        bond_rows("Σ всех bond", bonds, slaves, "всех слейвов; принадлежность части слейвов не определена")
    for bond in bonds:
        if not members.get(bond):
            continue
        if host._bond_src.get(bond) == "трафик":
            checks.append([f"{bond} rx/tx ≈ Σ слейвов", "не применимо (слейвы определены по трафику)", True, False])
        else:
            bond_rows(bond, [bond], members[bond])
    xf = host.disk_total("DISKXFER")
    if xf is not None and dw is not None and dr is not None:
        bs_calc = (fsum(dw) + fsum(dr)) / fsum(xf) if fsum(xf) > 0 else NAN
        checks.append(["средний размер IO по (read+write)/IOPS, KB", f"{bs_calc:.1f}", True, True])
    mt = host.col("MEM", "memtotal")
    if mt is not None and clean(mt):
        checks.append(["MEM memtotal постоянен", "да" if fmin(mt) == fmax(mt) else f"нет: {fmin(mt):.0f}..{fmax(mt):.0f} MB", fmin(mt) == fmax(mt), True])
    mi = host.meminfo()
    if mi.get("MemTotal") and mt is not None:
        ratio = fmax(mt) * 1024.0 / mi["MemTotal"]
        checks.append(["MEM memtotal ≈ /proc/meminfo MemTotal", f"{ratio:.3f}", 0.97 <= ratio <= 1.03, True])
    # Размер страницы (для VM nr_* и slab в avail): PageTables из meminfo ≈ nr_page_table_pages первого снимка × страница
    pk, psrc = host.page_size_info()
    pt_kb = mi.get("PageTables")
    pt_pages = host.files[0].first_value("VM", "nr_page_table_pages") if host.files else NAN
    if pt_kb and pt_pages == pt_pages and pt_pages > 0:
        ratio = round(pt_kb / (pt_pages * pk), 3)
        checks.append([f"размер страницы {pk:g} KB ({psrc}): PageTables (meminfo) ≈ nr_page_table_pages × страница (отношение)",
                       f"{ratio:.3f}", 0.9 <= ratio <= 1.1, True])
    elif host.has("VM"):
        checks.append([f"размер страницы, KB ({psrc}; сверка с PageTables недоступна)", f"{pk:g}", True, True])
    top_n = sum(1 for x in host.top if x)
    if top_n:
        # TOP нет в первом снимке каждого файла/запуска (T0001) и может не быть в неполном последнем снимке
        expect_gap = len(host.first_snapshot_indices()) + sum(
            1 for t, src in zip(host.snap_ids, host.snap_src) if t in host.files[src].incomplete)
        checks.append(["снимков с данными TOP", f"{top_n} из {n}", top_n >= n - max(1, expect_gap), True])
        sizes = [len(x) for x in host.top if x]
        checks.append(["процессов в снимке TOP: min / median / max", f"{min(sizes)} / {fmedian(sizes):.0f} / {max(sizes)}", True, True])
    # TOP MajorFault vs VM pgmajfault: известная особенность учёта faults процессов — на вердикт не влияет
    fa = _fault_accounting(host)
    if fa["status"] != "n/a":
        mr = fa["major_ratio"]
        mr_s = "∞ (VM pgmajfault = 0)" if mr == math.inf else (f"{mr:.1f}" if mr == mr else "0 / 0")
        name = "Σ TOP MajorFault (/s × шаг снимка) vs VM pgmajfault (отношение; ≫ 1 = колонка TOP не равна чтениям с диска)"
        if fa["status"] == "retry":
            checks.append([name, f"{mr_s} — MajorFault в TOP включает faults, завершённые после повтора (не чтения с диска); "
                                 f"согласуется с pgfault", True, False])
        elif fa["status"] == "mismatch":
            checks.append([name, mr_s, False, False])
            issues.append(("INFO", "колонка TOP MajorFault в этом файле ненадёжна; для major faults используйте vm.pgmajfault"))
        elif fa["status"] == "unverified":
            checks.append([name, f"{mr_s} — сверить с VM pgfault нельзя (колонки нет или она всегда 0)", False, False])
            issues.append(("INFO", "колонка TOP MajorFault ≫ VM pgmajfault, а сверка с VM pgfault невозможна: смысл колонки "
                                   "не установлен; о чтениях с диска судите по vm.pgmajfault"))
        else:
            checks.append([name, mr_s, True, False])
        if fa["r1"] == fa["r1"]:
            checks.append(["Σ TOP faults (Minor+Major / Minor+2·Major) vs VM pgfault (отношение)",
                           f"{fa['r1']:.3f} / {fa['r2']:.3f}", any(0.85 <= r <= 1.1 for r in (fa["r1"], fa["r2"])), False])
    # оценка avail vs MemAvailable: разница — резервы ядра (watermarks), постоянна в MB, поэтому сравнивается разность
    # в % RAM, а не отношение (при малом avail тот же резерв даёт большое отношение)
    ref = host.mem_avail_anchor()
    ram_mb = mi["MemTotal"] / 1024.0 if mi.get("MemTotal") else (fmax(mt) if mt is not None else NAN)
    if mi.get("MemAvailable") is not None:
        name = "оценка avail в снимке рядом с BBBP − MemAvailable ядра на старте (−1…10% RAM)"
        if ref and ram_mb == ram_mb and ram_mb > 0:
            d = ref["est"] - ref["memavail"]
            pct = round(100.0 * d / ram_mb, 1)  # с порогом сравнивается то же значение, что напечатано
            ratio = f"{ref['est'] / ref['memavail']:.2f}" if ref["memavail"] > 0 else "-"
            checks.append([name, f"разница {d:.0f} MB ({pct:.1f}% RAM; снимок {ref['snap']}); отношение {ratio}",
                           -1.0 <= pct <= 10.0, True])
        else:
            checks.append([name, f"сверка недоступна: {host.mem_avail_reason() or 'нет данных MEM'}", True, False])
    for a, b_, ok, verdict in checks:
        if not ok and verdict:
            issues.append(("WARN", f"перекрёстная проверка не пройдена: {a} = {b_}"))
    if checks:
        rep.table("Перекрёстные проверки", ["проверка", "результат", "ok"],
                  [[a, b_, "да" if ok else ("НЕТ" if verdict else "нет (инфо)")] for a, b_, ok, verdict in checks],
                  note="«нет (инфо)» — расхождение с известной причиной, на вердикт не влияет"
                  if any(not ok and not verdict for _, _, ok, verdict in checks) else None)
    # «Мёртвые» колонки (всегда 0 или всегда N/A)
    dead = []
    for sec in sorted(host.series):
        if re.match(r"^CPU\d+$", sec):
            continue
        zeros, na = [], []
        for c in host.cols(sec):
            arr = host.series[sec][c]
            cl = clean(arr)
            if not cl:
                na.append(c)
            elif all(v == 0 for v in cl):
                # -0.0 во всех снимках — метка nmon «не поддерживается» (MEM high*/low*), а не нулевая активность
                (na if all(math.copysign(1.0, v) < 0 for v in cl) else zeros).append(c)
            elif all(v < 0 for v in cl):
                na.append(c)
        if zeros or na:
            dead.append([sec, zeros, na])
    if dead:
        rep.table("Колонки без информации за период (всегда 0 / всегда N/A)", ["секция", "всегда 0", "N/A (-1, -0.0 или пусто)"], dead,
                  prec={"всегда 0": "list", "N/A (-1, -0.0 или пусто)": "list"},
                  note="0 в VM для kswapd_steal/allocstall/pgscan_*/pgsteal_*/pgrefill_* на современных ядрах — норма (счётчики "
                       "переименованы в разных версиях ядра, см. vm), "
                       "не признак отсутствия активности; -1 в PROC (syscall/read/write/exec/sem/msg) — nmon для Linux их не собирает; "
                       f"в text/md списки усечены до {LIST_CELL_MAX} имён, полные — в --format json")
    sev_rank = {"CRIT": 0, "WARN": 1, "INFO": 2}
    issues.sort(key=lambda x: sev_rank.get(x[0], 9))
    verdict = "непригодны" if any(s == "CRIT" for s, _ in issues) or n < 3 or not host.has("CPU_ALL") else \
        ("пригодны с оговорками" if any(s == "WARN" for s, _ in issues) else "пригодны")
    rep.kv("Вердикт", [("данные", verdict), ("снимков", n), ("период", f"{ts(host.start())} .. {ts(host.end())}")])
    # таблица (попадает и в csv); --no-info/--min-severity фильтруют только показ, вердикт — по всем замечаниям
    shown = issues
    if not _opt(args, "show_info", True):
        shown = [x for x in shown if x[0] != "INFO"]
    if _opt(args, "min_severity", None):
        lim = SEV_ORDER.get(args.min_severity.upper(), 9)
        shown = [x for x in shown if SEV_ORDER.get(x[0], 9) <= lim]
    if issues and not shown:
        rep.text("Замечания", f"нет (скрыто фильтром --no-info/--min-severity: {len(issues)}; вердикт — по всем замечаниям)")
    elif issues:
        rep.table("Замечания", ["severity", "замечание"], [list(x) for x in shown],
                  note=f"показано {len(shown)} из {len(issues)} замечаний (--no-info/--min-severity); вердикт — по всем "
                       f"замечаниям" if len(shown) != len(issues) else None)
    else:
        rep.text("Замечания", "нет")
    return rep


def _parse_window(spec, host=None, ref=None, end=None):
    """'HH:MM-HH:MM' или 'A..B' (любой формат времени) -> (datetime, datetime).
    Начало разрешается resolve_user_time по периоду данных ref..end (по умолчанию — период host; main передаёт
    период всех хостов). Конец без даты берётся на дату начала, а если он раньше начала — на следующий день (только
    если данные продолжаются в следующие сутки); конец только датой — конец этого дня; конец раньше начала — ValueError."""
    if ref is None and host is not None and host.times:
        ref, end = host.times[0], host.times[-1]
    if ".." in spec:
        a, b = spec.split("..", 1)
    else:
        m = re.match(r"^\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*-\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*$", spec)
        if not m:
            raise UserError(f"окно {spec!r}: ожидается 'HH:MM-HH:MM' или 'начало..конец'")
        a, b = m.group(1), m.group(2)
    ta = resolve_user_time(a, ref, end)
    if user_time_kind(b) == "time":
        tb = parse_user_time(b, ta)
        if tb < ta and end is not None and end.date() > ta.date():
            tb += timedelta(days=1)  # окно через полночь (23:50-00:20)
    else:
        tb = resolve_user_time(b, ref, end, upper=True)
    if tb < ta:
        raise UserError(f"окно {spec!r}: конец ({ts(tb)}) раньше начала ({ts(ta)})")
    return ta, tb


def _compare_windows(host, args):
    """Окна A и B команды compare -> ((ta, tb), (tc, td), ha, hb): срезы ряда без первого снимка каждого файла/запуска
    (T0001: неполный интервал — ложные max и средние), как в остальной статистике рядов; ошибки окна — SystemExit."""
    try:
        wa = getattr(args, "window_a", None) or _parse_window(_opt(args, "a", None), host)
        wb = getattr(args, "window_b", None) or _parse_window(_opt(args, "b", None), host)
    except UserError as e:
        raise SystemExit(f"ERROR: {e}")
    base = host.without_first()
    ha, hb = base.slice([wa[0] <= t <= wa[1] for t in base.times]), base.slice([wb[0] <= t <= wb[1] for t in base.times])
    ha.firsts_kept = hb.firsts_kept = base.firsts_kept  # T0001 не исключён (других снимков нет) — для _t1_note
    return wa, wb, ha, hb


def check_compare_windows(hosts, args):
    """compare: окно без снимков ни у одного хоста — ERROR с окном и периодами данных; только у части — WARN
    (их отчёт — «в одном из окон нет снимков»)."""
    res = [(h, _compare_windows(h, args)) for h in hosts]
    for k, name in ((2, "A"), (3, "B")):
        empty = [h for h, r in res if r[k].n() == 0]
        if not empty:
            continue
        w = res[0][1][k - 2]
        periods = ", ".join(f"{h.name} {ts(h.start())} .. {ts(h.end())}" for h in empty)
        if len(empty) == len(res):
            raise SystemExit(f"ERROR: compare: в окне {name} нет снимков (без первых снимков файлов) ни у одного хоста: "
                             f"окно {ts(w[0])} .. {ts(w[1])}; данные: {periods}")
        warn(f"compare: в окне {name} ({ts(w[0])} .. {ts(w[1])}) нет снимков у хостов: {periods}")


def analyze_compare(host, args=None):
    """Сравнение двух окон времени (например, до инцидента и во время) по набору метрик."""
    rep = Report("Сравнение двух окон времени", host.name)
    if not host.times:
        rep.text("", "нет снимков")
        return rep
    spec_a, spec_b = _opt(args, "a", None), _opt(args, "b", None)
    if not spec_a or not spec_b:
        rep.text("", "укажите --a 'HH:MM-HH:MM' и --b 'HH:MM-HH:MM' (или 'YYYY-MM-DD HH:MM..YYYY-MM-DD HH:MM')")
        return rep
    (ta, tb), (tc, td), ha, hb = _compare_windows(host, args)
    rep.kv("Окна", [("A", f"{ts(ta)} .. {ts(tb)} ({ha.n()} снимков)"), ("B", f"{ts(tc)} .. {ts(td)} ({hb.n()} снимков)")],
           note=_t1_note(ha, "снимки окон — без первого снимка каждого файла/запуска nmon (T0001: неполный интервал)"))
    if ha.n() == 0 or hb.n() == 0:
        rep.text("", "в одном из окон нет снимков")
        return rep
    metrics = _opt(args, "metrics", None) or DEFAULT_TIMELINE + ["vm.pgmajfault", "mem.used", "top.java.sys", "cpu.core_max"]
    floors = event_min_abs(host)  # практический порог изменения: ½ минимального отклонения events
    rows = []
    for m, ra in resolve_metrics(ha, metrics, warn_missing=bool(_opt(args, "metrics", None))):
        rb = resolve_metric(hb, m)
        if not rb or not clean(ra[2]) or not clean(rb[2]):
            continue
        ma, mb = fmean(ra[2]), fmean(rb[2])
        pa, pb = percentile(ra[2], 95), percentile(rb[2], 95)
        d_mean = 100.0 * (mb - ma) / abs(ma) if ma == ma and ma != 0 else NAN
        d_p95 = 100.0 * (pb - pa) / abs(pa) if pa == pa and pa != 0 else NAN
        rows.append([m, ra[1], ma, pa, fmax(ra[2]), mb, pb, fmax(rb[2]), mb - ma, d_mean, d_p95,
                     True if ma == 0 and mb != 0 else None])

    def strength(r):
        # сначала изменения не меньше практического порога (½ минимального отклонения events; для метрик без него —
        # ½ от EVENT_REL_FLOOR·|A|), затем по симметричному относительному изменению 200·|B − A|/(|A| + |B|): рост
        # с нуля даёт 200 %, шум около нуля не раздувается
        d, s = abs(r[8]), abs(r[2]) + abs(r[5])
        floor = 0.5 * (floors[r[0]] if r[0] in floors else EVENT_REL_FLOOR * abs(r[2]))
        return (d > 0 and d >= floor, 200.0 * d / s if s > 0 else 0.0)

    rows.sort(key=strength, reverse=True)
    rep.table("Метрики: A vs B", ["метрика", "ед.", "A avg", "A p95", "A max", "B avg", "B p95", "B max", "Δ abs", "Δavg %",
                                  "Δp95 %", "рост с нуля"], rows,
              prec={"Δavg %": 0, "Δp95 %": 0, "A avg": 1, "B avg": 1},
              note=f"сначала изменения больше практического порога (½ минимального отклонения events: например, 5 п.п. для "
                   f"cpu.busy; для метрик без него — {EVENT_REL_FLOOR / 2:.1%} от A avg), затем по симметричному относительному "
                   f"изменению 200·|B − A| / (|A| + |B|); Δ abs = B avg − A avg, Δ % = (B − A) / |A|; «рост с нуля» — "
                   f"A avg = 0 (Δavg % не определён); " + _t1_note(ha, "без первых снимков файлов (T0001, неполный интервал)"))
    # процессы: кто появился/вырос
    if any(ha.top) and any(hb.top):
        def agg(h):
            d = defaultdict(float)
            cnt = defaultdict(set)
            n_top = sum(1 for x in h.top if x)
            for i, procs in enumerate(h.top):
                for p in procs:
                    if p.cpu == p.cpu:
                        d[p.cmd] += p.cpu
                        cnt[p.cmd].add(i)
            return {k: v / max(1, n_top) for k, v in d.items()}, {k: len(v) for k, v in cnt.items()}, n_top
        pa_, ca, na_ = agg(ha)
        pb_, cb, nb_ = agg(hb)
        prow = []
        for cmd in set(pa_) | set(pb_):
            a_, b_ = pa_.get(cmd, 0.0), pb_.get(cmd, 0.0)
            if max(a_, b_) >= 1.0:
                prow.append([cmd, a_, ca.get(cmd, 0), b_, cb.get(cmd, 0), b_ - a_])
        prow.sort(key=lambda r: -abs(r[5]))
        rep.table("Процессы: средний %CPU по окну (отсутствие в TOP = 0)", ["команда", "A avg%", "A снимков", "B avg%", "B снимков", "Δ п.п."],
                  prow[:_opt(args, "top", 15) or 15], total=len(prow), prec={"A снимков": 0, "B снимков": 0},
                  note=f"среднее делится на число снимков с TOP в окне (A: {na_}, B: {nb_}); «снимков» — в скольких из них процесс попал в TOP")
    return rep


QUESTIONS = [
    ("Что за файл: хост, период, интервал, версия nmon, есть ли TOP/UARG, разрывы?", "info"),
    ("Можно ли доверять данным: разрывы, дрожание интервала, «мёртвые» колонки, перекрёстные проверки, вердикт?", "check, health (DATA_QUALITY)"),
    ("Перезагружался ли узел между файлами/запусками nmon или во время наблюдения? Обрезан ли файл?", "info, check, health (BOOT_RECENT, NMON_COVERAGE_GAP)"),
    ("Какие секции и колонки есть в файле?", "sections"),
    ("Общая картина: что не так с узлом? С чего начать?", "report (затем health, events)"),
    ("Есть ли проблемы по порогам (CPU, память, swap, диски, ФС, java)?", "health [--thr CODE=WARN,CRIT]"),
    ("Насколько загружен CPU, сколько времени выше 80/90%, когда пики, user vs sys vs iowait vs steal?", "cpu"),
    ("Есть ли «горячее» одно ядро (однопоточное узкое место), когда и сколько длилось? Дисбаланс ядер? NUMA/HT, softirq?",
     "cpu (эпизоды горячего ядра), cores [--sort max], health (CPU_HOT_CORE, CPU_HOT_CORE_RUN)"),
    ("Были ли короткие эпизоды насыщения CPU или очереди Runnable, которые не видны в p95 за период?",
     "health (CPU_SATURATION_RUN, RUNQ_RUN), cpu (эпизоды), proc (пики Runnable)"),
    ("Есть ли CPU steal (виртуализация)?", "cpu, health (CPU_STEAL)"),
    ("Длина очереди на CPU, число заблокированных (D-state) процессов, переключения контекста?", "proc"),
    ("Сколько памяти использовано/свободно/в page cache, минимум доступной памяти, тренд роста, до исчерпания?", "mem"),
    ("Был ли swap, reclaim (kswapd/direct), major faults, грязные страницы?", "vm, health"),
    ("Какие hugepages/THP/overcommit настройки, близко ли Committed_AS к CommitLimit (meminfo на старте)?",
     "mem, health (OVERCOMMIT, COMMIT_LIMIT), bbbp --block /proc/meminfo"),
    ("Как загружены диски: busy, IOPS, throughput, размер IO, время > 80%, пики, периодичность всплесков?", "disk [--all] [--dev nvme0n1]"),
    ("Какой диск за какой точкой монтирования (WAL, persistence, логи)? LVM-карта, df, fstab?", "diskmap"),
    ("Заполненность файловых систем, рост, когда заполнится, скачки?", "fs [--mount '/opt/ignite.*']"),
    ("Сетевой трафик по интерфейсам, пакеты, размер пакета, MTU, ошибки, простои интерфейса, пики?", "net [--link-mbit 10000]"),
    ("Пропадал или проваливался трафик узла (изоляция), отказывал ли слейв bond?", "net, health (NET_ZERO, NET_DROP, NET_BOND_MEMBER)"),
    ("Какие процессы потребляли CPU/память, их RSS/threads/faults, перезапуски?", "top [--cmd java] [--sort rss]"),
    ("Как вёл себя процесс java (Ignite): CPU, sys-доля, RSS, потоки, паузы, перезапуски, конкуренты?", "java"),
    ("Перезапускалась, исчезла до конца данных или стартовала во время записи JVM?", "java, health (JAVA_RESTART, JAVA_GONE, JAVA_START)"),
    ("Какие параметры JVM (Xmx, GC, MaxDirectMemorySize)? Нужен nmon -T.", "uarg"),
    ("Что происходило в момент времени X (все метрики, процессы, диски, сеть)?", "at --time 'HH:MM' [--window-snaps 2]"),
    ("Временной ряд выбранных метрик (для графика/таблицы), с агрегацией по шагу?", "timeline [--metrics ...] [--step 5m --agg max]"),
    ("Когда были выбросы/аномалии и по каким метрикам одновременно?", "events [--z 4]"),
    ("Какие метрики связаны между собой (диск ↔ iowait, сеть ↔ sys)?", "correlate [--target cpu.wait]"),
    ("Сравнить узлы кластера: кто выбивается, синхронные события, дрейф конфигурации, покрытие?", "cluster [--sort cpu.busy:p95]"),
    ("Выгрузить данные секции/метрик в CSV/JSON для собственного анализа?", "export --section DISKWRITE --format csv"),
    ("Посмотреть сырой вывод lscpu/df/mount/ifconfig/meminfo и т.п.?", "bbbp --block lscpu | --grep regex"),
    ("Какие имена метрик доступны для timeline/events/correlate/export?", "metrics"),
    ("Что изменилось между «до инцидента» и «во время» (два окна времени)?", "compare --a 02:00-02:30 --b 03:00-03:30"),
    ("Есть ли сигнатуры Ignite: периодические checkpoint-всплески, I/O-stall, fsync-heavy диск, перезапуск JVM?", "health (коды CHECKPOINT_PERIOD, IO_STALL, DISK_SMALL_IO, JAVA_RESTART)"),
    ("Как сопоставить время nmon (локальное время хоста) с логами в UTC?", "любая команда с --tz-shift=-3h (сдвиг всех меток; отрицательное значение — через '=')"),
]


def analyze_questions(hosts=None, args=None):
    rep = Report("Вопрос → команда")
    rep.table("Индекс", ["вопрос", "команда"], [[q, c] for q, c in QUESTIONS])
    rep.text("Общие опции", "--from/--to 'YYYY-MM-DD HH:MM' или 'HH:MM'; --around 'HH:MM' --window 10m; --host regex; "
                            "--format text|md|json|csv; --top N; --output file; --no-merge; --thr CODE=WARN[,CRIT]; --link-mbit N; "
                            "--no-info; --min-severity CRIT|WARN|INFO; --skip-first; --tz-shift=±D; -v")
    return rep


def _top_presence(host, targets):
    """target -> число снимков, где в TOP есть процесс с именем, начинающимся с target (как у top.<cmd>.*), — один
    проход по TOP для всех имён."""
    targets = set(targets)
    lens = sorted({len(t) for t in targets})
    out = dict.fromkeys(targets, 0)
    for procs in host.top:
        hit = set()
        for cmd in {p.cmd for p in procs}:
            for k in lens:
                if k > len(cmd):
                    break
                if cmd[:k] in targets:
                    hit.add(cmd[:k])
        for t in hit:
            out[t] += 1
    return out


def analyze_metrics_list(host, args=None):
    rep = Report("Доступные метрики", host.name)
    names = list_metrics(host)
    target = lambda nm: ".".join(nm.split(".")[1:-1])  # noqa: E731  top.<target>.<поле>
    tops = {nm for nm in names if nm.startswith("top.") and nm != "top.sum_cpu"}
    pres = _top_presence(host, {target(nm) for nm in tops})
    rows = []
    for name in names:
        r = resolve_metric(host, name)
        if r:
            rows.append([name, r[1], BASE_METRICS[name][0] if name in BASE_METRICS else r[0], len(clean(r[2])),
                         pres[target(name)] if name in tops else None])
    rep.table("Метрики", ["имя", "ед.", "описание", "значений", "снимков в TOP"], rows, prec={"снимков в TOP": 0},
              note="значений — снимков с числом (у top.*.cpu|usr|sys|majflt|minflt снимок TOP без процесса = 0, поэтому это "
                   "все снимки с TOP); снимков в TOP — сколько раз процесс действительно был в TOP; "
                   "шаблоны: disk.<dev>.busy|read|write|iops|xfer|bsize|rserv|wserv, "
                   "net.<if>.read|write|pkt_in|pkt_out|rx_size|tx_size, fs.<mount>.pct|inode, "
                   "cpu.core<N>.busy|user|sys|wait|idle|steal, "
                   "top.<cmd>|pid<PID>|<группа со *>.cpu|usr|sys|rss|vsz|threads|majflt|minflt|iowait, raw.<SECTION>.<column>")
    return rep


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

PER_HOST_COMMANDS = {
    "info": (analyze_info, "метаданные файла/хоста, качество данных, конфигурация"),
    "sections": (analyze_sections, "секции и колонки, найденные в файле"),
    "report": (analyze_report, "сводный отчёт: ключевые показатели + health + краткий таймлайн"),
    "health": (analyze_health, "только проверки по порогам (CRIT/WARN/INFO)"),
    "cpu": (analyze_cpu, "загрузка CPU: сводка, пороги, пики, ядра"),
    "cores": (analyze_cores, "таблица по каждому логическому CPU"),
    "proc": (analyze_proc, "очередь Runnable, Blocked, context switches"),
    "mem": (analyze_mem, "память: сводка, тренды, минимум, meminfo"),
    "vm": (analyze_vm, "подкачка/reclaim/page faults/dirty (VM)"),
    "disk": (analyze_disk, "диски: busy, throughput, IOPS, пики, периодичность"),
    "diskmap": (analyze_diskmap, "карта устройство → LVM → mount → fs"),
    "fs": (analyze_fs, "файловые системы: заполненность и рост"),
    "net": (analyze_net, "сеть: интерфейсы, трафик, пакеты, простои, ошибки"),
    "top": (analyze_top, "процессы из TOP: сводка, перезапуски"),
    "java": (analyze_java, "процесс(ы) java/Ignite подробно"),
    "uarg": (analyze_uarg, "командные строки и JVM-флаги (нужен nmon -T)"),
    "at": (analyze_at, "срез всех метрик в момент времени"),
    "timeline": (analyze_timeline, "временной ряд метрик (с агрегацией)"),
    "events": (analyze_events, "выбросы/аномалии по времени"),
    "correlate": (analyze_correlate, "корреляции между метриками"),
    "export": (analyze_export, "выгрузка секции/метрик (csv/json)"),
    "bbbp": (analyze_bbbp, "сырые конфигурационные блоки BBBP"),
    "metrics": (analyze_metrics_list, "список доступных имён метрик"),
    "check": (analyze_check, "качество данных: разрывы, интервал, мёртвые колонки, перекрёстные проверки"),
    "compare": (analyze_compare, "сравнение двух окон времени (--a, --b)"),
}
CLUSTER_COMMANDS = {
    "cluster": (analyze_cluster, "сравнение хостов, выбросы, синхронные события"),
}


EXIT_ERROR = 3  # код возврата при ошибке данных/аргументов (0/1/2 — результат health/report/cluster)


class ArgParser(argparse.ArgumentParser):
    """argparse с кодом 3 при ошибке синтаксиса (по умолчанию 2 — совпадает с «есть CRIT»)."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def _thr_value(s, item):
    """Порог из --thr: любое число float ('5', '.5', '1e12'); не число или NaN — ERROR."""
    try:
        v = float(s)
    except ValueError:
        v = NAN
    if v != v:
        raise SystemExit(f"ERROR: --thr {item!r}: порог должен быть числом (CODE=WARN[,CRIT])")
    return v


# правила без числового порога (информационные или по факту события): --thr для них принимается, но не действует
# (JAVA_START берёт порог WARN правила JAVA_GONE)
THR_UNUSED = {"JAVA_RESTART", "JAVA_START", "THP_ACTIVE", "NO_SWAP", "CHECKPOINT_PERIOD", "THP_COMPACTION"}


def _parse_thr(items):
    out = {}
    for it in items or []:
        m = re.match(r"^([A-Za-z_]+)=([^,]+)(?:,([^,]+))?$", it.strip())
        if not m:
            raise SystemExit(f"ERROR: --thr ожидает CODE=WARN[,CRIT], получено {it!r}")
        code = m.group(1).upper()
        if code not in DEFAULT_THRESHOLDS:
            raise SystemExit(f"ERROR: неизвестный код правила {code}; известные: {', '.join(sorted(DEFAULT_THRESHOLDS))}")
        wv, cv = _thr_value(m.group(2), it), _thr_value(m.group(3), it) if m.group(3) else None
        if code in THR_UNUSED:
            warn(f"--thr {code}: у правила нет числового порога — значение не используется"
                 + (" (JAVA_START управляется порогом WARN правила JAVA_GONE)" if code == "JAVA_START" else ""))
        elif cv is not None:
            d = DEFAULT_THRESHOLDS[code]
            if (cv < wv) if d[2] >= d[1] else (cv > wv):  # CRIT должен быть не «мягче» WARN
                raise SystemExit(f"ERROR: --thr {it!r}: CRIT {cv:g} мягче WARN {wv:g} — для {code} "
                                 + ("CRIT ≥ WARN (больше — хуже)" if d[2] >= d[1] else "CRIT ≤ WARN (меньше — хуже)"))
        out[code] = (wv, cv)
    return out


def _int_arg(lo):
    """Тип argparse: целое ≥ lo (иначе ошибка синтаксиса с кодом 3)."""
    def conv(s):
        try:
            v = int(s)
        except ValueError:
            raise argparse.ArgumentTypeError(f"ожидается целое число, получено {s!r}")
        if v < lo:
            raise argparse.ArgumentTypeError(f"ожидается целое число ≥ {lo}, получено {v}")
        return v
    return conv


def _pos_float(s):
    """Тип argparse: конечное число > 0."""
    try:
        v = float(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"ожидается число, получено {s!r}")
    if not 0 < v < math.inf:
        raise argparse.ArgumentTypeError(f"ожидается число > 0, получено {s!r}")
    return v


def build_parser():
    p = ArgParser(
        prog="nmon_analyzer.py",
        description="Анализ файлов nmon (Linux) для разбора работы узлов Apache Ignite. "
                    "Команда `questions` показывает, какой командой отвечать на какой вопрос.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Примеры:\n"
               "  python3 nmon_analyzer.py report node01.nmon\n"
               "  python3 nmon_analyzer.py cluster /path/to/nmon/ --format md\n"
               "  python3 nmon_analyzer.py at --time 03:52 --host node07 *.nmon\n"
               "  python3 nmon_analyzer.py timeline node01.nmon --metrics cpu.busy disk.write --step 5m --agg max\n"
               "  python3 nmon_analyzer.py disk --dev nvme0n1 --from 03:30 --to 04:10 node01.nmon --format json\n"
               "Пути ставьте до списковых опций --metrics/--columns. Полное описание — NMON_ANALYZER.md.\n")
    p.add_argument("--version", action="version", version=f"nmon_analyzer {VERSION}")
    sub = p.add_subparsers(dest="command", metavar="команда")
    sub.required = True

    def common(sp):
        sp.add_argument("paths", nargs="*", help="файлы .nmon, каталоги (рекурсивно) или маски")
        sp.add_argument("--host", action="append", help="фильтр хостов (regex, можно несколько)")
        sp.add_argument("--from", dest="t_from", help="начало окна: 'YYYY-MM-DD HH:MM[:SS]' или 'HH:MM'")
        sp.add_argument("--to", dest="t_to", help="конец окна")
        sp.add_argument("--around", help="центр окна ('HH:MM' или полная дата-время), см. --window")
        sp.add_argument("--window", default="10m", help="полуширина окна для --around (по умолчанию 10m)")
        sp.add_argument("--format", choices=["text", "md", "json", "csv"], default="text", help="формат вывода")
        sp.add_argument("--output", "-o", help="записать вывод в файл")
        sp.add_argument("--top", type=_int_arg(1), help="сколько строк/пиков показывать (по умолчанию зависит от команды)")
        sp.add_argument("--no-merge", action="store_true", help="не объединять файлы одного хоста")
        sp.add_argument("--thr", action="append", help="переопределить порог: CODE=WARN[,CRIT] (см. health)")
        sp.add_argument("--link-mbit", type=_pos_float, dest="link_mbit", help="скорость одного физического порта, Mbit/s (загрузка nic и слейвов bond; bond — порт × число RUNNING-слейвов, bond с одним активным слейвом — один порт)")
        sp.add_argument("--no-info", action="store_true", help="не показывать INFO-замечания (только вывод; код возврата — по всем)")
        sp.add_argument("--min-severity", dest="min_severity", choices=["CRIT", "WARN", "INFO"], help="показывать замечания не ниже уровня (только вывод; код возврата — по всем)")
        sp.add_argument("--skip-first", dest="skip_first", action="store_true", help="отбросить первый снимок каждого файла и каждого запуска nmon в файле (неполный интервал)")
        sp.add_argument("--tz-shift", dest="tz_shift", help="сдвинуть все метки времени, например -3h или +02:00 (для сопоставления с логами в другой зоне)")
        sp.add_argument("--verbose", "-v", action="store_true", help="печатать ход разбора в stderr")

    for name, (fn, help_) in {**PER_HOST_COMMANDS, **CLUSTER_COMMANDS}.items():
        sp = sub.add_parser(name, help=help_, description=help_)
        common(sp)
        if name in ("disk",):
            sp.add_argument("--dev", action="append", help="устройство (regex, полное совпадение), можно несколько; работает и по имени LV")
            sp.add_argument("--all", action="store_true", help="включая разделы и dm-*")
        if name == "fs":
            sp.add_argument("--mount", action="append", help="точка монтирования (regex, полное совпадение, например '/opt.*'), можно несколько")
        if name == "net":
            sp.add_argument("--iface", action="append", help="интерфейс (regex, полное совпадение, например 'bond.*'), можно несколько")
            sp.add_argument("--all", action="store_true", help="включая интерфейсы без трафика")
        if name == "cores":
            sp.add_argument("--sort", choices=["avg", "p95", "max", "sys", "wait"], default="p95")
        if name == "top":
            sp.add_argument("--pid", type=int, action="append", help="только указанные PID")
            sp.add_argument("--cmd", action="append", help="только команды по regex")
            sp.add_argument("--by-cmd", dest="by_cmd", action="store_true",
                            help="группировать по команде: суммы по всем PID в снимке (kworker — по задаче, потоки ядра по CPU — вместе)")
            sp.add_argument("--sort", choices=["cpu", "cpuavg", "cpumax", "rss", "threads", "majflt", "sys", "snapshots"], default="cpu",
                            help="cpu — среднее за весь период (снимок без процесса = 0), cpuavg — среднее по снимкам присутствия")
        if name == "uarg":
            sp.add_argument("--cmd", action="append", help="фильтр по regex (prog или командная строка)")
            sp.add_argument("--full", action="store_true", help="полные командные строки без обрезки")
        if name == "at":
            sp.add_argument("--time", help="момент времени ('HH:MM[:SS]' или 'YYYY-MM-DD HH:MM'); по умолчанию — пик CPU")
            sp.add_argument("--window-snaps", dest="window_snaps", type=_int_arg(0), default=2, help="снимков до/после (по умолчанию 2)")
            sp.add_argument("--metrics", nargs="+", help="какие метрики показать (см. metrics)")
        if name in ("timeline", "export"):
            sp.add_argument("--metrics", nargs="+", help="имена метрик (см. metrics)")
            sp.add_argument("--step", help="шаг агрегации: 5m, 1h ...")
            sp.add_argument("--agg", choices=["mean", "max", "min", "sum", "last"], default="mean")
            sp.add_argument("--limit", type=_int_arg(0), help="максимум строк (0 — без ограничения)")
        if name == "export":
            sp.add_argument("--section", help="секция nmon (CPU_ALL, MEM, DISKWRITE, TOP, UARG ...) вместо метрик")
            sp.add_argument("--columns", nargs="+", help="фильтр колонок секции (regex, полное совпадение)")
        if name == "events":
            sp.add_argument("--metrics", nargs="+", help="какие метрики проверять")
            sp.add_argument("--z", type=_pos_float, default=4.0, help="порог робастного z (по умолчанию 4)")
            sp.add_argument("--window-snaps", dest="window_snaps", type=_int_arg(1), default=15, help="окно скользящей медианы, снимков")
            sp.add_argument("--limit", type=_int_arg(1), default=200)
        if name == "correlate":
            sp.add_argument("--metrics", nargs="+")
            sp.add_argument("--target", help="считать корреляции только с этой метрикой")
            sp.add_argument("--limit", type=_int_arg(1), default=40)
        if name == "bbbp":
            sp.add_argument("--block", action="append", help="имя блока (regex): lscpu, /proc/meminfo, /bin/df-m, /bin/mount, ifconfig ...")
            sp.add_argument("--grep", help="regex по строкам всех блоков")
            sp.add_argument("--limit", type=_int_arg(0), default=400, help="максимум строк блока (0 — без ограничения)")
        if name == "compare":
            sp.add_argument("--a", help="окно A: 'HH:MM-HH:MM' или 'начало..конец'")
            sp.add_argument("--b", help="окно B: 'HH:MM-HH:MM' или 'начало..конец'")
            sp.add_argument("--metrics", nargs="+", help="имена метрик (см. metrics)")
        if name == "cluster":
            sp.add_argument("--sort", help="колонка сортировки, например cpu.busy:p95")
            sp.add_argument("--metrics", nargs="+", help="метрики для поиска синхронных выбросов")
            sp.add_argument("--z", type=_pos_float, default=4.0)
    sq = sub.add_parser("questions", help="индекс: какой вопрос какой командой решается")
    sq.add_argument("--format", choices=["text", "md", "json", "csv"], default="text")
    sq.add_argument("--output", "-o")
    return p


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "questions":
        emit([analyze_questions()], args)
        return 0
    # Списковые опции (--metrics, --columns) могут «съесть» пути, указанные после них: возвращаем их в paths
    for opt in ("metrics", "columns"):
        vals = getattr(args, opt, None)
        if vals:
            moved = []
            while vals and (os.path.exists(vals[-1]) or glob.glob(vals[-1])):
                moved.insert(0, vals.pop())
            if moved:
                args.paths = list(args.paths) + moved
            if not vals:
                setattr(args, opt, None)
    if not args.paths:
        parser.error("укажите хотя бы один файл/каталог nmon (если используете --metrics/--columns, ставьте пути ПЕРЕД ними или после '--')")
    args.thresholds = _parse_thr(args.thr)
    args.show_info = not args.no_info
    try:
        tz = parse_tz_shift(args.tz_shift)
    except UserError as e:
        raise SystemExit(f"ERROR: --tz-shift: {e}")
    # проверка регулярных выражений из опций до разбора
    for opt in ("host", "dev", "iface", "mount", "cmd", "columns", "block"):
        for pat in (getattr(args, opt, None) or []):
            try:
                re.compile(pat)
            except re.error as e:
                raise SystemExit(f"ERROR: --{opt}: неверное регулярное выражение {pat!r}: {e}")
    if getattr(args, "grep", None):
        try:
            re.compile(args.grep)
        except re.error as e:
            raise SystemExit(f"ERROR: --grep: неверное регулярное выражение {args.grep!r}: {e}")
    hosts = load_hosts(args.paths, host_filter=args.host, no_merge=args.no_merge, verbose=args.verbose,
                       skip_first=args.skip_first, tz_shift=tz)
    if not hosts:
        raise SystemExit("ERROR: после фильтра --host не осталось хостов")
    t_from, t_to = resolve_cli_times(args, hosts)
    hosts = apply_time_filter(hosts, t_from, t_to)
    empty = [h for h in hosts if h.n() == 0]
    hosts = [h for h in hosts if h.n() > 0]
    periods = ", ".join(f"{h.name} {ts(h.unfiltered.start())} .. {ts(h.unfiltered.end())}" if h.unfiltered else h.name
                        for h in empty)
    if not hosts:
        raise SystemExit(f"ERROR: в выбранном окне времени нет снимков: окно {ts(t_from) if t_from else 'начало данных'} .. "
                         f"{ts(t_to) if t_to else 'конец данных'}; данные: {periods}")
    if empty:
        warn("в выбранном окне времени нет снимков у хостов: " + periods)
    if args.command == "compare":
        check_compare_windows(hosts, args)
    reports = []
    try:
        if args.command in CLUSTER_COMMANDS:
            reports.append(CLUSTER_COMMANDS[args.command][0](hosts, args))
        else:
            fn = PER_HOST_COMMANDS[args.command][0]
            for h in hosts:
                reports.append(fn(h, args))
    except UserError as e:  # ошибка во входных данных (время, длительность, окно); прочие исключения — внутренние
        raise SystemExit(f"ERROR: {e}")
    except re.error as e:
        raise SystemExit(f"ERROR: неверное регулярное выражение: {e}")
    emit(reports, args)
    if args.command == "export" and reports and all(r.error for r in reports):
        # выгружать нечего ни по одному хосту: причины — в WARN выше; если данные есть хотя бы у одного — код 0
        sys.stderr.write("ERROR: export: нет данных для выгрузки ни по одному хосту (причины — в WARN выше)\n")
        return EXIT_ERROR
    # код возврата: 2 при CRIT, 1 при WARN (для health/report/cluster), иначе 0; rep.worst считается по всем
    # замечаниям, а не по отфильтрованным --no-info/--min-severity
    if args.command in ("health", "report", "cluster"):
        return max((r.worst for r in reports), default=0)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit as e:
        if not isinstance(e.code, str):
            raise
        # SystemExit("ERROR: …") — ошибка данных/аргументов: код 3, чтобы не путать с 1/2 (WARN/CRIT)
        sys.stderr.write(e.code + "\n")
        sys.exit(EXIT_ERROR)
    except BrokenPipeError:
        # читатель закрыл pipe (| head): остаток вывода не нужен — stdout на /dev/null, чтобы финальный flush
        # интерпретатора не печатал ошибку; код 0
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:  # noqa: BLE001 — внутренняя ошибка не должна давать код 1/2 (WARN/CRIT)
        import traceback
        traceback.print_exc()
        sys.stderr.write("ERROR: внутренняя ошибка nmon_analyzer (трассировка выше)\n")
        sys.exit(EXIT_ERROR)
