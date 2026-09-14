#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmon_analyzer.py — однофайловый анализатор файлов NMON (nmon for Linux).

Назначение: быстрый ответ на вопросы о поведении ОС (CPU, память, диски,
файловые системы, сеть, процессы) по файлам nmon, снятым с узлов кластера
Apache Ignite 2.x. Ориентирован на использование ИИ-агентами через shell.

Требования: Python >= 3.12, только стандартная библиотека.

Запуск:  python nmon_analyzer.py <команда> [опции] <файлы|каталоги|маски>
Справка: python nmon_analyzer.py --help ; python nmon_analyzer.py <команда> --help
Полное описание команд и интерпретации — в NMON_ANALYZER.md.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import sys
from array import array
from collections import defaultdict
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
    "VM": ("Счётчики vmstat: nr_* — текущие значения (страницы); остальные — приращения за интервал (pgpgin/pgpgout в KB)", "pages/interval"),
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


def robust_z(vals):
    """Робастный z-score (медиана и MAD*1.4826); при MAD=0 — по стандартному отклонению."""
    med = fmedian(vals)
    m = mad(vals, med)
    out = []
    if not (m == m) or m == 0:
        sd = fstdev(vals)
        for v in vals:
            if v == v and sd == sd and sd > 0:
                out.append((v - med) / sd)
            else:
                out.append(NAN)
        return out
    scale = 1.4826 * m
    for v in vals:
        out.append((v - med) / scale if v == v else NAN)
    return out


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
    """'03:40:04' или '03:40.02' -> (h, m, s)."""
    s = s.strip()
    m = re.match(r"^(\d{1,2}):(\d{2})[:.](\d{2})$", s)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    m = re.match(r"^(\d{1,2}):(\d{2})$", s)
    if m:
        return int(m.group(1)), int(m.group(2)), 0
    return None


def parse_user_time(s: str, ref):
    """Время из аргумента пользователя.
    Поддерживает: 'YYYY-MM-DD HH:MM[:SS]', 'YYYY-MM-DDTHH:MM[:SS]', 'YYYY-MM-DD',
    'DD-MON-YYYY HH:MM[:SS]', 'HH:MM[:SS]' (дата берётся от ref)."""
    if s is None:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    m = re.match(r"^(\d{1,2}-[A-Za-z]{3}-\d{4})[ T](\d{1,2}:\d{2}(?::\d{2})?)$", s)
    if m:
        d = parse_nmon_date(m.group(1))
        t = parse_nmon_time(m.group(2))
        if d and t:
            return datetime(d.year, d.month, d.day, *t)
    t = parse_nmon_time(s)
    if t and ref is not None:
        return datetime(ref.year, ref.month, ref.day, *t)
    raise ValueError(f"не удалось разобрать время: {s!r} (ожидается 'YYYY-MM-DD HH:MM[:SS]' или 'HH:MM[:SS]')")


def parse_duration(s: str) -> float:
    """'10m', '90s', '2h', '1d', '300' (секунды) -> секунды."""
    s = str(s).strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", s)
    if not m:
        raise ValueError(f"не удалось разобрать длительность: {s!r} (пример: 10m, 90s, 2h)")
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


class RawSection:
    """Секция файла nmon с временными строками: колонки + значения по снимкам."""
    __slots__ = ("name", "columns", "rows", "title")

    def __init__(self, name):
        self.name = name
        self.columns = []
        self.title = ""
        self.rows = {}  # Tnnnn -> list[float]


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

    def snapshot_ids(self):
        ids = set(self.zzzz.keys())
        for sec in self.sections.values():
            ids.update(sec.rows.keys())
        ids.update(self.top.keys())
        return sorted(ids)

    def start_datetime(self):
        d = parse_nmon_date(self.meta.get("date", ""))
        t = parse_nmon_time(self.meta.get("time", ""))
        if d and t:
            return datetime(d.year, d.month, d.day, *t)
        return None


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


def _tnum(t: str) -> int:
    """Номер снимка из 'T0012' или 'T0012#2' (второй запуск в том же файле)."""
    m = re.match(r"^T(\d+)", t)
    return int(m.group(1)) if m else 0


def parse_nmon_file(path: str) -> NmonFile:
    """Потоковый разбор одного файла nmon. Если в файле несколько запусков nmon подряд (повтор AAA,progname
    или ZZZZ с уже встречавшимся Tnnnn), снимки последующих запусков получают суффикс '#N', чтобы не
    смешивать данные разных запусков."""
    nf = NmonFile(path)
    top_cmd_idx = None
    top_n_head = 0
    top_map = {}
    run = 0
    seen_data = False
    last_zzzz = None
    last_run = 0

    def tkey(t):
        return f"{t}#{run}" if run else t
    if path.lower().endswith(".gz"):
        import gzip
        opener = gzip.open(path, "rt", encoding="utf-8", errors="replace", newline=None)
    else:
        opener = open(path, "r", encoding="utf-8", errors="replace", newline=None)
    with opener as fh:
        for raw in fh:
            nf.line_count += 1
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
                elif len(parts) == 2:
                    nf.meta.setdefault(key, "")
                continue
            if tag == "BBBP":
                r = _split_bbbp(line)
                if r:
                    _seq, cmd, text = r
                    cmd = cmd.strip()
                    if cmd not in nf.bbbp:
                        nf.bbbp[cmd] = []
                        nf.bbbp_order.append(cmd)
                    if text is not None:
                        nf.bbbp[cmd].append(text)
                continue
            if tag == "ZZZZ":
                parts = line.split(",")
                seen_data = True
                tid = parts[1].strip() if len(parts) > 1 else ""
                if tkey(tid) in nf.zzzz and RE_TSNAP.match(tid):
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
                    continue
                if not RE_TSNAP.match(parts[2].strip()):
                    continue  # "TOP,%CPU Utilisation" и т.п.
                vals = parts[1:]
                if top_cmd_idx is None:
                    nf.top_columns = list(TOP_DEFAULT_COLUMNS)
                    top_map = {c: i for i, c in enumerate(nf.top_columns)}
                    top_cmd_idx = top_map["Command"]
                    top_n_head = len(nf.top_columns)
                extra = len(vals) - top_n_head
                if extra > 0:
                    cmd = ",".join(vals[top_cmd_idx:top_cmd_idx + extra + 1])
                    vals = vals[:top_cmd_idx] + [cmd] + vals[top_cmd_idx + extra + 1:]
                if top_cmd_idx >= len(vals) or not vals[top_cmd_idx].strip():
                    nf.bad_lines += 1  # обрезанная строка TOP без имени команды
                    continue

                def g(name):
                    i = top_map.get(name)
                    if i is None or i >= len(vals):
                        return NAN
                    return to_float(vals[i])

                try:
                    pid = int(vals[0])
                except ValueError:
                    continue
                seen_data = True
                snap = tkey(vals[1].strip())
                cmd = vals[top_cmd_idx].strip()
                p = Proc(pid, cmd, g("%CPU"), g("%Usr"), g("%Sys"), g("Size"), g("ResSet"),
                         g("ResText"), g("ResData"), g("ShdLib"), g("MinorFault"), g("MajorFault"),
                         g("Threads"), g("IOwaitTime"))
                nf.top[snap].append(p)
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
                nf.uarg[tkey(vals[0].strip())].append((pid, prog, full.strip()))
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
                key = tkey(second)
                if key in sec.rows:
                    continue  # дубликат снимка — оставляем первый
                sec.rows[key] = [to_float(x) for x in parts[2:]]
            else:
                if not sec.columns:
                    sec.title = second
                    sec.columns = [c.strip() for c in parts[2:]]
    # Согласованность: длина строк vs колонки
    for sec in list(nf.sections.values()):
        if not sec.rows and not sec.columns:
            del nf.sections[sec.name]
            continue
        if not sec.columns:
            width = max((len(v) for v in sec.rows.values()), default=0)
            sec.columns = [f"col{i + 1}" for i in range(width)]
            nf.warnings.append(f"секция {sec.name}: заголовок не найден, колонки названы col1..col{width}")
        ncol = len(sec.columns)
        for vals in sec.rows.values():
            if len(vals) < ncol:
                vals.extend([NAN] * (ncol - len(vals)))
            elif len(vals) > ncol:
                del vals[ncol:]
    # Восстановление отсутствующих ZZZZ по интервалу
    ids = nf.snapshot_ids()
    if ids:
        missing = [t for t in ids if t not in nf.zzzz]
        if missing:
            start = nf.start_datetime()
            interval = nf.interval or 60.0
            for t in missing:
                n = _tnum(t)
                suffix = t[t.find("#"):] if "#" in t else ""
                known = sorted(((_tnum(k), dt) for k, dt in nf.zzzz.items() if (k[k.find("#"):] if "#" in k else "") == suffix),
                               key=lambda x: x[0])
                est = None
                if known:
                    k = min(known, key=lambda kv: abs(kv[0] - n))
                    est = k[1] + timedelta(seconds=(n - k[0]) * interval)
                elif start is not None and not suffix:
                    est = start + timedelta(seconds=(n - 1) * interval)
                if est is not None:
                    nf.zzzz[t] = est
            nf.warnings.append(f"{len(missing)} снимков без строки ZZZZ — время оценено по интервалу {interval:.0f}s")
    return nf


# --------------------------------------------------------------------------
# Хост: объединение файлов, выровненные по времени ряды
# --------------------------------------------------------------------------


class Host:
    """Все данные по одному хосту: объединённые файлы, ряды, выровненные по времени."""

    def __init__(self, name: str):
        self.name = name
        self.files = []
        self.times = []
        self.snap_ids = []
        self.snap_src = []
        self.series = {}      # section -> column -> array('d')
        self.columns = {}     # section -> [columns]
        self.top = []         # по индексу снимка: list[Proc]
        self.uarg = []
        self.meta = {}
        self.bbbp = {}
        self.bbbp_order = []
        self.interval = 0.0
        self.warnings = []
        self.duplicates_dropped = 0
        self.cpu_cores = []

    # --- построение ---
    def build(self):
        self.files.sort(key=lambda f: (f.start_datetime() or datetime.min, f.path))
        self.meta = dict(self.files[0].meta)
        for f in self.files:
            for cmd in f.bbbp_order:
                if cmd not in self.bbbp:
                    self.bbbp[cmd] = list(f.bbbp[cmd])
                    self.bbbp_order.append(cmd)
        intervals = [f.interval for f in self.files if f.interval > 0]
        self.interval = fmedian(intervals) if intervals else 60.0
        chosen = {}
        for fi, f in enumerate(self.files):
            for t, dt in f.zzzz.items():
                if dt in chosen:
                    self.duplicates_dropped += 1
                    continue
                chosen[dt] = (fi, t)
        # Перекрывающиеся файлы одного хоста: снимки из разных файлов, отстоящие
        # меньше чем на полинтервала, считаем дубликатами (оставляем более ранний файл).
        if len(self.files) > 1:
            ordered = sorted(chosen.keys())
            half = (self.interval or 60.0) * 0.5
            keep = []
            last_dt = None
            for dt in ordered:
                if last_dt is not None and chosen[dt][0] != chosen[last_dt][0] \
                        and (dt - last_dt).total_seconds() < half:
                    # оставляем снимок из файла с меньшим индексом (более ранний старт)
                    if chosen[dt][0] < chosen[last_dt][0]:
                        keep.pop()
                        del chosen[last_dt]
                        keep.append(dt)
                        last_dt = dt
                    else:
                        del chosen[dt]
                    self.duplicates_dropped += 1
                    continue
                keep.append(dt)
                last_dt = dt
        self.times = sorted(chosen.keys())
        self.snap_src = [chosen[dt][0] for dt in self.times]
        self.snap_ids = [chosen[dt][1] for dt in self.times]
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
                for c, v in zip(sec.columns, vals):
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
        """Шаг для интегрирования (с): интервал nmon либо фактический."""
        return self.interval if self.interval > 0 else (self.actual_interval() or 60.0)

    def gaps(self, factor=1.5):
        """Разрывы во времени: список (t_prev, t_next, seconds)."""
        out = []
        step = self.step()
        for i in range(len(self.times) - 1):
            d = (self.times[i + 1] - self.times[i]).total_seconds()
            if d > step * factor:
                out.append((self.times[i], self.times[i + 1], d))
        return out

    def slice(self, mask) -> "Host":
        """Новый Host с подмножеством снимков (фильтр по времени)."""
        h = Host(self.name)
        h.files = self.files
        h.meta = self.meta
        h.bbbp = self.bbbp
        h.bbbp_order = self.bbbp_order
        h.interval = self.interval
        h.warnings = self.warnings
        h.duplicates_dropped = self.duplicates_dropped
        idx = [i for i, m in enumerate(mask) if m]
        h.times = [self.times[i] for i in idx]
        h.snap_ids = [self.snap_ids[i] for i in idx]
        h.snap_src = [self.snap_src[i] for i in idx]
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
            if v == v:
                return int(v)
        try:
            return int(self.meta.get("cpus", "0"))
        except ValueError:
            return len(self.cpu_cores)

    def mem_used(self):
        """Использовано (MB) = memtotal - memfree - cached - buffers (как 'used' у free)."""
        t = self.col("MEM", "memtotal")
        f = self.col("MEM", "memfree")
        c = self.col("MEM", "cached")
        b = self.col("MEM", "buffers")
        if t is None or f is None:
            return None
        out = []
        for i in range(self.n()):
            tv, fv = t[i], f[i]
            cv = c[i] if c is not None and c[i] == c[i] and c[i] >= 0 else 0.0
            bv = b[i] if b is not None and b[i] == b[i] and b[i] >= 0 else 0.0
            out.append(tv - fv - cv - bv if (tv == tv and fv == fv) else NAN)
        return out

    def mem_avail(self):
        """Приближение MemAvailable (MB): memfree + buffers + (cached − memshared) + slab reclaimable.
        memshared (Shmem/tmpfs) входит в cached, но не вытесняется; slab reclaimable берётся из VM."""
        f = self.col("MEM", "memfree")
        c = self.col("MEM", "cached")
        b = self.col("MEM", "buffers")
        s = self.col("MEM", "memshared")
        slab = self.col("VM", "nr_slab_reclaimable")
        if f is None:
            return None
        out = []
        for i in range(self.n()):
            fv = f[i]
            cv = c[i] if c is not None and c[i] == c[i] and c[i] >= 0 else 0.0
            bv = b[i] if b is not None and b[i] == b[i] and b[i] >= 0 else 0.0
            sv = s[i] if s is not None and s[i] == s[i] and s[i] >= 0 else 0.0
            lv = slab[i] * 4.0 / 1024.0 if slab is not None and slab[i] == slab[i] and slab[i] >= 0 else 0.0
            out.append(fv + bv + max(0.0, cv - sv) + lv if fv == fv else NAN)
        return out

    def mem_avail_offset(self):
        """Калибровка оценки avail по MemAvailable ядра на старте (BBBP): оценка − MemAvailable, MB (0, если данных нет)."""
        av = self.mem_avail()
        mi = self.meminfo()
        if av and mi.get("MemAvailable") and av[0] == av[0]:
            return max(0.0, av[0] - mi["MemAvailable"] / 1024.0)
        return 0.0

    def mem_avail_calibrated(self):
        """avail с поправкой на MemAvailable ядра на старте (ближе к тому, что видит ядро)."""
        av = self.mem_avail()
        if av is None:
            return None
        off = self.mem_avail_offset()
        return [v - off if v == v else NAN for v in av]

    def kernel_version(self):
        """(major, minor) из AAA,OS; (0, 0) если не разобрать."""
        m = re.search(r"\b(\d+)\.(\d+)\.\d+", self.meta.get("OS", ""))
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    def first_snapshot_indices(self):
        """Индексы снимков, являющихся первым (T0001) снимком своего файла или запуска в файле: интервал неполный."""
        pos = {(dt, src): i for i, (dt, src) in enumerate(zip(self.times, self.snap_src))}
        out = set()
        for fi, f in enumerate(self.files):
            by_run = defaultdict(list)
            for t, dt in f.zzzz.items():
                by_run[t[t.find("#"):] if "#" in t else ""].append(dt)
            for dts in by_run.values():
                i = pos.get((min(dts), fi))
                if i is not None:
                    out.add(i)
        return out

    def without_first(self):
        """Копия без первых снимков файлов (для статистик, чувствительных к неполному интервалу)."""
        firsts = self.first_snapshot_indices()
        if not firsts or self.n() <= len(firsts) + 1:
            return self
        return self.slice([i not in firsts for i in range(self.n())])

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

    def bond_slaves(self):
        """Интерфейсы-слейвы бондов: по флагу SLAVE в ifconfig (BBBP), а без ifconfig — по трафику."""
        return [i for i, role in self.net_roles().items() if role.startswith("bond-slave")]

    def net_roles(self):
        """Роль каждого интерфейса: lo | bond | bond-slave | bond-slave (по трафику) | nic."""
        if getattr(self, "_net_roles", None) is not None:
            return self._net_roles
        roles = {}
        ifaces = self.net_ifaces()
        flags = {}
        for line in self.bbbp.get("ifconfig", []):
            m = re.match(r"^(\S+): flags=\d+<([^>]*)>", line)
            if m:
                flags[m.group(1)] = set(m.group(2).split(","))
        for i in ifaces:
            if i == "lo":
                roles[i] = "lo"
            elif i in flags and "SLAVE" in flags[i]:
                roles[i] = "bond-slave"
            elif i in flags and "MASTER" in flags[i]:
                roles[i] = "bond"
            elif i.startswith("bond"):
                roles[i] = "bond"
            else:
                roles[i] = "nic"
        bonds = [i for i in ifaces if roles[i] == "bond"]
        if bonds and not flags:
            # ifconfig нет: слейвы определяем по трафику — набор NIC, сумма трафика которых ≈ трафику бонда
            def total(i):
                rd = self.col("NET", f"{i}-read-KB/s")
                wr = self.col("NET", f"{i}-write-KB/s")
                return (fsum(rd) if rd is not None else 0.0) + (fsum(wr) if wr is not None else 0.0)
            cands = sorted([i for i in ifaces if roles[i] == "nic"], key=lambda i: -total(i))
            for b in bonds:
                tb = total(b)
                if tb <= 0:
                    continue
                acc = 0.0
                for i in cands:
                    if roles[i] != "nic":
                        continue
                    ti = total(i)
                    if ti <= 0:
                        continue
                    if acc + ti <= tb * 1.15:
                        acc += ti
                        roles[i] = "bond-slave (по трафику)"
                    if acc >= tb * 0.85:
                        break
        self._net_roles = roles
        return roles

    def net_primary_ifaces(self):
        """Интерфейсы без lo и без слейвов бондов (чтобы не считать трафик дважды)."""
        roles = self.net_roles()
        return [i for i in self.net_ifaces() if roles.get(i) in ("bond", "nic")]

    def net_counters(self):
        """Накопительные счётчики интерфейсов на старте: из ifconfig, а если его нет — из /proc/net/dev (BBBP)."""
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
            out[name] = {"name": name, "flags": "", "mtu": NAN, "inet": "",
                         "rx_packets": vals[1], "rx_bytes": vals[0], "tx_packets": vals[9], "tx_bytes": vals[8],
                         "rx_errors": vals[2], "rx_dropped": vals[3], "tx_errors": vals[10], "tx_dropped": vals[11],
                         "source": "/proc/net/dev"}
        return out

    def net_total(self, direction: str):
        """Сумма KB/s по основным интерфейсам (read|write); снимок без данных остаётся NaN."""
        out = array("d", [NAN]) * self.n()
        anyd = False
        for i in self.net_primary_ifaces():
            arr = self.col("NET", f"{i}-{direction}-KB/s")
            if arr is None:
                continue
            anyd = True
            for k, v in enumerate(arr):
                if v == v:
                    out[k] = (out[k] if out[k] == out[k] else 0.0) + v
        return out if anyd else None

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
        """Максимальная занятость среди всех устройств в каждом снимке + имя устройства."""
        if "DISKBUSY" not in self.series:
            return None, None
        n = self.n()
        best = array("d", [NAN]) * n
        who = [""] * n
        for d, arr in self.series["DISKBUSY"].items():
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
                dev = m.group(1)
                if dev.startswith("ddev/"):
                    dev = "/dev/" + dev[5:]
                out.append({"device": dev, "mount": m.group(2), "fstype": m.group(3), "options": m.group(4)})
        return out

    def df(self):
        """df -m из BBBP."""
        out = []
        for line in self.bbbp.get("/bin/df-m", []):
            m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S+)\s*$", line)
            if m:
                dev = m.group(1)
                if dev.startswith("ddev/"):
                    dev = "/dev/" + dev[5:]
                out.append({"filesystem": dev, "size_mb": int(m.group(2)), "used_mb": int(m.group(3)),
                            "avail_mb": int(m.group(4)), "use_pct": int(m.group(5)), "mount": m.group(6)})
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
        """Карта: устройство nmon -> dm/LV -> точка монтирования -> fs -> размер."""
        dm = self.dm_map()
        lsb = self.lsblk()
        lsb_by_name = {r["name"]: r for r in lsb}
        lsb_by_majmin = {(r["major"], r["minor"]): r for r in lsb}
        mount_by_dev = {}
        for m in self.mounts():
            mount_by_dev[m["device"]] = m
            mount_by_dev[os.path.basename(m["device"])] = m
        dfrows = {r["mount"]: r for r in self.df()}
        parts = self.partitions()
        result = []
        for dev in self.disk_devices():
            lv = dm.get(dev, "")
            entry = {"device": dev, "lv": lv, "mount": "", "fstype": "", "size": "", "type": "", "parent": "", "phys": ""}
            mm = parts.get(dev)
            row = None
            if mm:
                row = lsb_by_majmin.get((mm[0], mm[1]))
                entry["size_mb"] = round(mm[2] / 1024.0)
            if row is None:
                row = lsb_by_name.get(lv) or lsb_by_name.get(dev)
            if row:
                entry["size"] = row["size"]
                entry["type"] = row["type"]
                entry["parent"] = row.get("parent", "")
                entry["phys"] = row.get("root", "") if row.get("root", "") != row["name"] or row["type"] == "disk" else ""
                if row["mount"]:
                    entry["mount"] = row["mount"]
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
            if r["mount"] and r.get("root") and r["root"] != r["name"]:
                by_phys[r["root"]].append(r["mount"])
        for e in result:
            if not e["mount"] and e["device"] in by_phys:
                e["child_mounts"] = by_phys[e["device"]]
        return result

    def phys_disk_of(self, dev):
        """Физический диск, на котором лежит устройство/LV nmon (по дереву lsblk); '' если неизвестно."""
        for e in self.device_map():
            if e["device"] == dev:
                return e.get("phys", "")
        return ""

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
        """/proc/meminfo из BBBP: ключ -> kB (int)."""
        out = {}
        for line in self.bbbp.get("/proc/meminfo", []):
            m = re.match(r"^(\S+):\s+(\d+)(?:\s+kB)?\s*$", line)
            if m:
                out[m.group(1)] = int(m.group(2))
        return out

    def lscpu(self):
        out = {}
        for line in self.bbbp.get("lscpu", []):
            m = re.match(r"^([^:]+):\s+(.*)$", line)
            if m:
                out[m.group(1).strip()] = m.group(2).strip()
        return out

    def numa_map(self):
        """NUMA node -> список номеров CPU (0-based) из lscpu 'NUMA nodeN CPU(s): 0-13,28-41'."""
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
        for line in self.bbbp.get("uptime", []):
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

    def load_average(self):
        for line in self.bbbp.get("uptime", []):
            m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", line)
            if m:
                return float(m.group(1)), float(m.group(2)), float(m.group(3))
        return None

    def ifconfig(self):
        """ifconfig из BBBP: список интерфейсов с флагами, mtu, inet, ошибками."""
        out = []
        cur = None
        for line in self.bbbp.get("ifconfig", []):
            m = re.match(r"^(\S+): flags=\d+<([^>]*)>\s+mtu\s+(\d+)", line)
            if m:
                cur = {"name": m.group(1), "flags": m.group(2), "mtu": int(m.group(3)), "inet": "",
                       "rx_packets": None, "rx_bytes": None, "tx_packets": None, "tx_bytes": None,
                       "rx_errors": None, "rx_dropped": None, "tx_errors": None, "tx_dropped": None}
                out.append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^\s*inet\s+(\S+)", line)
            if m:
                cur["inet"] = m.group(1)
            m = re.match(r"^\s*RX packets\s+(\d+)\s+bytes\s+(\d+)", line)
            if m:
                cur["rx_packets"], cur["rx_bytes"] = int(m.group(1)), int(m.group(2))
            m = re.match(r"^\s*TX packets\s+(\d+)\s+bytes\s+(\d+)", line)
            if m:
                cur["tx_packets"], cur["tx_bytes"] = int(m.group(1)), int(m.group(2))
            m = re.match(r"^\s*RX errors\s+(\d+)\s+dropped\s+(\d+)", line)
            if m:
                cur["rx_errors"], cur["rx_dropped"] = int(m.group(1)), int(m.group(2))
            m = re.match(r"^\s*TX errors\s+(\d+)\s+dropped\s+(\d+)", line)
            if m:
                cur["tx_errors"], cur["tx_dropped"] = int(m.group(1)), int(m.group(2))
        return out


def _parse_cpu_list(s):
    """'0-13,28-41' -> [0..13, 28..41]."""
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
            for root, _dirs, files in os.walk(p):
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


def load_hosts(paths, host_filter=None, no_merge=False, verbose=False, skip_first=False, tz_shift=None):
    files = expand_paths(paths)
    if not files:
        raise SystemExit("ERROR: не найдено ни одного файла nmon")
    hosts = {}
    for path in files:
        try:
            nf = parse_nmon_file(path)
        except OSError as e:
            warn(f"не удалось прочитать {path}: {e}")
            continue
        if not nf.sections and not nf.zzzz:
            warn(f"{path}: не похоже на файл nmon (нет секций) — пропущен")
            continue
        name = nf.host
        if no_merge:
            name = f"{name}:{os.path.basename(path)}"
        if host_filter and not any(re.search(hf, name) for hf in host_filter):
            continue
        h = hosts.get(name)
        if h is None:
            h = Host(name)
            hosts[name] = h
        h.files.append(nf)
        if verbose:
            sys.stderr.write(f"parsed {path}: host={nf.host} snapshots={len(nf.zzzz)} "
                             f"sections={len(nf.sections)} bad_lines={nf.bad_lines}\n")
    if not hosts:
        if host_filter:
            raise SystemExit("ERROR: после фильтра --host не осталось хостов")
        raise SystemExit("ERROR: ни один из файлов не удалось разобрать как nmon")
    result = []
    for h in hosts.values():
        h.build()
        if h.n() == 0:
            warn(f"{h.name}: не удалось определить время ни одного снимка (нет ZZZZ и AAA date/time) — хост пропущен")
            continue
        if skip_first and h.n() > 1:
            # первый снимок (T0001) каждого файла/запуска: интервал неполный, дельты VM/TOP искажены.
            # Отбрасывается только если именно он попал в объединённый ряд (не вытеснен дедупликацией).
            firsts = h.first_snapshot_indices()
            if firsts:
                h = h.slice([i not in firsts for i in range(h.n())])
        if tz_shift:
            delta = timedelta(seconds=tz_shift)
            h.times = [t + delta for t in h.times]
            for f in h.files:  # чтобы first_snapshot_indices() и далее сравнивали одинаково сдвинутые времена
                f.zzzz = {t: dt + delta for t, dt in f.zzzz.items()}
        result.append(h)
    result.sort(key=lambda h: h.name)
    if not result:
        raise SystemExit("ERROR: ни в одном файле нет снимков с временем (нет ZZZZ и AAA date/time)")
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


def apply_time_filter(hosts, t_from=None, t_to=None, around=None, window=None):
    out = []
    for h in hosts:
        if not h.times:
            out.append(h)
            continue
        ref = h.times[0]
        crosses_midnight = h.times[-1].date() != ref.date()

        def tod(spec, dt, upper=False):
            # Только время суток: если оно раньше начала данных, а данные переходят через полночь — берём
            # следующий день (для нижней границы — только если перенесённое время ещё внутри данных;
            # верхняя граница раньше начала данных смысла не имеет, поэтому переносится всегда)
            if dt is not None and spec and re.match(r"^\s*\d{1,2}:\d{2}(:\d{2})?\s*$", spec) and dt < ref and crosses_midnight:
                nd = dt + timedelta(days=1)
                if upper or nd <= h.times[-1]:
                    return nd
            return dt

        f = tod(t_from, parse_user_time(t_from, ref)) if t_from else None
        t = tod(t_to, parse_user_time(t_to, ref), upper=True) if t_to else None
        if around:
            a = tod(around, parse_user_time(around, ref))
            w = parse_duration(window) if window else 600.0
            f = a - timedelta(seconds=w)
            t = a + timedelta(seconds=w)
        if f is None and t is None:
            out.append(h)
            continue
        mask = [(f is None or x >= f) and (t is None or x <= t) for x in h.times]
        out.append(h.slice(mask))
    return out


# --------------------------------------------------------------------------
# Вывод: отчёты, таблицы, форматы (text | md | json | csv)
# --------------------------------------------------------------------------

SEV_ORDER = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}


class Finding:
    """Результат проверки: severity, код правила, доказательства, подсказка."""
    __slots__ = ("severity", "code", "host", "time", "metric", "value", "threshold", "evidence", "hint")

    def __init__(self, severity, code, host, metric, value, threshold, evidence, hint="", time=None):
        self.severity = severity
        self.code = code
        self.host = host
        self.time = time
        self.metric = metric
        self.value = value
        self.threshold = threshold
        self.evidence = evidence
        self.hint = hint

    def to_dict(self):
        return {"severity": self.severity, "code": self.code, "host": self.host,
                "time": ts(self.time) if self.time else None, "metric": self.metric,
                "value": _jsonable(self.value), "threshold": _jsonable(self.threshold),
                "evidence": self.evidence, "hint": self.hint}


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

    def kv(self, title, items, note=None, prec=None):
        """items: список (ключ, значение); prec: dict ключ -> 'mb'|'kb'|'dur'|число знаков для text/md (JSON хранит число)."""
        self.blocks.append({"type": "kv", "title": title, "items": list(items), "note": note, "prec": prec or {}})
        return self

    def table(self, title, columns, rows, note=None, prec=None, total=None):
        """columns: список имён; rows: список списков; prec: dict колонка->знаков после запятой."""
        self.blocks.append({"type": "table", "title": title, "columns": list(columns),
                            "rows": [list(r) for r in rows], "note": note, "prec": prec or {},
                            "total": total})
        return self

    def text(self, title, text):
        self.blocks.append({"type": "text", "title": title, "text": text})
        return self

    def findings(self, title, items, note=None):
        items = sorted(items, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.host or "", f.code))
        self.blocks.append({"type": "findings", "title": title, "items": items, "note": note})
        return self

    def to_dict(self):
        out = {"title": self.title, "host": self.host, "blocks": []}
        for b in self.blocks:
            if b["type"] == "kv":
                out["blocks"].append({"type": "kv", "title": b["title"],
                                      "items": {str(k): _jsonable(v) for k, v in b["items"]},
                                      "note": b["note"]})
            elif b["type"] == "table":
                cols = b["columns"]
                out["blocks"].append({"type": "table", "title": b["title"], "columns": cols,
                                      "rows": [{c: _jsonable(v) for c, v in zip(cols, r)} for r in b["rows"]],
                                      "note": b["note"], "total_rows": b["total"]})
            elif b["type"] == "text":
                out["blocks"].append({"type": "text", "title": b["title"], "text": b["text"]})
            elif b["type"] == "findings":
                out["blocks"].append({"type": "findings", "title": b["title"],
                                      "items": [f.to_dict() for f in b["items"]], "note": b["note"]})
        return out


def _cell(v, prec=1):
    """Ячейка для text/md. prec: число знаков либо спец-формат 'mb' (MB -> GB/TB), 'kb', 'dur' (секунды)."""
    if isinstance(v, datetime):
        return ts(v)
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


def _render_table_text(columns, rows, prec, md=False):
    cells = []
    for r in rows:
        cells.append([_cell(v, prec.get(c, 1)) for c, v in zip(columns, r)])
    # колонки со спец-форматом (mb/kb/dur) выравниваем по правому краю как числа
    fmt_cols = {c for c, p in prec.items() if isinstance(p, str)}
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
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("|" + "|".join(("---:" if numeric[i] else ":---") for i in range(len(columns))) + "|")
        for r in cells:
            lines.append("| " + " | ".join(r) + " |")
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
                out.append(f"## {title}" if md else f"--- {title} ---")
            if b["type"] == "kv":
                w = max((len(str(k)) for k, _ in b["items"]), default=0)
                pr = b.get("prec") or {}
                for k, v in b["items"]:
                    cell = _cell(v, pr.get(k, 1))
                    if md:
                        out.append(f"- **{k}**: {cell}")
                    else:
                        out.append(f"{str(k).ljust(w)} : {cell}")
            elif b["type"] == "table":
                if not b["rows"]:
                    out.append("(нет данных)")
                else:
                    out.extend(_render_table_text(b["columns"], b["rows"], b["prec"], md))
                    if b["total"] is not None and b["total"] > len(b["rows"]):
                        out.append(f"(показано {len(b['rows'])} из {b['total']})")
            elif b["type"] == "text":
                out.append(b["text"])
            elif b["type"] == "findings":
                items = b["items"]
                if not items:
                    out.append("(нет замечаний)")
                for f in items:
                    when = f" @ {ts(f.time)}" if f.time else ""
                    hostp = f" [{f.host}]" if f.host and not rep.host else ""
                    val = _cell(f.value) if not isinstance(f.value, str) else f.value
                    thr = f" (порог {_cell(f.threshold) if not isinstance(f.threshold, str) else f.threshold})" \
                        if f.threshold is not None and f.threshold != "" else ""
                    out.append(f"[{f.severity}] {f.code}{hostp}{when}: {f.metric} = {val}{thr}")
                    if f.evidence:
                        out.append(f"    факты: {f.evidence}")
                    if f.hint:
                        out.append(f"    подсказка: {f.hint}")
            if b.get("note"):
                out.append(f"({b['note']})" if not md else f"_{b['note']}_")
        out.append("")
    return "\n".join(out)


def render_csv(reports):
    """CSV: только табличные блоки (первый — без префикса, остальные разделяются пустой строкой)."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    first = True
    for rep in reports:
        for b in rep.blocks:
            if b["type"] != "table":
                continue
            if not first:
                w.writerow([])
            first = False
            w.writerow(b["columns"])
            for r in b["rows"]:
                w.writerow([("" if (isinstance(v, float) and v != v) else
                             (ts(v) if isinstance(v, datetime) else v)) for v in r])
    return buf.getvalue()


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
                if not text.endswith("\n"):
                    fh.write("\n")
        except OSError as e:
            raise SystemExit(f"ERROR: не удалось записать --output {args.output}: {e}")
        sys.stderr.write(f"записано: {args.output}\n")
    else:
        try:
            sys.stdout.write(text)
            if not text.endswith("\n"):
                sys.stdout.write("\n")
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))


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


def time_above(arr, thr, step):
    """Суммарное время (с), когда значение > thr."""
    return count_above(arr, thr) * step


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


def rolling_spikes(arr, times, window=15, z_thr=4.0, min_abs=None, direction="up"):
    """Выбросы по скользящей медиане/MAD (окно центрированное). Возвращает [(time, value, baseline, z)]."""
    n = len(arr)
    out = []
    if n < 5:
        return out
    half = max(2, window // 2)
    for i in range(n):
        v = arr[i]
        if v != v:
            continue
        lo, hi = max(0, i - half), min(n, i + half + 1)
        win = [arr[j] for j in range(lo, hi) if j != i and arr[j] == arr[j]]
        if len(win) < 4:
            continue
        med = fmedian(win)
        m = mad(win, med)
        scale = 1.4826 * m if m > 0 else (fstdev(win) if fstdev(win) == fstdev(win) else 0.0)
        if scale <= 0:
            # плоский фон: любой заметный отход — выброс, если он больше min_abs
            if min_abs is not None and abs(v - med) >= min_abs:
                z = math.inf
            else:
                continue
        else:
            z = (v - med) / scale
        if direction == "up" and z < z_thr:
            continue
        if direction == "down" and z > -z_thr:
            continue
        if direction == "both" and abs(z) < z_thr:
            continue
        if min_abs is not None and abs(v - med) < min_abs:
            continue
        out.append((times[i], v, med, z))
    return out


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


def bucket_start(t, step_sec):
    """Начало корзины для момента t: границы кратны step от полуночи того же дня."""
    base = t.replace(hour=0, minute=0, second=0, microsecond=0)
    k = math.floor((t - base).total_seconds() / step_sec)
    return base + timedelta(seconds=k * step_sec)


def downsample(times, arr, step_sec, agg="mean"):
    """Агрегация по временным корзинам step_sec (границы кратны шагу от полуночи): (times, values)."""
    if not times or step_sec <= 0:
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
    return out_t, out_v


# --------------------------------------------------------------------------
# Реестр метрик (для timeline / events / correlate / export)
# --------------------------------------------------------------------------


def _per_sec(arr, step):
    return [v / step if v == v else NAN for v in arr]


def _pages_to_mb(arr, page_kb=4.0):
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


def _proc_series(host, pred, field):
    """Ряд по процессам TOP: сумма поля по процессам, удовлетворяющим pred (NaN если процесс не виден)."""
    n = host.n()
    out = [NAN] * n
    for i, procs in enumerate(host.top):
        acc = None
        for p in procs:
            if pred(p):
                v = getattr(p, field)
                if v == v:
                    acc = (acc or 0.0) + v
        out[i] = acc if acc is not None else NAN
    return out


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
    "mem.active": ("active", "MB", lambda h: h.col("MEM", "active")),
    "mem.inactive": ("inactive", "MB", lambda h: h.col("MEM", "inactive")),
    "mem.shared": ("memshared", "MB", lambda h: h.col("MEM", "memshared")),
    "mem.swap_used": ("swap used", "MB", lambda h: h.swap_used()),
    "mem.swapcached": ("swapcached", "MB", lambda h: h.col("MEM", "swapcached")),
    "vm.pgpgin": ("pgpgin (чтение с блочных устройств)", "KB/s", lambda h: _per_sec(h.col("VM", "pgpgin") or [], h.step())),
    "vm.pgpgout": ("pgpgout (запись на блочные устройства)", "KB/s", lambda h: _per_sec(h.col("VM", "pgpgout") or [], h.step())),
    "vm.pswpin": ("pswpin (страниц из swap за интервал)", "pages/int", lambda h: h.col("VM", "pswpin")),
    "vm.pswpout": ("pswpout (страниц в swap за интервал)", "pages/int", lambda h: h.col("VM", "pswpout")),
    "vm.pgfault": ("page faults", "/s", lambda h: _per_sec(h.col("VM", "pgfault") or [], h.step())),
    "vm.pgmajfault": ("major page faults", "/s", lambda h: _per_sec(h.col("VM", "pgmajfault") or [], h.step())),
    "vm.pgfree": ("pgfree", "/s", lambda h: _per_sec(h.col("VM", "pgfree") or [], h.step())),
    "vm.kswapd_steal": ("kswapd_steal (страниц освобождено kswapd за интервал)", "pages/int", lambda h: h.col("VM", "kswapd_steal")),
    "vm.pgscan_kswapd": ("pgscan_kswapd_* (сканирование kswapd за интервал)", "pages/int",
                         lambda h: _sum_cols(h, "VM", ["pgscan_kswapd_high", "pgscan_kswapd_normal", "pgscan_kswapd_dma"])),
    "vm.pgscan_direct": ("pgscan_direct_* (прямой reclaim за интервал)", "pages/int",
                         lambda h: _sum_cols(h, "VM", ["pgscan_direct_high", "pgscan_direct_normal", "pgscan_direct_dma"])),
    "vm.pgsteal": ("pgsteal_* (освобождено reclaim за интервал)", "pages/int",
                   lambda h: _sum_cols(h, "VM", ["pgsteal_high", "pgsteal_normal", "pgsteal_dma"])),
    "vm.allocstall": ("allocstall (direct reclaim stalls за интервал; на ядрах ≥ 4.x всегда 0)", "count/int", lambda h: h.col("VM", "allocstall")),
    "vm.pageoutrun": ("pageoutrun (запуски kswapd за интервал)", "count/int", lambda h: h.col("VM", "pageoutrun")),
    "vm.slabs_scanned": ("slabs_scanned (сканирование slab при reclaim за интервал)", "count/int", lambda h: h.col("VM", "slabs_scanned")),
    "vm.pgdeactivate": ("pgdeactivate (страниц переведено в inactive за интервал)", "pages/int", lambda h: h.col("VM", "pgdeactivate")),
    "vm.pgactivate": ("pgactivate (страниц переведено в active за интервал)", "pages/int", lambda h: h.col("VM", "pgactivate")),
    "vm.nr_dirty": ("nr_dirty (грязные страницы)", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_dirty") or [])),
    "vm.nr_writeback": ("nr_writeback (страницы в записи)", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_writeback") or [])),
    "vm.nr_mapped": ("nr_mapped", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_mapped") or [])),
    "vm.nr_slab": ("nr_slab_reclaimable", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_slab_reclaimable") or [])),
    "vm.nr_page_table": ("nr_page_table_pages", "MB", lambda h: _pages_to_mb(h.col("VM", "nr_page_table_pages") or [])),
    "disk.busy_max": ("Макс. занятость среди устройств", "%", lambda h: h.disk_max_busy()[0]),
    "disk.read": ("Чтение, сумма по физическим дискам", "KB/s", lambda h: h.disk_total("DISKREAD")),
    "disk.write": ("Запись, сумма по физическим дискам", "KB/s", lambda h: h.disk_total("DISKWRITE")),
    "disk.iops": ("IOPS, сумма по физическим дискам", "/s", lambda h: h.disk_total("DISKXFER")),
    "net.read": ("Сеть приём, сумма (без lo и слейвов bond)", "KB/s", lambda h: h.net_total("read")),
    "net.write": ("Сеть передача, сумма (без lo и слейвов bond)", "KB/s", lambda h: h.net_total("write")),
    "top.java.cpu": ("java: %CPU (сумма по java-процессам)", "%", lambda h: _proc_series(h, _is_java, "cpu")),
    "top.java.usr": ("java: %Usr", "%", lambda h: _proc_series(h, _is_java, "usr")),
    "top.java.sys": ("java: %Sys", "%", lambda h: _proc_series(h, _is_java, "sys")),
    "top.java.rss": ("java: RSS", "MB", lambda h: _kb_to_mb(_proc_series(h, _is_java, "rss"))),
    "top.java.vsz": ("java: VSZ", "MB", lambda h: _kb_to_mb(_proc_series(h, _is_java, "size"))),
    "top.java.threads": ("java: threads", "count", lambda h: _proc_series(h, _is_java, "threads")),
    "top.java.majflt": ("java: major faults (TOP; сверяйте с vm.pgmajfault)", "/s", lambda h: _proc_series(h, _is_java, "majflt")),
    "top.java.minflt": ("java: minor faults", "/s", lambda h: _proc_series(h, _is_java, "minflt")),
    "top.java.iowait": ("java: IOwaitTime (только главный поток)", "ticks", lambda h: _proc_series(h, _is_java, "iowait")),
    "top.sum_cpu": ("Сумма %CPU всех процессов TOP", "%", _top_sum_cpu),
    "top.kswapd.cpu": ("kswapd: %CPU", "%", lambda h: _proc_series(h, lambda p: p.cmd.startswith("kswapd"), "cpu")),
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
    """[(name, (label, unit, values))] для известных метрик; о неизвестных предупреждает в stderr
    (warn_missing=False — для наборов по умолчанию, где часть метрик может отсутствовать в файле)."""
    out = []
    for m in names or []:
        r = resolve_metric(host, m)
        if r is None:
            if warn_missing:
                warn(f"{host.name}: метрика {m!r} неизвестна или отсутствует в данных (список: команда metrics)")
        else:
            out.append((m, r))
    return out


def resolve_metric(host, name):
    """Имя метрики -> (label, unit, values) или None.
    Кроме BASE_METRICS поддерживаются:
      disk.<dev>.busy|read|write|iops|bsize|rserv|wserv
      net.<if>.read|write|pkt_in|pkt_out
      fs.<mount>.pct
      cpu.core<N>.busy|user|sys|wait   (N — номер CPU как в nmon, с 1)
      top.<cmd>.cpu|rss|threads|sys|usr|majflt|minflt|vsz
      top.pid<PID>.cpu|rss|threads|...
      raw.<SECTION>.<column>
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
            pred = lambda p, pid=pid: p.pid == pid  # noqa: E731
        else:
            pred = lambda p, t=target: p.cmd == t or p.cmd.startswith(t)  # noqa: E731
        vals = _proc_series(host, pred, field)
        unit = {"cpu": "%", "usr": "%", "sys": "%", "rss": "MB", "size": "MB", "threads": "count",
                "majflt": "/s", "minflt": "/s", "iowait": "ticks"}.get(field, "count")
        if field in ("rss", "size"):
            vals = _kb_to_mb(vals)
        return f"{target} {what}", unit, vals
    if len(parts) >= 3 and parts[0] == "raw":
        sec, col = parts[1], ".".join(parts[2:])
        arr = host.col(sec, col)
        if arr is None:
            return None
        return f"{sec} {col}", SECTION_INFO.get(sec, ("", ""))[1], list(arr)
    return None


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
        for what in ("read", "write", "pkt_in", "pkt_out"):
            names.append(f"net.{i}.{what}")
    for m in host.cols("JFSFILE"):
        names.append(f"fs.{m}.pct")
    for k in range(1, len(host.cpu_cores) + 1):
        names.append(f"cpu.core{k}.busy")
    cmds = set()
    for procs in host.top:
        for p in procs:
            cmds.add(p.cmd)
    for c in sorted(cmds):
        names.append(f"top.{c}.cpu")
    return names


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
        ("boottime (из AAA)", m.get("boottime", "-")),
        ("interval, с (AAA)", host.interval),
        ("фактический шаг, с (медиана)", host.actual_interval()),
        ("снимков", host.n()),
        ("начало", host.start()),
        ("конец", host.end()),
        ("длительность", fmt_dur(host.duration())),
        ("CPU (логических)", host.ncpus()),
    ]
    mt = host.col("MEM", "memtotal")
    if mt is not None:
        items.append(("memtotal", fmt_mb(fmax(mt))))
    st = host.col("MEM", "swaptotal")
    if st is not None:
        items.append(("swaptotal", fmt_mb(fmax(st))))
    items.append(("дисков в DISK*", len(host.disk_devices())))
    items.append(("физических дисков", ", ".join(host.physical_disks()) or "-"))
    items.append(("сетевых интерфейсов", ", ".join(host.net_ifaces()) or "-"))
    items.append(("файловых систем (JFSFILE)", len(host.cols("JFSFILE"))))
    items.append(("TOP (процессы)", "да" if any(host.top) else "нет (nmon без -t)"))
    items.append(("UARG (командные строки)", "да" if any(host.uarg) else "нет (nmon без -T)"))
    items.append(("дубликатов снимков отброшено", host.duplicates_dropped))
    gaps = host.gaps()
    items.append(("разрывов во времени (> 1.5×interval)", len(gaps)))
    # Планировалось vs собрано
    try:
        planned = int(m.get("snapshots", "0"))
        if 0 < planned < 9999999:
            items.append(("снимков запланировано (-c)", planned))
    except ValueError:
        pass
    rep.kv("Метаданные", items)
    if gaps:
        rep.table("Разрывы во времени (возможная заморозка хоста или остановка nmon)",
                  ["от", "до", "длительность"],
                  [[a, b, fmt_dur(d)] for a, b, d in gaps[:50]], total=len(gaps))
    # Аппаратная конфигурация из BBBP
    lscpu = host.lscpu()
    mi = host.meminfo()
    hw = []
    for k in ("Model name", "Socket(s)", "Core(s) per socket", "Thread(s) per core", "NUMA node(s)",
              "CPU MHz", "CPU max MHz", "L3 cache", "Hypervisor vendor", "Virtualization type"):
        if k in lscpu:
            hw.append((k, lscpu[k]))
    if mi:
        for k in ("MemTotal", "MemAvailable", "SwapTotal", "HugePages_Total", "Hugepagesize",
                  "AnonHugePages", "Committed_AS", "CommitLimit", "Shmem", "Dirty"):
            if k in mi:
                hw.append((k, fmt_bytes_kb(mi[k]) if k not in ("HugePages_Total",) else mi[k]))
    for line in host.bbbp.get("uptime", []):
        if line.strip():
            hw.append(("uptime на старте", line.strip()))
    rel = [x for x in host.bbbp.get("/etc/release", []) if x.startswith("PRETTY_NAME=")]
    if rel:
        hw.append(("дистрибутив", rel[0].split("=", 1)[1].strip('"Q')))
    if hw:
        rep.kv("Конфигурация (BBBP)", hw)
    secs = sorted(host.series.keys(), key=lambda s: (not s.startswith("CPU"), s))
    compact = [s for s in secs if not re.match(r"^CPU\d+$", s)]
    if host.cpu_cores:
        compact.insert(0, f"CPU001..CPU{len(host.cpu_cores):03d}")
    rep.kv("Секции", [("присутствуют", ", ".join(compact))])
    if host.warnings:
        rep.text("Предупреждения разбора", "\n".join(host.warnings[:20]))
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
        label = name if not re.match(r"^CPU\d+$", name) else f"CPU001..CPU{len(host.cpu_cores):03d}"
        desc = SECTION_INFO.get(name, SECTION_INFO.get("CPUnnn") if re.match(r"^CPU\d+$", name) else ("", ""))
        rows.append([label, len(cols), nvals, desc[1] if desc else "",
                     ", ".join(cols[:12]) + (" ..." if len(cols) > 12 else "")])
    if any(host.top):
        rows.append(["TOP", len(host.files[0].top_columns), sum(len(x) for x in host.top), "mixed",
                     ", ".join(host.files[0].top_columns)])
    if any(host.uarg):
        rows.append(["UARG", 0, sum(len(x) for x in host.uarg), "", "PID, ProgName, FullCommand"])
    rep.table("Секции", ["секция", "колонок", "значений", "ед.", "колонки"], rows)
    rep.table("BBBP (конфигурационные блоки)", ["блок", "строк"],
              [[c, len(host.bbbp[c])] for c in host.bbbp_order])
    return rep


def analyze_cpu(host, args=None):
    rep = Report("CPU", host.name)
    if not host.has("CPU_ALL"):
        rep.text("", "Секция CPU_ALL отсутствует")
        return rep
    step = host.step()
    busy = host.cpu_busy()
    rows = []
    for label, arr in (("busy (user+sys)", busy), ("user", host.col("CPU_ALL", "User%")),
                       ("sys", host.col("CPU_ALL", "Sys%")), ("wait (iowait)", host.col("CPU_ALL", "Wait%")),
                       ("idle", host.col("CPU_ALL", "Idle%")), ("steal", host.col("CPU_ALL", "Steal%"))):
        if arr is None:
            continue
        s = series_stats(arr, host.times)
        rows.append([label, s["mean"], s["median"], s["p95"], s["max"], s["max_time"], s["min"]])
    rep.table("Сводка CPU_ALL, %", ["метрика", "avg", "median", "p95", "max", "время max", "min"], rows)
    ncpu = host.ncpus()
    thr_rows = []
    for thr in (50, 70, 80, 90, 95):
        sec = time_above(busy, thr, step)
        thr_rows.append([f"busy > {thr}%", fmt_dur(sec), 100.0 * count_above(busy, thr) / max(1, len(clean(busy)))])
    w = host.col("CPU_ALL", "Wait%")
    if w is not None:
        for thr in (5, 10, 25):
            thr_rows.append([f"wait > {thr}%", fmt_dur(time_above(w, thr, step)),
                             100.0 * count_above(w, thr) / max(1, len(clean(w)))])
    rep.table("Время выше порогов", ["условие", "время", "% снимков"], thr_rows, prec={"% снимков": 1})
    peaks = top_peaks(busy, host.times, n=_opt(args, "top", 5) or 5, min_gap=2)
    peak_rows = []
    u, s_, wv = host.col("CPU_ALL", "User%"), host.col("CPU_ALL", "Sys%"), host.col("CPU_ALL", "Wait%")
    rq = host.col("PROC", "Runnable")
    for t, v in peaks:
        i = host.times.index(t)
        peak_rows.append([t, v, u[i] if u is not None else NAN, s_[i] if s_ is not None else NAN,
                          wv[i] if wv is not None else NAN, rq[i] if rq is not None else NAN,
                          _top_proc_at(host, i)])
    rep.table("Пики busy", ["время", "busy%", "user%", "sys%", "wait%", "runq", "топ-процесс"], peak_rows)
    ep = _episodes(host, busy, 80, min_len=2)
    if ep:
        rep.table("Эпизоды насыщения: busy > 80% два и более снимка подряд", ["начало", "конец", "длительность", "max%", "avg%", "топ-процесс"],
                  ep[:_opt(args, "top", 5) or 5], total=len(ep))
    if w is not None:
        epw = _episodes(host, w, 10, min_len=2)
        if epw:
            rep.table("Эпизоды iowait > 10% два и более снимка подряд", ["начало", "конец", "длительность", "max%", "avg%", "топ-процесс"],
                      epw[:_opt(args, "top", 5) or 5], total=len(epw))
    # Ядра (без первых снимков файлов: T0001 охватывает неполный интервал и даёт ложные 100% на ядре)
    if host.cpu_cores:
        hx = host.without_first()
        busyx = hx.cpu_busy()
        core_max = _core_busy_max(hx)
        hot = _core_hot_count(hx)
        s = series_stats(core_max, hx.times)
        per_core = []
        for core in hx.cpu_cores:
            cu, cs = hx.col(core, "User%"), hx.col(core, "Sys%")
            cb = [a + b if (a == a and b == b) else NAN for a, b in zip(cu, cs)]
            per_core.append((core, fmean(cb), percentile(cb, 95), fmax(cb), time_above(cb, 90, step)))
        means = [x[1] for x in per_core]
        cv = fstdev(means) / fmean(means) if fmean(means) > 0 else NAN
        hot_low = [hx.times[i] for i in range(hx.n()) if hot[i] > 0 and busyx[i] == busyx[i] and busyx[i] < 50]
        kv = [("ядер (логических CPU)", len(hx.cpu_cores)),
              ("avg busy по ядрам, %", fmean(means)),
              ("разброс средних по ядрам (CV = stdev/avg)", cv),
              ("макс. busy одного ядра: avg / p95 / max, %", f"{s['mean']:.1f} / {s['p95']:.1f} / {s['max']:.1f} (max @ {ts(s['max_time'])})"),
              ("снимков, где ≥1 ядро > 90% busy", f"{count_above(hot, 0)} из {hx.n()}"),
              ("снимков, где ≥1 ядро > 90% при общем busy < 50%",
               f"{len(hot_low)}" + (f" (первый @ {ts(hot_low[0])})" if hot_low else ""))]
        rep.kv("Ядра", kv, note="статистика без первых снимков файлов (T0001, неполный интервал); одно «горячее» ядро при низкой "
                              "общей загрузке = однопоточное узкое место (например, один поток Ignite: checkpoint, exchange, GC-поток)")
        topn = sorted(per_core, key=lambda x: -x[2])[:_opt(args, "top", 5) or 5]
        rep.table("Самые загруженные ядра", ["ядро", "avg%", "p95%", "max%", "время > 90%"],
                  [[c, a, p, mx, fmt_dur(ta)] for c, a, p, mx, ta in topn])
        wait_core = []
        for core in hx.cpu_cores:
            cw = hx.col(core, "Wait%")
            if cw is not None:
                wait_core.append((core, fmean(cw), fmax(cw)))
        if wait_core:
            wc = sorted(wait_core, key=lambda x: -x[1])[:3]
            if wc[0][1] > 1:
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
    step = host.step()
    hx = host.without_first()
    rows = []
    for core in hx.cpu_cores:
        cu, cs, cw, cst = (hx.col(core, "User%"), hx.col(core, "Sys%"), hx.col(core, "Wait%"),
                           hx.col(core, "Steal%"))
        cb = [a + b if (a == a and b == b) else NAN for a, b in zip(cu, cs)]
        rows.append([core, fmean(cb), percentile(cb, 95), fmax(cb), fmean(cu), fmean(cs),
                     fmean(cw) if cw is not None else NAN, fmax(cst) if cst is not None else NAN,
                     time_above(cb, 90, step)])
    sort = _opt(args, "sort", "p95") or "p95"
    key = {"avg": 1, "p95": 2, "max": 3, "sys": 5, "wait": 6}.get(sort, 2)
    rows.sort(key=lambda r: -(r[key] if r[key] == r[key] else -1))
    top = _opt(args, "top", None)
    total = len(rows)
    if top:
        rows = rows[:top]
    rep.table("Ядра", ["ядро", "avg busy%", "p95 busy%", "max busy%", "avg user%", "avg sys%",
                       "avg wait%", "max steal%", "время > 90%"], rows, total=total, prec={"время > 90%": "dur"},
              note="сортировка: " + sort + "; без первых снимков файлов (T0001, неполный интервал)")
    # Топология из lscpu
    lscpu = host.lscpu()
    topo = [(k, lscpu[k]) for k in ("Socket(s)", "Core(s) per socket", "Thread(s) per core", "NUMA node(s)",
                                    "NUMA node0 CPU(s)", "NUMA node1 CPU(s)", "On-line CPU(s) list") if k in lscpu]
    if topo:
        rep.kv("Топология (lscpu)", topo)
    # Ядра, которые почти не используются (cpuset/isolcpus/IRQ-only), и разбивка по NUMA/сокетам
    core_avg = {}
    core_busy = {}
    for core in host.cpu_cores:
        cu, cs = host.col(core, "User%"), host.col(core, "Sys%")
        cb = [a + b if (a == a and b == b) else NAN for a, b in zip(cu, cs)]
        core_busy[core] = cb
        core_avg[core] = fmean(cb)
    idle = [c for c, v in core_avg.items() if v == v and v < 1.0]
    if idle and len(idle) < len(host.cpu_cores):
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
            for i in range(host.n()):
                v = [core_busy[c][i] for c in cores if core_busy[c][i] == core_busy[c][i]]
                per_snap.append(sum(v) / len(v) if v else NAN)
            nrows.append([f"node{node}", len(cores), fmean(vals), percentile(per_snap, 95), fmax(per_snap)])
        rep.table("Загрузка по NUMA-узлам (avg busy ядер узла)", ["NUMA", "ядер", "avg%", "p95%", "max%"], nrows,
                  note="нумерация nmon CPUnnn = номер CPU ОС + 1; сильный перекос между узлами = проблемы affinity/IRQ/numactl")
    topo_ci = host.cpuinfo_topology()
    if topo_ci:
        phys = defaultdict(list)
        for p, (sock, coreid) in topo_ci.items():
            phys[(sock, coreid)].append(f"CPU{p + 1:03d}")
        both_busy = 0
        any_busy = 0
        firsts = host.first_snapshot_indices()
        for i in range(host.n()):
            if i in firsts:
                continue
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
            ("физических ядер / логических CPU", f"{len(phys)} / {len(topo_ci)}"),
            ("макс. физических ядер с хотя бы одним потоком > 80%", any_busy),
            ("макс. физических ядер с обоими HT-потоками > 80%", both_busy),
        ], note="без первых снимков файлов; если оба HT-потока ядра заняты, реальная производительность на поток ниже номинальной")
    return rep


def _episodes(host, arr, thr, min_len=2):
    """Непрерывные эпизоды arr > thr длиной ≥ min_len снимков: [начало, конец, длительность, max, avg, топ-процесс]."""
    step = host.step()
    rows = []
    for s, e, mx in runs_above(arr, thr, min_len=min_len):
        seg = [v for v in arr[s:e + 1] if v == v]
        rows.append([host.times[s], host.times[e], fmt_dur((e - s + 1) * step), mx, sum(seg) / len(seg) if seg else NAN,
                     _top_proc_at(host, s + argmax(arr[s:e + 1]))])
    rows.sort(key=lambda r: -(r[3] if r[3] == r[3] else 0))
    return rows


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
    rows = []
    for label, arr in (("memfree", host.col("MEM", "memfree")), ("cached (включая shmem)", host.col("MEM", "cached")),
                       ("buffers", host.col("MEM", "buffers")), ("used (total-free-cached-buffers)", host.mem_used()),
                       ("avail ≈ free+buffers+(cached−shmem)+slab", host.mem_avail()),
                       ("active", host.col("MEM", "active")), ("inactive", host.col("MEM", "inactive")),
                       ("memshared (Shmem/tmpfs)", host.col("MEM", "memshared")),
                       ("swap used", host.swap_used()), ("swapcached", host.col("MEM", "swapcached"))):
        if arr is None:
            continue
        c = clean(arr)
        if not c or all(v < 0 for v in c):
            continue
        s = series_stats(arr, host.times)
        rows.append([label, s["first"], s["mean"], s["min"], s["min_time"], s["max"], s["max_time"], s["last"],
                     100.0 * s["last"] / total if total else NAN])
    mi = host.meminfo()
    calib = ""
    if mi.get("MemAvailable") and host.mem_avail() and host.mem_avail()[0] == host.mem_avail()[0]:
        calib = f"; MemAvailable ядра на старте = {fmt_bytes_kb(mi['MemAvailable'])} (оценка avail в первом снимке {fmt_mb(host.mem_avail()[0])})"
    rep.table("Сводка MEM (значения в MB; в тексте — в удобных единицах)",
              ["метрика", "начало", "avg", "min", "время min", "max", "время max", "конец", "% от total (конец)"],
              rows, prec={"начало": "mb", "avg": "mb", "min": "mb", "max": "mb", "конец": "mb"},
              note=f"memtotal = {fmt_mb(total)}; swaptotal = {fmt_mb(fmax(host.col('MEM', 'swaptotal')))}{calib}")
    # Тренды
    trows = []
    for label, arr, limit in (("used", host.mem_used(), total), ("cached", host.col("MEM", "cached"), None),
                              ("memfree", host.col("MEM", "memfree"), None),
                              ("swap used", host.swap_used(), fmax(host.col("MEM", "swaptotal")))):
        if arr is None:
            continue
        tr = trend(arr, host.times)
        last = series_stats(arr, host.times)["last"]
        tte = time_to_limit(last, tr["slope_per_h"], limit) if limit else NAN
        reliable = tr["r2"] == tr["r2"] and tr["r2"] >= 0.7
        trows.append([label, tr["slope_per_h"], tr["r2"], tr["delta"],
                      tte * 3600 if (tte == tte and reliable) else NAN])
    rep.table("Тренды (линейная регрессия)", ["метрика", "наклон, MB/ч", "r²", "конец − начало", "до исчерпания при таком росте"],
              trows, prec={"наклон, MB/ч": 0, "r²": 2, "конец − начало": "mb", "до исчерпания при таком росте": "dur"},
              note="r² близко к 1 = устойчивый линейный рост (утечка/накопление); низкое r² = колебания; "
                   "«конец − начало» — разница последнего и первого значений (не из регрессии); "
                   "время до исчерпания показано только при r² ≥ 0.7")
    # Минимум свободной памяти и что было в этот момент
    avail = host.mem_avail()
    i = argmin(avail)
    if i >= 0:
        ctx = [("время", host.times[i]), ("avail, MB", avail[i]), ("memfree, MB", host.col("MEM", "memfree")[i]),
               ("cached, MB", host.col("MEM", "cached")[i])]
        for name in ("vm.pageoutrun", "vm.pgmajfault", "vm.pswpout", "vm.allocstall"):
            r = resolve_metric(host, name)
            if r:
                ctx.append((name, r[2][i]))
        ctx.append(("топ-процесс", _top_proc_at(host, i)))
        rep.kv("Момент минимума доступной памяти", ctx, prec={"avail, MB": "mb", "memfree, MB": "mb", "cached, MB": "mb"})
    if any(host.top):
        used = host.mem_used()
        diffs = []
        for i, procs in enumerate(host.top):
            if not procs or used is None or used[i] != used[i]:
                continue
            rss_sum = sum(p.rss for p in procs if p.rss == p.rss) / 1024.0
            diffs.append(used[i] - rss_sum)
        if diffs:
            shl = []
            for procs in host.top:
                s_ = sum(p.shlib for p in procs if p.shlib == p.shlib) / 1024.0
                if procs:
                    shl.append(s_)
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
        rep.kv("/proc/meminfo на старте nmon (BBBP), значения в KB",
               [(k, mi[k]) for k in keys if k in mi],
               prec={k: "kb" for k in keys if k not in counts},
               note="однократный снимок в момент запуска nmon, не временной ряд; в JSON — числа в KB")
    return rep


def analyze_vm(host, args=None):
    rep = Report("Подкачка и виртуальная память (VM)", host.name)
    if not host.has("VM"):
        rep.text("", "Секция VM отсутствует")
        return rep
    step = host.step()
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
    for label, name in specs:
        r = resolve_metric(host, name)
        if not r:
            continue
        arr = r[2]
        s = series_stats(arr, host.times)
        nz = sum(1 for v in arr if v == v and v > 0)
        rows.append([label, s["mean"], s["p95"], s["max"], s["max_time"], fsum(arr) if "интервал" in label else NAN, nz])
    rep.table("Сводка VM", ["метрика", "avg", "p95", "max", "время max", "сумма за период", "снимков > 0"], rows,
              prec={"avg": 1, "p95": 1, "max": 1, "сумма за период": 0},
              note="pgpgin/pgpgout — обмен с блочными устройствами (включая page cache); "
                   "pswpin/pswpout > 0 = реальная подкачка (swap); pgscan_direct/allocstall > 0 = прямой reclaim "
                   "(процесс сам ждёт освобождения памяти); kswapd_* = фоновый reclaim")
    nd = resolve_metric(host, "vm.nr_dirty")
    wb = resolve_metric(host, "vm.nr_writeback")
    dw = resolve_metric(host, "disk.write")
    if nd and clean(nd[2]):
        kv = [("nr_dirty avg / max", f"{fmt_mb(fmean(nd[2]))} / {fmt_mb(fmax(nd[2]))} @ {ts(series_stats(nd[2], host.times)['max_time'])}")]
        if dw and fmean(dw[2]) > 0:
            kv.append(("время сброса max dirty при средней скорости записи", fmt_dur(fmax(nd[2]) * 1024.0 / fmean(dw[2]))))
        if wb and clean(wb[2]):
            kv.append(("nr_writeback max / снимков > 0", f"{fmt_mb(fmax(wb[2]))} / {count_above(wb[2], 0)} из {host.n()}"))
        rep.kv("Грязные страницы page cache (ожидают записи на диск)", kv,
               note="большой dirty-backlog в момент fsync = долгий fsync (WAL, завершение checkpoint); "
                    "постоянно ненулевой nr_writeback = диск не успевает за сбросом")
    # Интерпретация
    notes = []
    for name, text in (("vm.pswpout", "были выгрузки в swap"), ("vm.pswpin", "были загрузки из swap"),
                       ("vm.allocstall", "были direct-reclaim stalls (нехватка памяти, задержки в аллокациях)"),
                       ("vm.pgscan_direct", "было прямое сканирование страниц (memory pressure)"),
                       ("vm.kswapd_steal", "kswapd освобождал страницы (фоновый reclaim, давление на page cache)"),
                       ("vm.pageoutrun", "kswapd просыпался (фоновый reclaim: свободной памяти меньше watermark)"),
                       ("vm.slabs_scanned", "сканировался slab (reclaim затронул кэши ядра)")):
        r = resolve_metric(host, name)
        if r and count_above(r[2], 0) > 0:
            notes.append(f"{name}: {text}; снимков > 0: {count_above(r[2], 0)} из {host.n()}, сумма: {fsum(r[2]):.0f}")
    ks = resolve_metric(host, "top.kswapd.cpu")
    if ks and count_above(ks[2], 0) > 0:
        notes.append(f"kswapd0 в TOP: {count_above(ks[2], 0)} снимков, CPU avg {fmean(ks[2]):.1f}%, max {fmax(ks[2]):.1f}% — фоновый reclaim работает")
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
                 "Признаки reclaim на новых ядрах смотрите по pageoutrun, slabs_scanned, pgdeactivate, kswapd0 в TOP, memfree.")
    return rep


def analyze_proc(host, args=None):
    rep = Report("Планировщик: очередь, блокировки, переключения контекста", host.name)
    if not host.has("PROC"):
        rep.text("", "Секция PROC отсутствует")
        return rep
    ncpu = host.ncpus()
    step = host.step()
    rows = []
    for label, col in (("Runnable (очередь)", "Runnable"), ("Blocked (D-state)", "Blocked"),
                       ("pswitch, /s", "pswitch"), ("fork, /s", "fork"), ("syscall, /s", "syscall"),
                       ("read, /s", "read"), ("write, /s", "write"), ("exec, /s", "exec")):
        arr = host.col("PROC", col)
        if arr is None:
            continue
        c = clean(arr)
        if not c or all(v < 0 for v in c):
            continue
        s = series_stats(arr, host.times)
        rows.append([label, s["mean"], s["median"], s["p95"], s["max"], s["max_time"]])
    rep.table("Сводка PROC", ["метрика", "avg", "median", "p95", "max", "время max"], rows,
              note=f"CPU = {ncpu}; Runnable > CPU = очередь на выполнение (CPU-насыщение); Blocked = процессы в D-state (ждут I/O)")
    rq = host.col("PROC", "Runnable")
    bl = host.col("PROC", "Blocked")
    thr_rows = []
    if rq is not None and ncpu:
        for f in (1.0, 2.0):
            thr_rows.append([f"Runnable > {f:.0f}×CPU ({f * ncpu:.0f})", fmt_dur(time_above(rq, f * ncpu, step)),
                             count_above(rq, f * ncpu)])
    if bl is not None:
        for thr in (1, 5, 20):
            thr_rows.append([f"Blocked > {thr}", fmt_dur(time_above(bl, thr, step)), count_above(bl, thr)])
    if thr_rows:
        rep.table("Время выше порогов", ["условие", "время", "снимков"], thr_rows)
    if bl is not None:
        peaks = top_peaks(bl, host.times, n=_opt(args, "top", 5) or 5, min_gap=2)
        w = host.col("CPU_ALL", "Wait%")
        dbusy, dwho = host.disk_max_busy()
        prow = []
        for t, v in peaks:
            if v <= 0:
                continue
            i = host.times.index(t)
            prow.append([t, v, w[i] if w is not None else NAN,
                         f"{dwho[i]} {dbusy[i]:.0f}%" if dbusy is not None and dbusy[i] == dbusy[i] else "-",
                         _top_proc_at(host, i)])
        if prow:
            rep.table("Пики Blocked", ["время", "blocked", "wait%", "самый занятый диск", "топ-процесс"], prow)
    return rep


def _disk_rows(host, devices, args=None):
    step = host.step()
    dm = host.dm_map()
    dmap = {e["device"]: e for e in host.device_map()}
    rows = []
    for d in devices:
        busy = host.col("DISKBUSY", d)
        rd = host.col("DISKREAD", d)
        wr = host.col("DISKWRITE", d)
        xf = host.col("DISKXFER", d)
        bs = host.col("DISKBSIZE", d)
        sb = series_stats(busy, host.times) if busy is not None else None
        e = dmap.get(d, {})
        name = d + (f" ({dm[d]})" if d in dm else "")
        stalled = 0
        if busy is not None and xf is not None:
            stalled = sum(1 for b, x in zip(busy, xf) if b == b and x == x and b >= 95 and x < 1)
        mount = e.get("mount", "") or ""
        if not mount and e.get("child_mounts"):
            cm = e["child_mounts"]
            mount = "LVM/разделы: " + ", ".join(cm[:3]) + (f" (+{len(cm) - 3})" if len(cm) > 3 else "")
        rows.append([
            name, mount,
            sb["mean"] if sb else NAN, sb["p95"] if sb else NAN, sb["max"] if sb else NAN,
            sb["max_time"] if sb else None,
            time_above(busy, 80, step) if busy is not None else NAN,
            fmean(rd) if rd is not None else NAN, fmax(rd) if rd is not None else NAN,
            fmean(wr) if wr is not None else NAN, fmax(wr) if wr is not None else NAN,
            fmean(xf) if xf is not None else NAN, fmax(xf) if xf is not None else NAN,
            _io_size(rd, wr, xf),
            _svc_estimate(busy, xf),
            stalled,
            fsum(rd) * step if rd is not None else NAN,
            fsum(wr) * step if wr is not None else NAN,
        ])
    return rows


def _io_size(rd, wr, xf):
    """Средний размер операции, KB = Σ(read+write) / Σ IOPS (взвешенно по операциям, без искажения простоями)."""
    if xf is None or fsum(xf) <= 0:
        return NAN
    tot = (fsum(rd) if rd is not None else 0.0) + (fsum(wr) if wr is not None else 0.0)
    return tot / fsum(xf)


DISK_PREC = {"IO size avg KB": 1, "svc≈ms": 2, "stalled": 0, "время > 80%": "dur", "прочитано всего": "kb", "записано всего": "kb"}


def link_capacity_kbs(mbit):
    """Пропускная способность линка в KB/s (KiB, как в nmon) по скорости в Mbit/s."""
    return float(mbit) * 1e6 / 8.0 / 1024.0


def _svc_estimate(busy, xf):
    """Оценка среднего времени обслуживания одной операции, ms = util% × 10 / IOPS (медиана по снимкам с IOPS ≥ 10).
    Это грубая нижняя оценка латентности (без учёта очереди); для NVMe с параллелизмом занижает."""
    if busy is None or xf is None:
        return NAN
    vals = [b * 10.0 / x for b, x in zip(busy, xf) if b == b and x == x and x >= 10]
    return fmedian(vals) if vals else NAN


DISK_COLS = ["устройство", "mount", "busy avg%", "busy p95%", "busy max%", "время max", "время > 80%",
             "read avg KB/s", "read max KB/s", "write avg KB/s", "write max KB/s", "IOPS avg", "IOPS max",
             "IO size avg KB", "svc≈ms", "stalled", "прочитано всего", "записано всего"]


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
    rows = _disk_rows(host, devices, args)
    active = [r for r in rows if not (r[2] != r[2] and r[7] != r[7])]
    active.sort(key=lambda r: -(r[3] if r[3] == r[3] else -1))
    rep.table("Устройства" + (" (все, включая разделы и dm-*)" if _opt(args, "all", False) else " (физические; разделы и dm-* см. --all или --dev)"),
              DISK_COLS, active, prec=DISK_PREC,
              note="busy% = доля времени, когда у устройства была хотя бы одна операция в очереди (util); "
                   "для NVMe/RAID 100% ещё не означает предел производительности; IO size = Σ(read+write)/Σ IOPS; "
                   "svc≈ms = util×10/IOPS — грубая оценка времени на операцию; stalled = снимков с busy ≥ 95% при IOPS < 1; "
                   "для физического диска в колонке mount перечислены точки монтирования его LV/разделов")
    # Всего по физическим дискам
    rt, wt, xt = host.disk_total("DISKREAD"), host.disk_total("DISKWRITE"), host.disk_total("DISKXFER")
    if rt is not None:
        step = host.step()
        rep.kv("Итого по физическим дискам", [
            ("read avg / max, KB/s", f"{fmean(rt):.0f} / {fmax(rt):.0f}"),
            ("write avg / max, KB/s", f"{fmean(wt):.0f} / {fmax(wt):.0f}"),
            ("IOPS avg / max", f"{fmean(xt):.0f} / {fmax(xt):.0f}" if xt is not None else "-"),
            ("прочитано / записано за период", f"{fmt_bytes_kb(fsum(rt) * step)} / {fmt_bytes_kb(fsum(wt) * step)}"),
            ("доля записи в трафике", f"{100.0 * fsum(wt) / max(1e-9, fsum(rt) + fsum(wt)):.0f}%"),
        ])
    # Пики записи/чтения и периодичность (checkpoint-подобные всплески); без первых снимков файлов (T0001)
    n_top = _opt(args, "top", 5) or 5
    hx = host.without_first()
    for label, sec in (("записи", "DISKWRITE"), ("чтения", "DISKREAD")):
        for d in devices:
            arr = hx.col(sec, d)
            if arr is None or fmax(arr) < 1024:
                continue
            pr = periodicity(arr, hx.times, hx.step())
            peaks = top_peaks(arr, hx.times, n=n_top, min_gap=1)
            busy = hx.col("DISKBUSY", d)
            bs = hx.col("DISKBSIZE", d)
            prow = []
            for t, v in peaks:
                i = hx.times.index(t)
                prow.append([t, v, busy[i] if busy is not None else NAN, bs[i] if bs is not None else NAN,
                             _top_proc_at(hx, i)])
            note = None
            if pr["regular"]:
                tol = max(0.25 * pr["period"], host.step())
                note = (f"всплески {label} регулярны: медианный период {fmt_dur(pr['period'])}, {pr['npeaks']} пиков ≥ p90, "
                        f"{100 * pr['share_within']:.0f}% интервалов в пределах ±{tol:.0f} с (max(25%, шаг)) от медианы")
            elif pr["period"] == pr["period"]:
                note = (f"пики {label} нерегулярны: {pr['npeaks']} пиков ≥ p90, медианный интервал {fmt_dur(pr['period'])}, "
                        f"разброс MAD/медиана {pr['spread']:.2f} — период не определён")
            if fmean(arr) > 0 and (fmax(arr) > 2 * fmean(arr) or pr["regular"] or pr["npeaks"] >= 6):
                rep.table(f"Пики {label}: {d}", ["время", "KB/s", "busy%", "IO size KB", "топ-процесс"], prow, note=note)
    # Латентность (если есть)
    if host.has("DISKREADSERV") or host.has("DISKWRITESERV"):
        lrows = []
        for d in devices:
            rs, ws = host.col("DISKREADSERV", d), host.col("DISKWRITESERV", d)
            lrows.append([d, fmean(rs) if rs is not None else NAN, percentile(rs, 95) if rs is not None else NAN,
                          fmax(rs) if rs is not None else NAN, fmean(ws) if ws is not None else NAN,
                          percentile(ws, 95) if ws is not None else NAN, fmax(ws) if ws is not None else NAN])
        rep.table("Время обслуживания, ms", ["устройство", "read avg", "read p95", "read max", "write avg", "write p95", "write max"], lrows)
    return rep


def analyze_diskmap(host, args=None):
    rep = Report("Карта устройств: диск → LVM → точка монтирования", host.name)
    rows = []
    for e in host.device_map():
        mount = e.get("mount", "") or ""
        if not mount and e.get("child_mounts"):
            mount = "→ " + ", ".join(e["child_mounts"][:4]) + (" …" if len(e["child_mounts"]) > 4 else "")
        rows.append([e["device"], e.get("type", ""), e.get("size", ""), e.get("phys", "") or "", e.get("parent", "") or "",
                     e.get("lv", ""), mount, e.get("fstype", ""), e.get("fs_use_pct_start", NAN), (e.get("options", "") or "")[:60]])
    rep.table("Устройства nmon", ["устройство", "тип", "размер", "физ. диск", "родитель", "LV", "mount", "fs", "use% на старте", "опции монтирования"],
              rows, note="источники: lsblk (дерево), ls -l /dev/mapper, /proc/partitions, mount, df -m из BBBP; "
                         "«физ. диск» — корень дерева lsblk; для диска без своей ФС в mount перечислены точки монтирования потомков")
    dfrows = host.df()
    if dfrows:
        rep.table("df -m на старте nmon", ["filesystem", "mount", "size", "used", "avail", "use%"],
                  [[r["filesystem"], r["mount"], fmt_mb(r["size_mb"]), fmt_mb(r["used_mb"]), fmt_mb(r["avail_mb"]), r["use_pct"]]
                   for r in dfrows if not r["filesystem"].startswith(("tmpfs", "devtmpfs"))])
    ign = [e for e in host.device_map()
           if re.search(r"ignite|wal|persist|snapshot|archive|marshaller|binary_meta|/db(/|$)|/data(/|$)",
                        (e.get("mount", "") or "") + " " + (e.get("lv", "") or ""), re.I)]
    if ign:
        rep.table("Точки монтирования, похожие на хранилище Ignite (по именам)",
                  ["устройство", "физ. диск", "LV", "mount", "fs", "размер", "use% на старте"],
                  [[e["device"], e.get("phys", ""), e.get("lv", ""), e.get("mount", ""), e.get("fstype", ""), e.get("size", ""), e.get("fs_use_pct_start", NAN)] for e in ign],
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
                          fmt_bytes_kb(s["sectors_read"] / 2.0), fmt_bytes_kb(s["sectors_written"] / 2.0),
                          100.0 * s["io_ticks"] / 1000.0 / up if up else NAN, s["in_flight"]])
        rep.table("/proc/diskstats на старте nmon: накопительно с загрузки ОС",
                  ["устройство", "reads", "writes", "avg read ms", "avg write ms", "avg read KB", "avg write KB",
                   "прочитано", "записано", "util% с загрузки", "in_flight"], lrows,
                  prec={"reads": 0, "writes": 0, "avg read ms": 2, "avg write ms": 2, "in_flight": 0},
                  note="средняя латентность = ms/операцию за всё время с загрузки (включая ожидание в очереди); "
                       "HDD обычно > 5 ms, SSD/NVMe < 1 ms; это не значения за период наблюдения")
    fstab = [x for x in host.bbbp.get("/etc/fstab", []) if x.strip() and not x.strip().startswith("#")]
    if fstab:
        rep.text("/etc/fstab", "\n".join(re.sub(r"\s+", " ", x.strip()) for x in fstab))
    return rep


def analyze_fs(host, args=None):
    rep = Report("Файловые системы (заполненность)", host.name)
    if not host.has("JFSFILE"):
        rep.text("", "Секция JFSFILE отсутствует")
        return rep
    dfrows = {r["mount"]: r for r in host.df()}
    rows = []
    skipped = []
    sel = _opt(args, "mount", None)
    for m in host.cols("JFSFILE"):
        if sel and not any(re.fullmatch(p, m) for p in sel):
            continue
        arr = host.col("JFSFILE", m)
        if arr is None or not clean(arr):
            continue
        fs_dev = dfrows.get(m, {}).get("filesystem", "")
        if not sel and (fs_dev.startswith(("tmpfs", "devtmpfs", "overlay", "squashfs")) or m in ("/dev", "/run", "/sys", "/proc", "/dev/shm")
                        or m.startswith(("/run/", "/sys/"))):
            skipped.append(m)
            continue
        s = series_stats(arr, host.times)
        tr = trend(arr, host.times)
        size_mb = dfrows.get(m, {}).get("size_mb")
        reliable = tr["r2"] == tr["r2"] and tr["r2"] >= 0.7 and tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] >= 0.05
        tte = time_to_limit(s["last"], tr["slope_per_h"], 100.0) if reliable else NAN
        growth_mb_h = tr["slope_per_h"] / 100.0 * size_mb if size_mb else NAN
        rows.append([m, size_mb if size_mb else NAN, s["first"], s["last"], s["min"], s["max"], s["max_time"],
                     s["last"] - s["first"], tr["slope_per_h"], tr["r2"], growth_mb_h, tte * 3600 if tte == tte else NAN,
                     (100 - s["last"]) / 100.0 * size_mb if size_mb else NAN])
    rows.sort(key=lambda r: -(r[3] if r[3] == r[3] else -1))
    rep.table("JFSFILE, % занято", ["mount", "размер", "начало%", "конец%", "min%", "max%", "время max", "Δ% за период",
                                     "рост п.п./ч", "r²", "рост MB/ч", "до 100% при таком росте", "свободно (конец)"],
              rows, prec={"размер": "mb", "рост п.п./ч": 3, "r²": 2, "рост MB/ч": 0, "до 100% при таком росте": "dur", "свободно (конец)": "mb"},
              note="рост оценён линейной регрессией; «до 100%» показано только при r² ≥ 0.7 и росте ≥ 0.05 п.п./ч "
                   "(разрешение JFSFILE 0.1%, на больших ФС шаг = гигабайты)" +
                   (f"; скрыты псевдо-ФС: {', '.join(skipped)} (укажите --mount, чтобы показать)" if skipped else ""))
    # Резкие изменения (освобождение / скачки)
    jumps = []
    for m in host.cols("JFSFILE"):
        arr = host.col("JFSFILE", m)
        if arr is None:
            continue
        for i in range(1, len(arr)):
            if arr[i] == arr[i] and arr[i - 1] == arr[i - 1] and abs(arr[i] - arr[i - 1]) >= 2.0:
                jumps.append([host.times[i], m, arr[i - 1], arr[i], arr[i] - arr[i - 1]])
    if jumps:
        rep.table("Скачки заполненности (≥ 2 п.п. за интервал)", ["время", "mount", "было%", "стало%", "Δ"],
                  jumps[:50], total=len(jumps))
    if host.has("JFSINODE"):
        irows = []
        for m in host.cols("JFSINODE"):
            arr = host.col("JFSINODE", m)
            if arr is not None and clean(arr):
                irows.append([m, fmax(arr), series_stats(arr, host.times)["last"]])
        rep.table("JFSINODE, % inode", ["mount", "max%", "конец%"], irows)
    return rep


def analyze_net(host, args=None):
    rep = Report("Сеть", host.name)
    if not host.has("NET"):
        rep.text("", "Секция NET отсутствует")
        return rep
    step = host.step()
    ifc = host.net_counters()
    roles = host.net_roles()
    rows = []
    sel = _opt(args, "iface", None)
    for i in host.net_ifaces():
        if sel and not any(re.fullmatch(p, i) for p in sel):
            continue
        rd = host.col("NET", f"{i}-read-KB/s")
        wr = host.col("NET", f"{i}-write-KB/s")
        pr = host.col("NETPACKET", f"{i}-read/s")
        pw = host.col("NETPACKET", f"{i}-write/s")
        if rd is None:
            continue
        if fmax(rd) <= 0 and fmax(wr) <= 0 and not _opt(args, "all", False):
            continue
        role = roles.get(i, "nic")
        avg_pkt_in = (fmean(rd) * 1024.0 / fmean(pr)) if pr is not None and fmean(pr) > 0 else NAN
        avg_pkt_out = (fmean(wr) * 1024.0 / fmean(pw)) if pw is not None and fmean(pw) > 0 else NAN
        rows.append([i, role, ifc.get(i, {}).get("mtu", NAN),
                     fmean(rd), percentile(rd, 95), fmax(rd), series_stats(rd, host.times)["max_time"],
                     fmean(wr), percentile(wr, 95), fmax(wr), series_stats(wr, host.times)["max_time"],
                     fmean(pr) if pr is not None else NAN, fmean(pw) if pw is not None else NAN,
                     avg_pkt_in, avg_pkt_out,
                     fmt_bytes_kb(fsum(rd) * step), fmt_bytes_kb(fsum(wr) * step)])
    rows.sort(key=lambda r: -((r[4] if r[4] == r[4] else 0) + (r[8] if r[8] == r[8] else 0)))
    rep.table("Интерфейсы", ["iface", "роль", "mtu", "rx avg KB/s", "rx p95", "rx max", "время rx max",
                             "tx avg KB/s", "tx p95", "tx max", "время tx max", "rx pkt/s", "tx pkt/s",
                             "avg rx pkt B", "avg tx pkt B", "принято всего", "передано всего"],
              rows, prec={"mtu": 0, "rx pkt/s": 0, "tx pkt/s": 0, "avg rx pkt B": 0, "avg tx pkt B": 0},
              note="интерфейсы без трафика скрыты (--all покажет); суммарный трафик хоста считается без lo и bond-слейвов" +
                   ("; роли слейвов определены по трафику (в BBBP нет ifconfig)" if any("по трафику" in r for r in roles.values()) else ""))
    link = _opt(args, "link_mbit", None)
    rt, wt = host.net_total("read"), host.net_total("write")
    if rt is not None:
        kv = [("rx avg / p95 / max, KB/s", f"{fmean(rt):.0f} / {percentile(rt, 95):.0f} / {fmax(rt):.0f}"),
              ("tx avg / p95 / max, KB/s", f"{fmean(wt):.0f} / {percentile(wt, 95):.0f} / {fmax(wt):.0f}"),
              ("принято / передано за период", f"{fmt_bytes_kb(fsum(rt) * step)} / {fmt_bytes_kb(fsum(wt) * step)}")]
        if link:
            cap = link_capacity_kbs(link)
            kv.append((f"использование линка {link} Mbit/s: rx p95 / max", f"{100 * percentile(rt, 95) / cap:.1f}% / {100 * fmax(rt) / cap:.1f}%"))
            kv.append((f"использование линка {link} Mbit/s: tx p95 / max", f"{100 * percentile(wt, 95) / cap:.1f}% / {100 * fmax(wt) / cap:.1f}%"))
        rep.kv("Итого (без lo и bond-слейвов)", kv)
        peaks = top_peaks([a + b for a, b in zip(rt, wt)], host.times, n=_opt(args, "top", 5) or 5, min_gap=2)
        cs = host.col("CPU_ALL", "Sys%")
        rep.table("Пики суммарного трафика", ["время", "rx KB/s", "tx KB/s", "sys%", "топ-процесс"],
                  [[t, rt[host.times.index(t)], wt[host.times.index(t)],
                    cs[host.times.index(t)] if cs is not None else NAN, _top_proc_at(host, host.times.index(t))]
                   for t, _ in peaks])
    # Простои интерфейсов (трафик упал до нуля после активности)
    idle = []
    for i in host.net_primary_ifaces():
        rd = host.col("NET", f"{i}-read-KB/s")
        wr = host.col("NET", f"{i}-write-KB/s")
        if rd is None or fmax(rd) <= 1:
            continue
        tot = [a + b if (a == a and b == b) else NAN for a, b in zip(rd, wr)]
        zero_runs = runs_above([-v if v == v else NAN for v in tot], -0.5, min_len=2)
        for s_, e_, _ in zero_runs:
            idle.append([i, host.times[s_], host.times[e_], fmt_dur((e_ - s_ + 1) * step)])
    if idle:
        rep.table("Отрезки нулевого трафика на активных интерфейсах (возможная изоляция узла)",
                  ["iface", "от", "до", "длительность"], idle[:30], total=len(idle))
    # Конфигурация интерфейсов
    if ifc:
        crow = []
        for i in ifc.values():
            crow.append([i["name"], i["inet"] or "-", i["mtu"], (i["flags"] or "")[:40],
                         i["rx_errors"], i["rx_dropped"], i["tx_errors"], i["tx_dropped"], i.get("source", "ifconfig")])
        rep.table("Счётчики интерфейсов на старте (BBBP): ошибки/дропы — накопительные с загрузки ОС",
                  ["iface", "inet", "mtu", "flags", "rx err", "rx drop", "tx err", "tx drop", "источник"], crow, prec={"mtu": 0})
    if host.has("NETERROR"):
        erows = []
        for c in host.cols("NETERROR"):
            arr = host.col("NETERROR", c)
            if arr is not None and fsum(arr) > 0:
                erows.append([c, fsum(arr), fmax(arr)])
        rep.table("NETERROR (ненулевые)", ["колонка", "сумма", "max"], erows)
    return rep


# --------------------------------------------------------------------------
# Процессы (TOP), JVM, командные строки (UARG)
# --------------------------------------------------------------------------


def _proc_summary_rows(host, groups, n_snap):
    """groups: key -> list[(idx, Proc)]. Возвращает строки сводки."""
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
            fmean(cpu), percentile(cpu, 95), fmax(cpu), host.times[idxs[imax]] if imax >= 0 else None,
            (100.0 * fsum(sy) / max(1e-9, fsum(usr) + fsum(sy))) if (fsum(usr) + fsum(sy)) > 0 else NAN,
            (rss[0] / 1024.0) if rss else NAN, (max(rss) / 1024.0) if rss else NAN, (rss[-1] / 1024.0) if rss else NAN,
            (thr[0]) if thr else NAN, (max(thr)) if thr else NAN, (thr[-1]) if thr else NAN,
            fmean(majf), fmax(majf), fmean(minf), fsum(iow),
        ])
    return rows


PROC_COLS = ["команда", "pid", "снимков", "впервые", "последний", "cpu avg%", "cpu p95%", "cpu max%", "время cpu max",
             "доля sys%", "rss нач. MB", "rss max MB", "rss кон. MB", "thr нач.", "thr max", "thr кон.",
             "majflt avg/s", "majflt max/s", "minflt avg/s", "iowait Σ"]
PROC_NOTE = ("MinorFault/MajorFault в TOP — события в секунду (nmon делит приращение на длительность интервала); "
             "IOwaitTime учитывает только главный поток процесса и для многопоточных JVM неинформативен")


def analyze_top(host, args=None):
    rep = Report("Процессы (секция TOP)", host.name)
    if not any(host.top):
        rep.text("", "Секция TOP отсутствует (nmon запущен без -t) — данных по процессам нет")
        return rep
    n_snap = sum(1 for x in host.top if x)
    pid_filter = _opt(args, "pid", None)
    cmd_filter = _opt(args, "cmd", None)
    by_cmd = _opt(args, "by_cmd", False)
    groups = defaultdict(list)
    for i, procs in enumerate(host.top):
        for p in procs:
            if pid_filter and p.pid not in pid_filter:
                continue
            if cmd_filter and not any(re.search(c, p.cmd) for c in cmd_filter):
                continue
            key = (p.cmd, "*") if by_cmd else (p.cmd, p.pid)
            groups[key].append((i, p))
    rows = _proc_summary_rows(host, groups, n_snap)
    sort = _opt(args, "sort", "cpu") or "cpu"
    keyidx = {"cpu": 5, "cpumax": 7, "rss": 11, "threads": 14, "majflt": 16, "sys": 9, "snapshots": 2}.get(sort, 5)
    rows.sort(key=lambda r: -(r[keyidx] if r[keyidx] == r[keyidx] else -1))
    total = len(rows)
    n_top = _opt(args, "top", 20) or 20
    if not (pid_filter or cmd_filter):
        rows = rows[:n_top]
    rep.table("Сводка по процессам" + (" (сгруппировано по команде)" if by_cmd else ""), PROC_COLS, rows, total=total,
              prec={"pid": 0, "rss нач. MB": 0, "rss max MB": 0, "rss кон. MB": 0, "thr нач.": 0, "thr max": 0,
                    "thr кон.": 0, "majflt avg/s": 1, "majflt max/s": 0, "minflt avg/s": 0, "iowait Σ": 0},
              note=f"снимков с TOP: {n_snap}; в TOP попадают только процессы с заметным CPU в интервале, "
                   f"поэтому отсутствие процесса в снимке ≠ он не работал; сортировка: {sort}; {PROC_NOTE}")
    # Сумма CPU процессов vs CPU_ALL
    sum_cpu = _top_sum_cpu(host)
    busy = host.cpu_busy()
    ncpu = host.ncpus()
    if busy is not None and ncpu:
        # %CPU в TOP — в процентах одного ядра; CPU_ALL — в % от всех ядер
        sys_pct = [v / ncpu if v == v else NAN for v in sum_cpu]
        diff = [b - s if (b == b and s == s) else NAN for b, s in zip(busy, sys_pct)]
        rep.kv("Учёт CPU: сумма %CPU процессов (в % от всех CPU) vs CPU_ALL busy", [
            ("сумма TOP avg / max, % всех CPU", f"{fmean(sys_pct):.1f} / {fmax(sys_pct):.1f}"),
            ("CPU_ALL busy avg / max, %", f"{fmean(busy):.1f} / {fmax(busy):.1f}"),
            ("неучтённое в TOP (busy − сумма) avg, п.п.", fmean(diff)),
        ], note="большая неучтённая доля = много мелких процессов ниже порога TOP либо прерывания/softirq/kernel-потоки")
    # Появления/исчезновения (перезапуски)
    changes = _pid_changes(host)
    if changes:
        rep.table("Смена PID у команд (перезапуск процесса)", PID_CHANGE_COLS, changes[:30], total=len(changes), prec=PID_CHANGE_PREC)
    return rep


PROC_CATEGORIES = [
    (r"^(kswapd|kcompactd|khugepaged|oom_reaper)", "ядро: память/reclaim/THP"),
    (r"^(kworker|jbd2|xfsaild|flush-|writeback|md\d+_raid|md\d+_resync|dmcrypt|kdmwork|kcopyd|nvme|scsi_eh|kblockd|loop\d)", "ядро: I/O/writeback"),
    (r"^(ksoftirqd|irq/|rcu_|migration|watchdog|kthreadd|cpuhp)", "ядро: прерывания/планировщик"),
    (r"^(zabbix|node_exporter|telegraf|collectd|datadog|dd-agent|nrpe|snmpd|filebeat|fluent|promtail|metricbeat|wazuh|osquery|sleepydog|mpstat|pidstat|iostat|sar$|sadc|vmstat|nmon|hlar|splunk|vector|logstash)", "мониторинг/агенты"),
    (r"^(clamd|clamav|kesl|klnagent|drweb|savd|falcon|cs-?agent|mfe|mcafee|symantec|sophos|tanium|crowdstrike|freshclam|kaspersky|avp)", "антивирус/безопасность"),
    (r"^(rsync|tar|gzip|bzip2|xz|zstd|pigz|bacula|bpbkar|nbjm|veeam|borg|restic|dd$|cp$|scp|sftp|rclone|aws|s3cmd|mc$)", "бэкап/копирование/сжатие"),
    (r"^(jstack|jmap|jcmd|jfr|jinfo|jstat|control\.sh|ignitevisor)", "JVM-диагностика/утилиты Ignite"),
    (r"^java", "JVM"),
    (r"^(postgres|mysqld|mariadbd|oracle|redis|mongod|kafka|zookeeper|etcd|elasticsearch|clickhouse)", "другая СУБД/брокер"),
    (r"^(sshd|bash|sh$|python|perl|ruby|ansible|salt|puppet|chef|crond|cron|systemd|dbus|rsyslog|journal|tuned|NetworkManager|polkitd|auditd|sssd|chronyd|ntpd)", "система/скрипты"),
]


def proc_category(cmd):
    for pat, cat in PROC_CATEGORIES:
        if re.search(pat, cmd):
            return cat
    return "прочее"


def _pid_changes(host, cmds=("java",)):
    """Перезапуски процессов команд cmds по времени жизни каждого PID: PID X исчез до конца данных, и ПОСЛЕ его
    последнего появления впервые появился PID Y той же команды (не существовавший одновременно с X).
    Строки: [команда, старый pid, последний раз, новый pid, впервые, между, RSS нового MB, RSS старого MB]."""
    life = {}  # pid -> [cmd, first_idx, last_idx, first_proc, last_proc]
    for i, procs in enumerate(host.top):
        for p in procs:
            if not any(p.cmd == c or p.cmd.startswith(c) for c in cmds):
                continue
            L = life.get(p.pid)
            if L is None:
                life[p.pid] = [p.cmd, i, i, p, p]
            else:
                L[2] = i
                L[4] = p
    last_top = max((i for i, x in enumerate(host.top) if x), default=-1)
    by_cmd = defaultdict(list)
    for pid, L in life.items():
        by_cmd[L[0]].append((pid, L))
    out = []
    used_new = set()
    for cmd, items in by_cmd.items():
        def is_dominant(pid, L):
            # основной процесс: в момент последнего появления у него наибольшая RSS среди процессов той же команды
            rss_old = L[4].rss if L[4].rss == L[4].rss else -1.0
            others = [p.rss for p in host.top[L[2]] if p.cmd == cmd and p.pid != pid and p.rss == p.rss]
            return not others or rss_old >= max(others)
        vanished = [(pid, L) for pid, L in items if L[2] < last_top]
        # сначала основные процессы и те, что исчезли позже: они получают ближайший новый PID
        vanished.sort(key=lambda kv: (0 if is_dominant(kv[0], kv[1]) else 1, -kv[1][2]))
        for pid, L in vanished:
            cands = [(q, M) for q, M in items if M[1] > L[2] and q not in used_new and q != pid]
            if not cands:
                continue
            q, M = min(cands, key=lambda kv: kv[1][1])
            used_new.add(q)
            gap = (host.times[M[1]] - host.times[L[2]]).total_seconds()
            out.append([cmd, pid, host.times[L[2]], q, host.times[M[1]], fmt_dur(gap),
                        M[3].rss / 1024.0 if M[3].rss == M[3].rss else NAN,
                        L[4].rss / 1024.0 if L[4].rss == L[4].rss else NAN,
                        "основной" if is_dominant(pid, L) else "вспомогательный"])
    out.sort(key=lambda r: r[4])
    return out


PID_CHANGE_COLS = ["команда", "старый pid", "последний раз", "новый pid", "впервые", "между", "RSS нового MB", "RSS старого MB", "роль"]
PID_CHANGE_PREC = {"старый pid": 0, "новый pid": 0, "RSS нового MB": 0, "RSS старого MB": 0}


def analyze_at(host, args=None):
    """Срез всех метрик в момент времени (ближайший снимок) ± окно."""
    when = _opt(args, "time", None)
    rep = Report("Срез на момент времени", host.name)
    if not host.times:
        rep.text("", "нет снимков")
        return rep
    try:
        t = parse_user_time(when, host.times[0]) if when else host.times[argmax(host.cpu_busy() or [0])]
    except ValueError as e:
        raise SystemExit(f"ERROR: --time: {e}")
    if when and re.match(r"^\d{1,2}:\d{2}(:\d{2})?$", when.strip()) and t < host.times[0] and host.times[-1].date() != host.times[0].date():
        t += timedelta(days=1)
    i = min(range(host.n()), key=lambda k: abs((host.times[k] - t).total_seconds()))
    wv = _opt(args, "window_snaps", None)
    win = 2 if wv is None else max(0, int(wv))
    lo, hi = max(0, i - win), min(host.n(), i + win + 1)
    dist = abs((host.times[i] - t).total_seconds())
    items = [("запрошено", t), ("ближайший снимок", host.times[i]), ("id", host.snap_ids[i]),
             ("окно", f"{host.times[lo]} .. {host.times[hi - 1]}")]
    if dist > host.step() * 1.5:
        items.append(("ВНИМАНИЕ", f"запрошенный момент вне периода данных ({ts(host.start())} .. {ts(host.end())}), "
                                  f"ближайший снимок отстоит на {fmt_dur(dist)}"))
        warn(f"{host.name}: момент {ts(t)} вне периода данных, ближайший снимок {ts(host.times[i])}")
    rep.kv("Снимок", items)
    explicit = bool(_opt(args, "metrics", None))
    metrics = _opt(args, "metrics", None) or DEFAULT_TIMELINE
    resolved = resolve_metrics(host, metrics, warn_missing=explicit)
    cols = ["время"] + [f"{m} [{r[1]}]" if r[1] else m for m, r in resolved]
    rows = []
    for k in range(lo, hi):
        row = [host.times[k]]
        for m, r in resolved:
            row.append(r[2][k])
        rows.append(row)
    rep.table("Ключевые метрики вокруг момента", cols, rows,
              prec={c: 0 for c, (m, _r) in zip(cols[1:], resolved) if m.startswith(("disk.", "net.", "mem.", "top.java.rss"))})
    # Процессы в этот момент
    procs = sorted(host.top[i], key=lambda p: -(p.cpu if p.cpu == p.cpu else -1))[:_opt(args, "top", 15) or 15]
    if procs:
        rep.table(f"TOP в {ts(host.times[i])}", ["pid", "команда", "%CPU", "%usr", "%sys", "RSS MB", "threads", "majflt", "iowait"],
                  [[p.pid, p.cmd, p.cpu, p.usr, p.sys, p.rss / 1024.0 if p.rss == p.rss else NAN, p.threads, p.majflt, p.iowait]
                   for p in procs], prec={"pid": 0, "RSS MB": 0, "threads": 0, "majflt": 0, "iowait": 0})
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
        nrows = []
        for iface in host.net_ifaces():
            rd, wr = host.col("NET", f"{iface}-read-KB/s"), host.col("NET", f"{iface}-write-KB/s")
            if rd is None or (rd[i] < 1 and wr[i] < 1):
                continue
            nrows.append([iface, rd[i], wr[i]])
        rep.table("Сеть в этот момент", ["iface", "rx KB/s", "tx KB/s"], nrows)
    # Ядра > 90%
    hot = []
    for core in host.cpu_cores:
        u, s = host.col(core, "User%")[i], host.col(core, "Sys%")[i]
        if u == u and s == s and u + s > 90:
            hot.append(f"{core}={u + s:.0f}%")
    if hot:
        rep.text("Ядра с busy > 90%", ", ".join(hot))
    return rep


JVM_FLAG_PATTERNS = [
    ("heap Xms", r"-Xms(\S+)"), ("heap Xmx", r"-Xmx(\S+)"), ("young Xmn", r"-Xmn(\S+)"),
    ("thread stack Xss", r"-Xss(\S+)"), ("MaxDirectMemorySize", r"-XX:MaxDirectMemorySize=(\S+)"),
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


def jvm_flags(cmdline):
    """Извлечь ключевые параметры JVM/Ignite из командной строки: список (имя, значение)."""
    flags = []
    for label, pat in JVM_FLAG_PATTERNS:
        m = re.search(pat, cmdline)
        if m:
            flags.append((label, m.group(1) if m.groups() else m.group(0)))
    for k, v in re.findall(r"-D(IGNITE_\w+)=(\S+)", cmdline):
        flags.append((k, v))
    xx = re.findall(r"-XX:[+-]?\w+(?:=\S+)?", cmdline)
    if xx:
        flags.append(("все -XX", " ".join(xx)))
    return flags


def analyze_uarg(host, args=None):
    rep = Report("Командные строки процессов (UARG) и параметры JVM", host.name)
    cl = host.uarg_cmdlines()
    if not cl:
        rep.text("", "Секция UARG отсутствует (nmon запущен без -T). Параметры JVM недоступны; "
                     "используйте логи Ignite или `ps` с узла.")
        return rep
    cmd_filter = _opt(args, "cmd", None)
    rows = []
    for pid, (prog, full, first) in sorted(cl.items(), key=lambda kv: kv[1][2]):
        if cmd_filter and not any(re.search(c, prog) or re.search(c, full) for c in cmd_filter):
            continue
        rows.append([pid, prog, first, full if _opt(args, "full", False) else (full[:200] + ("…" if len(full) > 200 else ""))])
    rep.table("Процессы", ["pid", "prog", "впервые", "командная строка"], rows, prec={"pid": 0},
              note="полная строка: --full")
    jp = host.java_procs()
    for pid, (prog, full, first) in cl.items():
        if prog != "java" and "java" not in full.split(" ")[0]:
            continue
        flags = [("роль", jvm_role(full))] + jvm_flags(full)
        rep.kv(f"JVM-параметры java[{pid}]", flags)
        thr_max = fmax([p.threads for _, p in jp.get(pid, [])]) if pid in jp else NAN
        rss_max = fmax([p.rss for _, p in jp.get(pid, [])]) / 1024.0 if pid in jp else NAN
        fp = jvm_footprint(full, thr_max, rss_max)
        if fp:
            rep.kv(f"Оценка памяти java[{pid}] по флагам", fp,
                   note="RSS − (heap + direct + стеки) ≈ off-heap Ignite (data regions, checkpoint buffer) + metaspace + буферы; "
                        "heap может быть занят не полностью, поэтому оценка приблизительная")
    return rep


def _parse_size_mb(s):
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


def jvm_footprint(cmdline, threads_max, rss_max_mb):
    xmx = re.search(r"-Xmx(\S+)", cmdline)
    mdm = re.search(r"-XX:MaxDirectMemorySize=(\S+)", cmdline)
    xss = re.search(r"-Xss(\S+)", cmdline)
    heap = _parse_size_mb(xmx.group(1)) if xmx else NAN
    direct = _parse_size_mb(mdm.group(1)) if mdm else NAN
    stack = _parse_size_mb(xss.group(1)) if xss else 1.0
    stacks = threads_max * stack if threads_max == threads_max else NAN
    if heap != heap and direct != direct:
        return None
    parts = [v for v in (heap, direct, stacks) if v == v]
    total = sum(parts)
    out = [("-Xmx (heap max)", fmt_mb(heap) if heap == heap else "не задан (по умолчанию 1/4 RAM)"),
           ("-XX:MaxDirectMemorySize", fmt_mb(direct) if direct == direct else "не задан (по умолчанию = Xmx)"),
           ("стеки потоков (threads max × Xss)", f"{fmt_mb(stacks)} ({threads_max:.0f} × {fmt_mb(stack)})" if stacks == stacks else "-"),
           ("сумма учтённого", fmt_mb(total))]
    if rss_max_mb == rss_max_mb:
        out.append(("RSS max (факт)", fmt_mb(rss_max_mb)))
        out.append(("RSS − учтённое ≈ off-heap/metaspace/прочее", fmt_mb(rss_max_mb - total)))
    return out


def analyze_java(host, args=None):
    rep = Report("JVM (java) — процесс Ignite глазами ОС", host.name)
    if not any(host.top):
        rep.text("", "Секция TOP отсутствует (nmon без -t): данных по процессам нет")
        return rep
    jp = host.java_procs()
    if not jp:
        rep.text("", "Процесс java не найден в TOP за период (Ignite не запущен на узле, либо потреблял < порога TOP)")
        return rep
    ncpu = host.ncpus()
    total_mb = fmax(host.col("MEM", "memtotal")) if host.has("MEM") else NAN
    n_snap = sum(1 for x in host.top if x)
    pgmaj = host.col("VM", "pgmajfault")
    step = host.step()
    for pid, lst in sorted(jp.items(), key=lambda kv: kv[1][0][0]):
        idxs = [i for i, _ in lst]
        cpu = [p.cpu for _, p in lst]
        usr = [p.usr for _, p in lst]
        sy = [p.sys for _, p in lst]
        rss = [p.rss / 1024.0 for _, p in lst]
        anon = [(p.rss - p.shlib) / 1024.0 if (p.rss == p.rss and p.shlib == p.shlib) else NAN for _, p in lst]
        vsz = [p.size / 1024.0 for _, p in lst]
        thr = [p.threads for _, p in lst]
        majf = [p.majflt for _, p in lst]
        minf = [p.minflt for _, p in lst]
        iow = [p.iowait for _, p in lst]
        times = [host.times[i] for i in idxs]
        first, last = times[0], times[-1]
        present_share = 100.0 * len(lst) / max(1, n_snap)
        tr_rss = trend(rss, times)
        tr_thr = trend(thr, times)
        imax = argmax(cpu)
        # согласованность MajorFault процесса с системным pgmajfault (VM) по тем же снимкам
        maj_note = ""
        if pgmaj is not None and clean(majf):
            proc_events = sum(m * step for m in majf if m == m)
            sys_events = sum(pgmaj[i] for i in idxs if pgmaj[i] == pgmaj[i])
            if sys_events > 0 and proc_events > 10 * sys_events:
                maj_note = (f" — НЕ согласуется с системным VM pgmajfault ({sys_events:.0f} событий за те же интервалы, "
                            f"в {proc_events / sys_events:.0f} раз меньше): значение TOP MajorFault для этого процесса ненадёжно")
        kv = [
            ("pid", pid),
            ("виден в TOP", f"{len(lst)} из {n_snap} снимков ({present_share:.0f}%), {ts(first)} .. {ts(last)}"),
            ("%CPU avg / p95 / max (в % одного ядра; 100% = 1 ядро)", f"{fmean(cpu):.0f} / {percentile(cpu, 95):.0f} / {fmax(cpu):.0f}"),
            ("время max %CPU", times[imax] if imax >= 0 else None),
            ("в ядрах: avg / max", f"{fmean(cpu) / 100:.1f} / {fmax(cpu) / 100:.1f} из {ncpu}" +
             (f" ({fmean(cpu) / ncpu:.1f}% / {fmax(cpu) / ncpu:.1f}% машины)" if ncpu else "")),
            ("доля sys в CPU процесса", f"{100.0 * fsum(sy) / max(1e-9, fsum(usr) + fsum(sy)):.0f}%"),
            ("RSS начало / max / конец", f"{fmt_mb(rss[0])} / {fmt_mb(max(rss))} / {fmt_mb(rss[-1])}"),
            ("RSS % от RAM (max)", f"{100.0 * max(rss) / total_mb:.0f}%" if total_mb == total_mb else "-"),
            ("анонимная RSS (ResSet − ShdLib) max / % RAM",
             f"{fmt_mb(fmax(anon))} / {100.0 * fmax(anon) / total_mb:.0f}%" if clean(anon) and total_mb == total_mb else "-"),
            ("file/shmem-backed часть RSS (ShdLib) max", fmt_mb(fmax([p.shlib / 1024.0 for _, p in lst]))),
            ("RSS тренд, MB/ч (r²)", f"{fmt_num(tr_rss['slope_per_h'], 0)} ({fmt_num(tr_rss['r2'], 2)})"),
            ("VSZ max", fmt_mb(fmax(vsz))),
            ("threads начало / max / конец", f"{fmt_num(thr[0], 0)} / {fmt_num(fmax(thr), 0)} / {fmt_num(thr[-1], 0)}"
             if clean(thr) else "нет данных (старая версия nmon без колонки Threads)"),
            ("threads тренд, /ч (r²)", f"{fmt_num(tr_thr['slope_per_h'], 1)} ({fmt_num(tr_thr['r2'], 2)})"),
            ("major faults, /s: avg / max", f"{fmt_num(fmean(majf), 1)} / {fmt_num(fmax(majf), 0)}{maj_note}"),
            ("minor faults, /s: avg / max", f"{fmt_num(fmean(minf), 0)} / {fmt_num(fmax(minf), 0)}"),
            ("IOwaitTime Σ (только главный поток — для JVM неинформативно)", fmt_num(fsum(iow), 0)),
        ]
        rep.kv(f"java[{pid}]", kv, note="RSS = heap + off-heap + metaspace + стеки + file/shmem-страницы (ShdLib); "
                                        "анонимная RSS ближе к реальному потреблению памяти процессом")
        # Провалы CPU процесса (возможные паузы/зависания)
        med = fmedian(cpu)
        if med == med and med > 20:
            drops = [(times[k], cpu[k]) for k in range(len(cpu)) if cpu[k] == cpu[k] and cpu[k] < 0.1 * med]
            if drops:
                rep.table(f"java[{pid}]: снимки с %CPU < 10% от медианы ({med:.0f}%) — возможные паузы/остановки",
                          ["время", "%CPU"], [[t, v] for t, v in drops[:20]], total=len(drops))
        # Пропуски присутствия внутри периода
        if len(lst) >= 2:
            gaps = []
            for a, b in zip(idxs, idxs[1:]):
                if b - a > 1:
                    gaps.append([host.times[a], host.times[b], b - a - 1])
            if gaps:
                rep.table(f"java[{pid}]: отсутствие в TOP между снимками (процесс не потреблял CPU или был остановлен)",
                          ["последний", "следующий", "пропущено снимков"], gaps[:20], total=len(gaps), prec={"пропущено снимков": 0})
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
    changes = _pid_changes(host)
    if changes:
        rep.table("Перезапуски java (смена PID)", PID_CHANGE_COLS, changes, prec=PID_CHANGE_PREC,
                  note="малый RSS нового процесса = «холодный» старт; между = время между последним снимком старого и первым нового")
    # Конкуренты за CPU (сумма %CPU по всем PID команды в снимке)
    others = defaultdict(list)
    for i, procs in enumerate(host.top):
        per_cmd = defaultdict(float)
        for p in procs:
            if not _is_java(p) and p.cpu == p.cpu:
                per_cmd[p.cmd] += p.cpu
        for c, v in per_cmd.items():
            others[c].append(v)
    orow = [[c, proc_category(c), len(v), fmean(v), fmax(v)] for c, v in others.items()]
    orow.sort(key=lambda r: -r[3] * r[2])
    rep.table("Другие процессы с заметным CPU (конкуренты за CPU/IO)", ["команда", "категория", "снимков", "cpu avg%", "cpu max%"],
              orow[:_opt(args, "top", 10) or 10], total=len(orow),
              note="kswapd0 = reclaim памяти; kworker/*flush*/writeback = сброс грязных страниц; "
                   "антивирусы/бэкапы/агенты мониторинга — типичные «соседи»")
    # Командная строка, если есть UARG
    cl = host.uarg_cmdlines()
    for pid, lst in jp.items():
        if pid in cl:
            flags = [("роль", jvm_role(cl[pid][1]))] + jvm_flags(cl[pid][1])
            rep.kv(f"JVM-параметры java[{pid}] (UARG)", flags)
            fp = jvm_footprint(cl[pid][1], fmax([p.threads for _, p in lst]), fmax([p.rss for _, p in lst]) / 1024.0)
            if fp:
                rep.kv(f"Оценка памяти java[{pid}] по флагам", fp)
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
    series = []
    units = {}
    resolved = resolve_metrics(host, metrics, warn_missing=bool(_opt(args, "metrics", None)))
    missing = [m for m in metrics if m not in {n for n, _ in resolved}]
    for m, r in resolved:
        label = f"{m} [{r[1]}]" if r[1] else m
        units[label] = m
        cols.append(label)
        series.append(r[2])
    if not series:
        rep.text("", "ни одна из метрик недоступна: " + ", ".join(missing))
        return rep
    if step_s:
        tt = None
        agg_series = []
        for s in series:
            tt, vv = downsample(host.times, s, step_s, agg)
            agg_series.append(vv)
        times = tt
        series = agg_series
    else:
        times = host.times
    rows = []
    for k in range(len(times)):
        rows.append([times[k]] + [s[k] for s in series])
    limit = _opt(args, "limit", None)
    total = len(rows)
    if limit and len(rows) > limit:
        rows = rows[:limit]
    prec = {}
    for label in cols[1:]:
        m = units[label]
        if m.startswith(("disk.", "net.", "vm.pgpg", "proc.pswitch", "mem.", "top.java.rss", "top.java.vsz", "top.java.threads")):
            prec[label] = 0
    rep.table("Ряд" + (f" (агрегация {agg} по {fmt_dur(step_s)})" if step_s else ""), cols, rows, total=total, prec=prec,
              note=("недоступны: " + ", ".join(missing)) if missing else None)
    return rep


def analyze_events(host, args=None):
    """Заметные события: выбросы по скользящей медиане/MAD и превышения порогов."""
    rep = Report("События и выбросы", host.name)
    zv = _opt(args, "z", None)
    z_thr = 4.0 if zv is None else float(zv)
    metrics = _opt(args, "metrics", None) or [
        "cpu.busy", "cpu.sys", "cpu.wait", "cpu.steal", "proc.runq", "proc.blocked", "mem.free", "mem.swap_used",
        "vm.pswpout", "vm.pgmajfault", "vm.allocstall", "disk.busy_max", "disk.read", "disk.write", "disk.iops",
        "net.read", "net.write", "top.java.cpu", "top.java.rss", "top.java.threads"]
    min_abs = {"cpu.busy": 10, "cpu.sys": 5, "cpu.wait": 5, "cpu.steal": 1, "proc.runq": 4, "proc.blocked": 3,
               "mem.free": 1024, "mem.swap_used": 64, "disk.busy_max": 15, "disk.read": 20000, "disk.write": 20000,
               "disk.iops": 500, "net.read": 10000, "net.write": 10000, "top.java.cpu": 100, "top.java.rss": 2048,
               "top.java.threads": 30, "top.java.majflt": 100, "vm.pswpout": 1, "vm.pgmajfault": 20, "vm.allocstall": 1}
    rows = []
    hx = host.without_first()  # первые снимки файлов (T0001, неполный интервал) не считаем событиями
    for m, r in resolve_metrics(hx, metrics, warn_missing=bool(_opt(args, "metrics", None))):
        direction = "down" if m in ("mem.free",) else ("both" if m in ("top.java.cpu", "top.java.threads") else "up")
        sp = rolling_spikes(r[2], hx.times, window=int(_opt(args, "window_snaps", 15) or 15), z_thr=z_thr,
                            min_abs=min_abs.get(m), direction=direction)
        for t, v, base, z in sp:
            rows.append([t, m, v, base, z if z != math.inf else 99.0, r[1]])
    rows.sort(key=lambda r: (r[0], -abs(r[4])))
    total = len(rows)
    limit = _opt(args, "limit", 200) or 200
    rep.table("Выбросы (робастный z-score по скользящему окну)", ["время", "метрика", "значение", "фон (медиана окна)", "z", "ед."],
              rows[:limit], total=total, prec={"значение": 1, "фон (медиана окна)": 1, "z": 1},
              note=f"порог |z| ≥ {z_thr}; фон — медиана ±{max(2, int(_opt(args, 'window_snaps', 15) or 15) // 2)} соседних снимков "
                   f"(без самой точки); минимальные абсолютные отклонения отсекают шум")
    # Кластеризация событий по времени: в какие минуты «всё сразу»
    if rows:
        by_time = defaultdict(list)
        for r in rows:
            by_time[r[0]].append(r[1])
        multi = [[t, len(ms), ", ".join(sorted(set(ms)))] for t, ms in by_time.items() if len(set(ms)) >= 3]
        multi.sort(key=lambda r: -r[1])
        if multi:
            rep.table("Моменты с выбросами сразу по нескольким метрикам", ["время", "метрик", "какие"], multi[:30], total=len(multi))
    return rep


# --------------------------------------------------------------------------
# Правила health-проверок
# --------------------------------------------------------------------------

# code: (описание, порог WARN, порог CRIT, единица)
DEFAULT_THRESHOLDS = {
    "CPU_SATURATION": ("CPU busy p95, %", 80.0, 95.0, "%"),
    "CPU_WAIT": ("CPU iowait avg, %", 10.0, 25.0, "%"),
    "CPU_WAIT_PEAK": ("CPU iowait max, %", 30.0, 60.0, "%"),
    "CPU_STEAL": ("CPU steal max, %", 1.0, 5.0, "%"),
    "CPU_SYS_SHARE": ("доля sys в busy (avg), %", 40.0, 60.0, "%"),
    "CPU_HOT_CORE": ("снимков с ядром > 90% при общей busy < 50%, %", 20.0, 50.0, "% снимков"),
    "RUNQ_HIGH": ("Runnable p95 / CPU", 1.0, 2.0, "x"),
    "BLOCKED_HIGH": ("Blocked p95", 5.0, 20.0, "процессов"),
    "MEM_AVAIL_LOW": ("min avail (free+buffers+(cached−shmem)+slab), % от RAM", 10.0, 5.0, "%"),
    "MEM_FREE_LOW": ("min memfree, % от RAM", 2.0, 1.0, "%"),
    "MEM_GROWTH": ("используемая память: часов до исчерпания при тренде", 48.0, 12.0, "ч"),
    "SWAP_USED": ("swap used max, % от RAM", 0.0, 5.0, "%"),
    "SWAP_ACTIVITY": ("снимков с pswpin/pswpout > 0", 0.0, 10.0, "снимков"),
    "DIRECT_RECLAIM": ("снимков с allocstall/pgscan_direct > 0", 0.0, 10.0, "снимков"),
    "KSWAPD_ACTIVE": ("доля снимков с активностью kswapd (pageoutrun > 0 или kswapd0 в TOP), %", 30.0, 80.0, "%"),
    "MAJFAULT_HIGH": ("major faults p95, /s", 20.0, 200.0, "/s"),
    "DISK_BUSY": ("busy p95 физического диска, %", 80.0, 95.0, "%"),
    "DISK_BUSY_SUSTAINED": ("доля времени busy > 90% (физический диск), %", 10.0, 30.0, "%"),
    "DISK_LATENCY": ("время обслуживания p95, ms (если DISK*SERV есть)", 20.0, 50.0, "ms"),
    "FS_FULL": ("заполненность ФС (конец периода), %", 85.0, 95.0, "%"),
    "FS_GROWTH": ("часов до 100% ФС при текущем росте", 24.0, 6.0, "ч"),
    "NET_LINK_UTIL": ("использование линка p95 (нужен --link-mbit), %", 70.0, 90.0, "%"),
    "NET_ZERO": ("отрезок нулевого трафика активного интерфейса, снимков", 2.0, 5.0, "снимков"),
    "NET_ERRORS": ("ошибки/дропы на старте (ifconfig, накопительно) — WARN от 1000, CRIT от 100000", 1000.0, 100000.0, "count"),
    "JAVA_RSS": ("RSS java max, % от RAM", 85.0, 95.0, "%"),
    "JAVA_RSS_GROWTH": ("часов до RAM при тренде RSS java", 48.0, 12.0, "ч"),
    "JAVA_THREADS": ("threads java max", 2000.0, 5000.0, "потоков"),
    "JAVA_THREADS_GROWTH": ("рост threads java за период, %", 30.0, 100.0, "%"),
    "JAVA_SYS_SHARE": ("доля sys в CPU java, %", 30.0, 50.0, "%"),
    "JAVA_CPU_DROP": ("снимков с CPU java < 10% медианы (при медиане > 20%)", 1.0, 3.0, "снимков"),
    "JAVA_RESTART": ("смена PID java", 1.0, 1.0, "раз"),
    "JAVA_ABSENT": ("java не виден в TOP подряд, снимков (при наличии TOP)", 2.0, 5.0, "снимков"),
    "NMON_GAP": ("максимальный разрыв между снимками / interval", 1.5, 5.0, "x"),
    "NMON_SHORT": ("длительность данных, мин", 15.0, 5.0, "мин"),
    "BOOT_RECENT": ("часов от загрузки ОС до начала данных", 24.0, 1.0, "ч"),
    "THP_ACTIVE": ("AnonHugePages на старте, MB (THP используется)", 0.0, 1e12, "MB"),
    "OVERCOMMIT": ("Committed_AS / MemTotal на старте", 1.0, 1.5, "x"),
    "NO_SWAP": ("swap отсутствует (информационно)", 0.0, -1.0, ""),
    "IO_STALL": ("снимков с сигнатурой I/O-stall: Blocked ≥ 5 и iowait ≥ 5% и диск ≥ 90%", 3.0, 10.0, "снимков"),
    "DISK_SMALL_IO": ("fsync-heavy профиль: busy p95 ≥ порога при среднем IO ≤ 16 KB (информационно)", 80.0, 1e12, "%"),
    "CHECKPOINT_PERIOD": ("периодические всплески записи на самом нагруженном диске (информационно)", 0.0, -1.0, ""),
    "THP_COMPACTION": ("khugepaged/kcompactd активны в TOP (информационно)", 0.0, -1.0, ""),
    "CLUSTER_OUTLIER": ("|z| хоста относительно кластера", 3.0, 5.0, "z"),
    "CLUSTER_SYNC": ("доля хостов с одновременным выбросом, %", 50.0, 80.0, "%"),
    "CLUSTER_COVERAGE": ("хост без данных, пока у других есть, снимков", 3.0, 10.0, "снимков"),
}


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
        if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] < 0 and tr["r2"] == tr["r2"] and tr["r2"] >= 0.7 \
                and abs(tr["delta"]) >= 0.10 * fmean(ca):
            ev.append(f"page cache устойчиво сжимается ({fmt_mb(tr['delta'])} за период)")
    return "; ".join(ev)


def _reclaim_share(host):
    """Доля снимков (%) с признаками работы kswapd: pageoutrun > 0, kswapd_steal > 0 или kswapd0 в TOP."""
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

    def add(sev, code, metric, value, threshold, evidence, hint="", time=None):
        if sev:
            F.append(Finding(sev, code, hn, metric, value, threshold, evidence, hint, time))

    # --- качество данных ---
    dur_min = host.duration() / 60.0
    w, c = _thr(thr, "NMON_SHORT")
    add(_sev(dur_min, w, c, higher_is_worse=False), "NMON_SHORT", "длительность, мин", dur_min, f"< {w}",
        f"{ts(host.start())} .. {ts(host.end())}", "короткий период: статистика ненадёжна")
    gaps = host.gaps(factor=1.0)
    if gaps:
        mx = max(gaps, key=lambda g: g[2])
        ratio = mx[2] / step
        w, c = _thr(thr, "NMON_GAP")
        add(_sev(ratio, w, c), "NMON_GAP", "макс. разрыв / interval", ratio, f"≥ {w}",
            f"разрыв {fmt_dur(mx[2])} между {ts(mx[0])} и {ts(mx[1])}; всего разрывов > 1.5×: {len(host.gaps())}",
            "nmon не успевал снимать данные: хост был заморожен/перегружен, либо nmon перезапускали", time=mx[0])
    bt = host.meta.get("boottime", "")
    m = re.match(r"^(\d{1,2}):(\d{2})\s*(AM|PM)?\s+(\d{1,2}-[A-Za-z]{3}-\d{4})$", bt.strip())
    if m and host.start():
        hh = int(m.group(1)) % 12 + (12 if (m.group(3) or "").upper() == "PM" else 0)
        d = parse_nmon_date(m.group(4))
        if d:
            boot = datetime(d.year, d.month, d.day, hh, int(m.group(2)))
            hours = (host.start() - boot).total_seconds() / 3600.0
            w, c = _thr(thr, "BOOT_RECENT")
            add(_sev(hours, w, c, higher_is_worse=False), "BOOT_RECENT", "часов от загрузки ОС", hours, f"< {w}",
                f"boottime {ts(boot)}, данные с {ts(host.start())}", "недавняя перезагрузка узла: проверьте причину (OOM-killer, kernel panic, плановые работы)")
    # --- CPU ---
    busy = host.cpu_busy()
    ncpu = host.ncpus()
    if busy is not None:
        p95 = percentile(busy, 95)
        w, c = _thr(thr, "CPU_SATURATION")
        add(_sev(p95, w, c), "CPU_SATURATION", "CPU busy p95, %", p95, f"≥ {w}",
            f"avg {fmean(busy):.0f}%, max {fmax(busy):.0f}% @ {ts(series_stats(busy, host.times)['max_time'])}, "
            f"время > 90%: {fmt_dur(time_above(busy, 90, step))}",
            "CPU-насыщение: проверьте пулы Ignite (striped/system/public), GC, SQL-запросы, rebalancing")
        wt = host.col("CPU_ALL", "Wait%")
        if wt is not None:
            w, c = _thr(thr, "CPU_WAIT")
            add(_sev(fmean(wt), w, c), "CPU_WAIT", "iowait avg, %", fmean(wt), f"≥ {w}",
                f"p95 {percentile(wt, 95):.1f}%, max {fmax(wt):.1f}% @ {ts(series_stats(wt, host.times)['max_time'])}",
                "CPU простаивает в ожидании диска: смотрите disk (busy, latency), checkpoint/WAL Ignite")
            w, c = _thr(thr, "CPU_WAIT_PEAK")
            add(_sev(fmax(wt), w, c), "CPU_WAIT_PEAK", "iowait max, %", fmax(wt), f"≥ {w}",
                f"@ {ts(series_stats(wt, host.times)['max_time'])}", "кратковременный I/O-шторм (checkpoint, снапшот, бэкап)",
                time=series_stats(wt, host.times)["max_time"])
        st = host.col("CPU_ALL", "Steal%")
        if st is not None:
            w, c = _thr(thr, "CPU_STEAL")
            add(_sev(fmax(st), w, c), "CPU_STEAL", "steal max, %", fmax(st), f"≥ {w}",
                f"avg {fmean(st):.2f}%, снимков > 0: {count_above(st, 0)}",
                "гипервизор отбирает CPU (переподписка): риск таймаутов failureDetectionTimeout/metrics",
                time=series_stats(st, host.times)["max_time"])
        sy = host.col("CPU_ALL", "Sys%")
        if sy is not None and fmean(busy) > 10:
            share = 100.0 * fmean(sy) / max(1e-9, fmean(busy))
            w, c = _thr(thr, "CPU_SYS_SHARE")
            add(_sev(share, w, c), "CPU_SYS_SHARE", "доля sys в busy, %", share, f"≥ {w}",
                f"sys avg {fmean(sy):.1f}%, user avg {fmean(host.col('CPU_ALL', 'User%')):.1f}%",
                "много ядерного времени: page faults/THP, сеть (softirq), spin/futex, слишком много потоков")
        if host.cpu_cores:
            hx = host.without_first()
            hot = _core_hot_count(hx)
            busyx = hx.cpu_busy()
            hits = [i for i in range(hx.n()) if hot[i] > 0 and busyx[i] == busyx[i] and busyx[i] < 50]
            share = 100.0 * len(hits) / max(1, hx.n())
            w, c = _thr(thr, "CPU_HOT_CORE")
            add(_sev(share, w, c), "CPU_HOT_CORE", "% снимков: ядро > 90% при busy < 50%", share, f"≥ {w}",
                f"{len(hits)} из {hx.n()} снимков (без T0001)" + (f", первый @ {ts(hx.times[hits[0]])}" if hits else ""),
                "однопоточное узкое место (один поток Ignite/GC/приложения упирается в ядро)",
                time=hx.times[hits[0]] if hits else None)
    # --- PROC ---
    rq = host.col("PROC", "Runnable")
    if rq is not None and ncpu:
        ratio = percentile(rq, 95) / ncpu
        w, c = _thr(thr, "RUNQ_HIGH")
        add(_sev(ratio, w, c), "RUNQ_HIGH", "Runnable p95 / CPU", ratio, f"≥ {w}",
            f"Runnable p95 {percentile(rq, 95):.0f}, max {fmax(rq):.0f} при {ncpu} CPU",
            "очередь на CPU длиннее числа ядер: задержки планирования потоков Ignite",
            time=series_stats(rq, host.times)["max_time"])
    bl = host.col("PROC", "Blocked")
    if bl is not None:
        w, c = _thr(thr, "BLOCKED_HIGH")
        w_eff = max(w, ncpu / 8.0) if ncpu else w  # порог масштабируется с числом CPU
        c_eff = max(c, w_eff * 4)
        sev = _sev(percentile(bl, 95), w_eff, c_eff)
        # подтверждение: в снимках с высоким Blocked есть iowait ≥ 5% или диск ≥ 90%
        wt_ = host.col("CPU_ALL", "Wait%")
        dbm, _who = host.disk_max_busy()
        hi = [i for i in range(n) if bl[i] == bl[i] and bl[i] >= w_eff]
        corr = [i for i in hi if (wt_ is not None and wt_[i] == wt_[i] and wt_[i] >= 5) or (dbm is not None and dbm[i] == dbm[i] and dbm[i] >= 90)]
        if sev and hi and len(corr) < 0.3 * len(hi):
            sev = "INFO"
        add(sev, "BLOCKED_HIGH", "Blocked p95", percentile(bl, 95), f"≥ {w_eff:.0f} (= max({w:.0f}, CPU/8))",
            f"max {fmax(bl):.0f} @ {ts(series_stats(bl, host.times)['max_time'])}; снимков с Blocked ≥ {w_eff:.0f}: {len(hi)}, "
            f"из них с iowait ≥ 5% или диск ≥ 90%: {len(corr)}",
            "много процессов/потоков ждут I/O (D-state): диск-насыщение, fsync WAL, checkpoint; Blocked — мгновенное значение "
            "в момент снимка, без подтверждения iowait/диском понижается до INFO",
            time=series_stats(bl, host.times)["max_time"])
    # --- память ---
    total = fmax(host.col("MEM", "memtotal")) if host.has("MEM") else NAN
    if total == total and total > 0:
        avail = host.mem_avail_calibrated()
        off = host.mem_avail_offset()
        pct = 100.0 * fmin(avail) / total
        w, c = _thr(thr, "MEM_AVAIL_LOW")
        add(_sev(pct, w, c, higher_is_worse=False), "MEM_AVAIL_LOW", "min avail (оценка MemAvailable с калибровкой), % RAM", pct, f"≤ {w}",
            f"min {fmt_mb(fmin(avail))} @ {ts(series_stats(avail, host.times)['min_time'])} из {fmt_mb(total)}"
            + (f"; поправка по MemAvailable на старте −{fmt_mb(off)}" if off > 0 else "; без калибровки (нет MemAvailable в BBBP)"),
            "мало доступной памяти: риск reclaim/swap/OOM; проверьте размер data regions + heap + page cache",
            time=series_stats(avail, host.times)["min_time"])
        free = host.col("MEM", "memfree")
        pctf = 100.0 * fmin(free) / total
        w, c = _thr(thr, "MEM_FREE_LOW")
        sev = _sev(pctf, w, c, higher_is_worse=False)
        corr = _memory_pressure_corroboration(host)
        if sev and not corr:
            sev = "INFO"  # мало free при большом page cache без признаков давления — штатное поведение Linux
        add(sev, "MEM_FREE_LOW", "min memfree, % RAM", pctf, f"≤ {w}",
            f"min {fmt_mb(fmin(free))} @ {ts(series_stats(free, host.times)['min_time'])}; page cache без shmem avg {fmt_mb(fmean(_page_cache(host)))}; "
            f"avail min {fmt_mb(fmin(avail))}; " + (f"подтверждение давления: {corr}" if corr else "признаков давления на память нет"),
            "memfree у нуля само по себе — норма Linux (память занята page cache); тревожно только вместе с major faults, swap, "
            "падением avail или ростом чтений с диска")
        used = host.mem_used()
        tr = trend(used, host.times)
        if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] > 0 and tr["r2"] == tr["r2"] and tr["r2"] > 0.7:
            tte = time_to_limit(series_stats(used, host.times)["last"], tr["slope_per_h"], total)
            w, c = _thr(thr, "MEM_GROWTH")
            add(_sev(tte, w, c, higher_is_worse=False), "MEM_GROWTH", "часов до исчерпания RAM (used)", tte, f"≤ {w}",
                f"used растёт на {tr['slope_per_h']:.0f} MB/ч (r²={tr['r2']:.2f}), сейчас {fmt_mb(series_stats(used, host.times)['last'])}",
                "устойчивый рост used: утечка/накопление off-heap, рост page tables, кэш метаданных")
        sw = host.swap_used()
        if sw is not None and fmax(sw) == fmax(sw):
            pcts = 100.0 * fmax(sw) / total
            w, c = _thr(thr, "SWAP_USED")
            sev = _sev(pcts, w, c) if fmax(sw) > 0 else None
            add(sev, "SWAP_USED", "swap used max, % RAM", pcts, f"> {w}",
                f"max {fmt_mb(fmax(sw))} @ {ts(series_stats(sw, host.times)['max_time'])}",
                "swap для Ignite недопустим: паузы JVM, таймауты failure detection; отключите swap / уменьшите память процессов")
        stt = host.col("MEM", "swaptotal")
        if stt is not None and fmax(stt) == 0:
            add("INFO", "NO_SWAP", "swaptotal", 0.0, None, "swap не настроен",
                "нормально для Ignite; при нехватке памяти сработает OOM-killer (ищите в dmesg/messages)")
    # --- VM ---
    swp = []
    swp_cnt = 0
    swp_first = None
    for name in ("vm.pswpin", "vm.pswpout"):
        r = resolve_metric(host, name)
        if r and count_above(r[2], 0):
            idx = [i for i, v in enumerate(r[2]) if v == v and v > 0]
            swp_cnt = max(swp_cnt, len(idx))
            t0 = host.times[idx[0]]
            swp_first = t0 if swp_first is None or t0 < swp_first else swp_first
            swp.append(f"{name.split('.')[1]}: {len(idx)} снимков, сумма {fsum(r[2]):.0f} страниц, max {fmax(r[2]):.0f} @ {ts(series_stats(r[2], host.times)['max_time'])}")
    if swp:
        w, c = _thr(thr, "SWAP_ACTIVITY")
        add(_sev(swp_cnt, w, c) or "WARN", "SWAP_ACTIVITY", "снимков с pswpin/pswpout > 0", swp_cnt, f"> {w}",
            "; ".join(swp), "идёт реальная подкачка: критично для латентности Ignite (паузы JVM, таймауты)", time=swp_first)
    dr = resolve_metric(host, "vm.allocstall")
    dr2 = resolve_metric(host, "vm.pgscan_direct")
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
    share = _reclaim_share(host)
    if share == share and share > 0:
        w, c = _thr(thr, "KSWAPD_ACTIVE")
        po = resolve_metric(host, "vm.pageoutrun")
        kc = resolve_metric(host, "top.kswapd.cpu")
        ev = []
        if po and count_above(po[2], 0):
            ev.append(f"pageoutrun > 0 в {count_above(po[2], 0)} снимках")
        if kc and count_above(kc[2], 0):
            ev.append(f"kswapd0 в TOP: {count_above(kc[2], 0)} снимков, CPU max {fmax(kc[2]):.1f}%")
        ks = resolve_metric(host, "vm.kswapd_steal")
        if ks and fsum(ks[2]) > 0:
            ev.append(f"kswapd_steal сумма {fsum(ks[2]):.0f} страниц")
        sev = _sev(share, w, c)
        corr = _memory_pressure_corroboration(host)
        if sev and not corr:
            sev = "INFO"  # kswapd при потоковом I/O работает постоянно — без подтверждения это не проблема
        add(sev, "KSWAPD_ACTIVE", "доля снимков с активностью kswapd, %", share, f"≥ {w}",
            "; ".join(ev) + ("; подтверждение давления: " + corr if corr else "; признаков давления (major faults, swap, падение avail/cached) нет"),
            "фоновый reclaim page cache при потоковом I/O — норма; проблема, если одновременно растут major faults, "
            "чтения с диска или падает avail (данные Ignite вытесняются из кэша)")
    mj = resolve_metric(host, "vm.pgmajfault")
    if mj:
        p95 = percentile(mj[2], 95)
        w, c = _thr(thr, "MAJFAULT_HIGH")
        add(_sev(p95, w, c), "MAJFAULT_HIGH", "major faults p95, /s", p95, f"≥ {w}",
            f"max {fmax(mj[2]):.0f}/s @ {ts(series_stats(mj[2], host.times)['max_time'])}",
            "страницы подгружаются с диска (swap или вытесненный код/файлы): память под давлением")
    # --- диски ---
    if host.has("DISKBUSY"):
        for d in host.physical_disks():
            b = host.col("DISKBUSY", d)
            if b is None or not clean(b):
                continue
            p95 = percentile(b, 95)
            w, c = _thr(thr, "DISK_BUSY")
            mnt = next((e.get("mount", "") for e in host.device_map() if e["device"] == d), "")
            add(_sev(p95, w, c), "DISK_BUSY", f"busy p95 {d}" + (f" ({mnt})" if mnt else ""), p95, f"≥ {w}",
                f"avg {fmean(b):.0f}%, max {fmax(b):.0f}% @ {ts(series_stats(b, host.times)['max_time'])}; "
                f"write max {fmax(host.col('DISKWRITE', d) or [NAN]):.0f} KB/s, read max {fmax(host.col('DISKREAD', d) or [NAN]):.0f} KB/s",
                "диск загружен: checkpoint/WAL/rebalance/снапшот; для NVMe busy≈100% может быть нормой при высоком IOPS — смотрите латентность и Blocked",
                time=series_stats(b, host.times)["max_time"])
            share = 100.0 * count_above(b, 90) / n
            w, c = _thr(thr, "DISK_BUSY_SUSTAINED")
            add(_sev(share, w, c), "DISK_BUSY_SUSTAINED", f"доля времени busy > 90% {d}", share, f"≥ {w}",
                f"{fmt_dur(time_above(b, 90, step))} из {fmt_dur(host.duration())}", "длительное насыщение диска")
        for sec, lbl in (("DISKREADSERV", "read"), ("DISKWRITESERV", "write")):
            if host.has(sec):
                for d in host.physical_disks():
                    a = host.col(sec, d)
                    if a is None or not clean(a):
                        continue
                    p95 = percentile(a, 95)
                    w, c = _thr(thr, "DISK_LATENCY")
                    add(_sev(p95, w, c), "DISK_LATENCY", f"{lbl} service time p95 {d}, ms", p95, f"≥ {w}",
                        f"max {fmax(a):.1f} ms", "высокая латентность диска: fsync WAL и checkpoint будут медленными")
    # --- ФС ---
    if host.has("JFSFILE"):
        dfrows = {r["mount"]: r for r in host.df()}
        for mnt in host.cols("JFSFILE"):
            a = host.col("JFSFILE", mnt)
            if a is None or not clean(a):
                continue
            if mnt.startswith(("/dev", "/run", "/sys", "/proc")) or dfrows.get(mnt, {}).get("filesystem", "").startswith("tmpfs"):
                continue
            last = series_stats(a, host.times)["last"]
            w, c = _thr(thr, "FS_FULL")
            add(_sev(last, w, c), "FS_FULL", f"заполненность {mnt}, %", last, f"≥ {w}",
                f"max {fmax(a):.1f}%, размер {fmt_mb(dfrows.get(mnt, {}).get('size_mb'))}",
                "ФС почти полна: WAL-архив/снапшоты/логи; Ignite при нехватке места останавливает узел")
            tr = trend(a, host.times)
            if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] > 0.05 and tr["r2"] == tr["r2"] and tr["r2"] > 0.7:
                tte = time_to_limit(last, tr["slope_per_h"], 100.0)
                w, c = _thr(thr, "FS_GROWTH")
                add(_sev(tte, w, c, higher_is_worse=False), "FS_GROWTH", f"часов до 100% {mnt}", tte, f"≤ {w}",
                    f"рост {tr['slope_per_h']:.2f} п.п./ч (r²={tr['r2']:.2f}), сейчас {last:.1f}%",
                    "при таком росте ФС заполнится: проверьте WAL archive, снапшоты, логи")
    # --- сеть ---
    if host.has("NET"):
        rt, wt = host.net_total("read"), host.net_total("write")
        if link_mbit and rt is not None:
            cap = link_capacity_kbs(link_mbit)
            for lbl, a in (("rx", rt), ("tx", wt)):
                util = 100.0 * percentile(a, 95) / cap
                w, c = _thr(thr, "NET_LINK_UTIL")
                add(_sev(util, w, c), "NET_LINK_UTIL", f"{lbl} p95 / линк {link_mbit} Mbit/s, %", util, f"≥ {w}",
                    f"p95 {percentile(a, 95):.0f} KB/s, max {fmax(a):.0f} KB/s", "сеть близка к насыщению: rebalance/putAll/backup")
        for i in host.net_primary_ifaces():
            rd, wr = host.col("NET", f"{i}-read-KB/s"), host.col("NET", f"{i}-write-KB/s")
            if rd is None or fmax(rd) <= 1:
                continue
            tot = [a + b if (a == a and b == b) else NAN for a, b in zip(rd, wr)]
            runs = runs_above([-v if v == v else NAN for v in tot], -0.5, min_len=1)
            if runs:
                longest = max(runs, key=lambda r: r[1] - r[0])
                ln = longest[1] - longest[0] + 1
                w, c = _thr(thr, "NET_ZERO")
                add(_sev(ln, w, c), "NET_ZERO", f"нулевой трафик {i}, снимков подряд", ln, f"≥ {w}",
                    f"{ts(host.times[longest[0]])} .. {ts(host.times[longest[1]])}",
                    "интерфейс молчал: изоляция узла/сегментация Ignite, падение линка, остановка узла", time=host.times[longest[0]])
        errs = []
        for i in host.net_counters().values():
            tot = sum(v for v in (i["rx_errors"], i["rx_dropped"], i["tx_errors"], i["tx_dropped"]) if v)
            if tot:
                errs.append((i["name"], tot))
        if errs:
            tot = sum(e[1] for e in errs)
            w, c = _thr(thr, "NET_ERRORS")
            add(_sev(tot, w, c) or "INFO", "NET_ERRORS", "ошибки+дропы (накопительно с загрузки)", tot, f"≥ {w} (ниже — INFO)",
                ", ".join(f"{n_}={v}" for n_, v in errs), "накопительные счётчики: сравните с uptime; дропы на bond — обычно безвредны")
        if host.has("NETERROR"):
            tot = sum(fsum(host.col("NETERROR", c_)) for c_ in host.cols("NETERROR") if clean(host.col("NETERROR", c_)))
            if tot > 0:
                w, c = _thr(thr, "NET_ERRORS")
                add(_sev(tot, w, c) or "INFO", "NET_ERRORS", "NETERROR сумма за период", tot, f"≥ {w} (ниже — INFO)",
                    "; ".join(f"{c_}={fsum(host.col('NETERROR', c_)):.0f}" for c_ in host.cols("NETERROR") if fsum(host.col("NETERROR", c_)) > 0),
                    "сетевые ошибки в период наблюдения")
    # --- java / TOP ---
    if any(host.top):
        jp = host.java_procs()
        n_snap_top = [i for i, x in enumerate(host.top) if x]
        if not jp:
            add("INFO", "JAVA_ABSENT", "java в TOP", 0, None, "процесс java не найден ни в одном снимке",
                "Ignite на узле не запущен либо потреблял < порога TOP")
        for pid, lst in jp.items():
            idxs = [i for i, _ in lst]
            rss = [p.rss / 1024.0 for _, p in lst]
            anon = [(p.rss - p.shlib) / 1024.0 for _, p in lst if p.rss == p.rss and p.shlib == p.shlib]
            thr_ = [p.threads for _, p in lst if p.threads == p.threads]
            cpu = [p.cpu for _, p in lst]
            usr = [p.usr for _, p in lst]
            sy = [p.sys for _, p in lst]
            times = [host.times[i] for i in idxs]
            if total == total and rss:
                base = anon if anon else rss
                pct = 100.0 * max(base) / total
                w, c = _thr(thr, "JAVA_RSS")
                add(_sev(pct, w, c), "JAVA_RSS", f"{'анонимная RSS' if anon else 'RSS'} java[{pid}] max, % RAM", pct, f"≥ {w}",
                    f"RSS max {fmt_mb(max(rss))}" + (f", из них file/shmem (ShdLib) {fmt_mb(max(rss) - max(anon))}" if anon else "") +
                    f" из {fmt_mb(total)}; page cache без shmem avg {fmt_mb(fmean(_page_cache(host))) if host.has('MEM') else '-'}",
                    "JVM занимает почти всю RAM: сверьте с планом (heap + data regions + metaspace); page cache для WAL/checkpoint "
                    "остаётся мало, растёт риск OOM-killer при любом всплеске")
                tr = trend(rss, times)
                if tr["slope_per_h"] == tr["slope_per_h"] and tr["slope_per_h"] > 0 and tr["r2"] == tr["r2"] and tr["r2"] > 0.7:
                    tte = time_to_limit(rss[-1], tr["slope_per_h"], total)
                    w, c = _thr(thr, "JAVA_RSS_GROWTH")
                    add(_sev(tte, w, c, higher_is_worse=False), "JAVA_RSS_GROWTH", f"часов до RAM при росте RSS java[{pid}]", tte, f"≤ {w}",
                        f"RSS растёт {tr['slope_per_h']:.0f} MB/ч (r²={tr['r2']:.2f}), сейчас {fmt_mb(rss[-1])}",
                        "устойчивый рост RSS: off-heap/утечка/рост heap до Xmx (нормально в начале работы)")
            if thr_:
                w, c = _thr(thr, "JAVA_THREADS")
                add(_sev(max(thr_), w, c), "JAVA_THREADS", f"threads java[{pid}] max", max(thr_), f"≥ {w}",
                    f"начало {thr_[0]:.0f}, конец {thr_[-1]:.0f}", "очень много потоков: пулы Ignite/клиентские соединения/утечка потоков")
                if thr_[0] > 0:
                    growth = 100.0 * (max(thr_) - thr_[0]) / thr_[0]
                    w, c = _thr(thr, "JAVA_THREADS_GROWTH")
                    add(_sev(growth, w, c), "JAVA_THREADS_GROWTH", f"рост threads java[{pid}], %", growth, f"≥ {w}",
                        f"{thr_[0]:.0f} → max {max(thr_):.0f}", "рост числа потоков: новые соединения/пулы, возможна утечка потоков")
            if fsum(usr) + fsum(sy) > 0:
                share = 100.0 * fsum(sy) / (fsum(usr) + fsum(sy))
                w, c = _thr(thr, "JAVA_SYS_SHARE")
                add(_sev(share, w, c), "JAVA_SYS_SHARE", f"доля sys в CPU java[{pid}], %", share, f"≥ {w}",
                    f"usr avg {fmean(usr):.0f}%, sys avg {fmean(sy):.0f}%",
                    "JVM много времени в ядре: page faults (THP/pretouch), futex-конкуренция, сеть, mmap-файлы")
            med = fmedian(cpu)
            if med == med and med > 20:
                drops = [k for k in range(len(cpu)) if cpu[k] == cpu[k] and cpu[k] < 0.1 * med]
                if drops:
                    w, c = _thr(thr, "JAVA_CPU_DROP")
                    add(_sev(len(drops), w, c), "JAVA_CPU_DROP", f"снимков с CPU java[{pid}] < 10% медианы", len(drops), f"≥ {w}",
                        f"медиана {med:.0f}%, первый провал @ {ts(times[drops[0]])}",
                        "резкое падение активности JVM: пауза (GC/safepoint), блокировка на I/O, остановка узла", time=times[drops[0]])
            # отсутствие в TOP подряд
            if len(idxs) >= 2:
                worst = 0
                wt0 = None
                for a, b in zip(idxs, idxs[1:]):
                    miss = sum(1 for k in range(a + 1, b) if host.top[k])
                    if miss > worst:
                        worst, wt0 = miss, host.times[a]
                if worst:
                    w, c = _thr(thr, "JAVA_ABSENT")
                    add(_sev(worst, w, c), "JAVA_ABSENT", f"java[{pid}] не виден в TOP подряд, снимков", worst, f"≥ {w}",
                        f"после {ts(wt0)}", "процесс не потреблял CPU (пауза/зависание) или был остановлен", time=wt0)
        changes = _pid_changes(host)
        if changes:
            main_ch = [r for r in changes if r[8] == "основной"]
            aux_ch = [r for r in changes if r[8] != "основной"]
            if main_ch:
                add("CRIT", "JAVA_RESTART", "смена PID основного процесса java", len(main_ch), "≥ 1",
                    "; ".join(f"{r[1]}→{r[3]} @ {ts(r[4])} (простой {r[5]}, RSS нового {fmt_mb(r[6])})" for r in main_ch[:5]),
                    "процесс Ignite перезапускался: ищите причину в логах (OOM, segmentation, kill)", time=main_ch[0][4])
            if aux_ch:
                add("INFO", "JAVA_RESTART", "смена PID вспомогательного java-процесса (основной JVM продолжал работать)", len(aux_ch), None,
                    "; ".join(f"{r[1]}→{r[3]} @ {ts(r[4])}" for r in aux_ch[:5]),
                    "короткоживущие java (control.sh, утилиты, клиенты) — не перезапуск узла Ignite", time=aux_ch[0][4])
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
    # --- составные сигнатуры (Ignite) ---
    blk = host.col("PROC", "Blocked")
    wtc = host.col("CPU_ALL", "Wait%")
    dbmax, dwho = host.disk_max_busy()
    if blk is not None and wtc is not None and dbmax is not None:
        hits = [i for i in range(n) if blk[i] == blk[i] and wtc[i] == wtc[i] and dbmax[i] == dbmax[i]
                and blk[i] >= 5 and wtc[i] >= 5 and dbmax[i] >= 90]
        if hits:
            w, c = _thr(thr, "IO_STALL")
            add(_sev(len(hits), w, c), "IO_STALL", "снимков с сигнатурой I/O-stall", len(hits), f"≥ {w}",
                f"первый @ {ts(host.times[hits[0]])} (диск {dwho[hits[0]]}), всего {len(hits)} из {n}; "
                f"пример: Blocked {blk[hits[0]]:.0f}, iowait {wtc[hits[0]]:.1f}%, busy {dbmax[hits[0]]:.0f}%",
                "потоки стоят в D-state на переполненном диске: checkpoint/WAL fsync/снапшот; сопоставьте с логами Ignite "
                "(Checkpoint started/finished, throttling, long fsync)", time=host.times[hits[0]])
    if host.has("DISKBUSY"):
        best_dev, best_w = None, -1.0
        for d in host.physical_disks():
            b = host.col("DISKBUSY", d)
            bs = host.col("DISKBSIZE", d)
            wr_ = host.col("DISKWRITE", d)
            if b is None or not clean(b):
                continue
            if wr_ is not None and fmean(wr_) > best_w:
                best_dev, best_w = d, fmean(wr_)
            w, c = _thr(thr, "DISK_SMALL_IO")
            iosz = _io_size(host.col("DISKREAD", d), wr_, host.col("DISKXFER", d))
            if iosz != iosz and bs is not None:
                iosz = fmean(bs)
            if percentile(b, 95) >= w and iosz == iosz and iosz <= 16:
                add("INFO", "DISK_SMALL_IO", f"{d}: busy p95 при мелких операциях", percentile(b, 95), f"≥ {w}",
                    f"средний IO {iosz:.1f} KB (Σ(read+write)/Σ IOPS), IOPS avg {fmean(host.col('DISKXFER', d)):.0f}",
                    "профиль мелких синхронных записей (WAL fsync / случайные страницы checkpoint): латентность важнее пропускной способности")
        if best_dev:
            wr_ = host.col("DISKWRITE", best_dev)
            pr = periodicity(wr_, host.times, step)
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


def analyze_health(host, args=None):
    rep = Report("Проверка здоровья (правила и пороги)", host.name)
    thr = _opt(args, "thresholds", None)
    F = _filter_sev(health_checks(host, thr, link_mbit=_opt(args, "link_mbit", None)), args)
    counts = defaultdict(int)
    for f in F:
        counts[f.severity] += 1
    rep.kv("Итог", [("CRIT", counts["CRIT"]), ("WARN", counts["WARN"]), ("INFO", counts["INFO"]),
                     ("период", f"{ts(host.start())} .. {ts(host.end())} ({fmt_dur(host.duration())}, {host.n()} снимков)")])
    rep.findings("Замечания", F, note="пороги по умолчанию можно переопределить: --thr CODE=WARN[,CRIT]")
    return rep


def analyze_report(host, args=None):
    """Полный обзор: ключевые показатели + замечания."""
    rep = Report("Сводный отчёт", host.name)
    step = host.step()
    ncpu = host.ncpus()
    kv = [("период", f"{ts(host.start())} .. {ts(host.end())} ({fmt_dur(host.duration())}, {host.n()} снимков, шаг {step:.0f}s)"),
          ("CPU / RAM", f"{ncpu} CPU, {fmt_mb(fmax(host.col('MEM', 'memtotal'))) if host.has('MEM') else '-'}"),
          ("OS", host.meta.get("OS", "-"))]
    busy = host.cpu_busy()
    if busy is not None:
        wt = host.col("CPU_ALL", "Wait%")
        st = host.col("CPU_ALL", "Steal%")
        p0 = lambda v: fmt_num(v, 0)  # noqa: E731
        p1 = lambda v: fmt_num(v, 1)  # noqa: E731
        kv.append(("CPU busy avg / p95 / max", f"{p0(fmean(busy))}% / {p0(percentile(busy, 95))}% / {p0(fmax(busy))}% @ {ts(series_stats(busy, host.times)['max_time'])}"))
        kv.append(("CPU user / sys / wait / steal avg", f"{p1(fmean(host.col('CPU_ALL', 'User%')))}% / {p1(fmean(host.col('CPU_ALL', 'Sys%')))}% / "
                                                       f"{p1(fmean(wt))}% / {fmt_num(fmean(st), 2)}%"))
        if host.cpu_cores:
            cm = _core_busy_max(host.without_first())
            kv.append(("макс. ядро busy avg / max (без T0001)", f"{p0(fmean(cm))}% / {p0(fmax(cm))}%"))
    rq, bl = host.col("PROC", "Runnable"), host.col("PROC", "Blocked")
    if rq is not None:
        kv.append(("Runnable avg / max; Blocked avg / max", f"{fmt_num(fmean(rq), 1)} / {fmt_num(fmax(rq), 0)}; {fmt_num(fmean(bl), 1)} / {fmt_num(fmax(bl), 0)}"))
    if host.has("MEM"):
        av = host.mem_avail()
        us = host.mem_used()
        sw = host.swap_used()
        kv.append(("память used avg / max", f"{fmt_mb(fmean(us))} / {fmt_mb(fmax(us))}"))
        avc = host.mem_avail_calibrated()
        kv.append(("память avail (оценка MemAvailable) min", f"{fmt_mb(fmin(av))} @ {ts(series_stats(av, host.times)['min_time'])}"
                   + (f" (с калибровкой по MemAvailable на старте: {fmt_mb(fmin(avc))})" if host.mem_avail_offset() > 0 else "")))
        kv.append(("page cache без shmem avg (cached avg)", f"{fmt_mb(fmean(_page_cache(host)))} ({fmt_mb(fmean(host.col('MEM', 'cached')))})"))
        if sw is not None:
            kv.append(("swap used max", fmt_mb(fmax(sw))))
    for nm, lbl in (("vm.pswpout", "swap out (страниц за период)"), ("vm.pgmajfault", "major faults avg/s")):
        r = resolve_metric(host, nm)
        if r:
            kv.append((lbl, fmean(r[2]) if nm == "vm.pgmajfault" else fsum(r[2])))
    po = resolve_metric(host, "vm.pageoutrun")
    if po:
        kv.append(("kswapd активен (pageoutrun > 0), снимков", f"{count_above(po[2], 0)} из {host.n()}"))
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
        for d in host.physical_disks():
            b = host.col("DISKBUSY", d)
            if b is None:
                continue
            mnt = next((e.get("mount", "") for e in host.device_map() if e["device"] == d), "")
            rows.append(f"{d}{'(' + mnt + ')' if mnt else ''}: busy avg {fmt_num(fmean(b), 0)}% p95 {fmt_num(percentile(b, 95), 0)}% max {fmt_num(fmax(b), 0)}%, "
                        f"w max {fmt_num(fmax(host.col('DISKWRITE', d)) / 1024, 0)} MB/s, r max {fmt_num(fmax(host.col('DISKREAD', d)) / 1024, 0)} MB/s")
        kv.append(("диски", "; ".join(rows)))
    if host.has("NET"):
        rt, wtn = host.net_total("read"), host.net_total("write")
        if rt is not None:
            kv.append(("сеть rx avg / max; tx avg / max", f"{fmean(rt) / 1024:.1f} / {fmax(rt) / 1024:.1f} MB/s; {fmean(wtn) / 1024:.1f} / {fmax(wtn) / 1024:.1f} MB/s"))
    if host.has("JFSFILE"):
        fs = []
        for m in host.cols("JFSFILE"):
            a = host.col("JFSFILE", m)
            if a is not None and clean(a) and series_stats(a, host.times)["last"] >= 70:
                fs.append(f"{m} {series_stats(a, host.times)['last']:.0f}%")
        kv.append(("ФС ≥ 70%", ", ".join(fs) or "нет"))
    jp = host.java_procs() if any(host.top) else {}
    for pid, lst in jp.items():
        cpu = [p.cpu for _, p in lst]
        rss = [p.rss / 1024 for _, p in lst]
        thr_ = [p.threads for _, p in lst]
        thr_txt = (f"threads {fmt_num(thr_[0], 0)} → {fmt_num(thr_[-1], 0)} (max {fmt_num(fmax(thr_), 0)})"
                   if clean(thr_) else "threads: нет колонки")
        kv.append((f"java[{pid}]", f"CPU avg {fmt_num(fmean(cpu), 0)}% max {fmt_num(fmax(cpu), 0)}% (в % ядра); RSS {fmt_mb(rss[0])} → {fmt_mb(rss[-1])} (max {fmt_mb(fmax(rss))}); "
                                   f"{thr_txt}; виден в {len(lst)} снимках"))
    if not any(host.top):
        kv.append(("процессы", "TOP отсутствует (nmon без -t)"))
    else:
        agg_ = defaultdict(list)
        for procs in host.top:
            per_cmd = defaultdict(float)
            for p in procs:
                if p.cpu == p.cpu:
                    per_cmd[p.cmd] += p.cpu
            for c, v in per_cmd.items():
                agg_[c].append(v)
        top5 = sorted(agg_.items(), key=lambda kv_: -fsum(kv_[1]))[:6]
        kv.append(("процессы по суммарному CPU (все PID команды вместе)",
                   "; ".join(f"{c} avg {fmt_num(fmean(v), 0)}% max {fmt_num(fmax(v), 0)}% ({len(v)} сн.)" for c, v in top5)))
    rep.kv("Ключевые показатели", kv)
    F = _filter_sev(health_checks(host, _opt(args, "thresholds", None), link_mbit=_opt(args, "link_mbit", None)), args)
    rep.findings("Замечания (health)", F)
    # Краткий таймлайн с крупным шагом
    if host.n() > 3:
        dur = host.duration()
        step_s = 300 if dur <= 3 * 3600 else (900 if dur <= 12 * 3600 else 3600)
        cols = ["cpu.busy", "cpu.wait", "proc.runq", "proc.blocked", "mem.avail", "disk.busy_max", "disk.write", "disk.read", "net.read", "net.write", "top.java.cpu", "top.java.rss"]
        res = [(c, resolve_metric(host, c)) for c in cols]
        res = [(c, r) for c, r in res if r]
        if res:
            tt = None
            agg = []
            for c, r in res:
                tt, vv = downsample(host.times, r[2], step_s, "max" if c in ("cpu.busy", "cpu.wait", "proc.runq", "proc.blocked", "disk.busy_max", "disk.write", "disk.read", "net.read", "net.write", "top.java.cpu") else "mean")
                agg.append(vv)
            rows = [[tt[k]] + [a[k] for a in agg] for k in range(len(tt))]
            rep.table(f"Таймлайн (шаг {fmt_dur(step_s)}; max для загрузок, mean для памяти)", ["время"] + [c for c, _ in res], rows,
                      prec={c: 0 for c, _ in res})
    return rep


# --------------------------------------------------------------------------
# Кластер: сравнение хостов, выбросы, синхронные события
# --------------------------------------------------------------------------

CLUSTER_METRICS = [
    ("cpu.busy", "mean"), ("cpu.busy", "p95"), ("cpu.wait", "mean"), ("cpu.steal", "max"), ("cpu.sys", "mean"),
    ("proc.runq", "p95"), ("proc.blocked", "p95"), ("mem.avail", "min"), ("mem.swap_used", "max"),
    ("disk.busy_max", "p95"), ("disk.write", "max"), ("disk.read", "max"), ("disk.iops", "max"),
    ("net.read", "max"), ("net.write", "max"),
    ("top.java.cpu", "mean"), ("top.java.rss", "max"), ("top.java.threads", "max"), ("top.java.sys", "mean"),
]


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


def analyze_cluster(hosts, args=None):
    rep = Report(f"Кластер: сравнение {len(hosts)} хостов")
    thr = _opt(args, "thresholds", None)
    # Покрытие
    cov = []
    for h in hosts:
        cov.append([h.name, h.start(), h.end(), fmt_dur(h.duration()), h.n(), h.ncpus(),
                    fmt_mb(fmax(h.col("MEM", "memtotal"))) if h.has("MEM") else "-", len(h.gaps()), len(h.files)])
    rep.table("Покрытие данными", ["host", "начало", "конец", "длительность", "снимков", "CPU", "RAM", "разрывов", "файлов"], cov)
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
                      ("MTU(bond/nic)", lambda h: ",".join(sorted({str(i['mtu']) for i in h.ifconfig() if i['name'] != 'lo' and 'RUNNING' in i['flags']}))),
                      ("swap", lambda h: fmt_mb(fmax(h.col("MEM", "swaptotal"))) if h.has("MEM") else "-"),
                      ("THP AnonHugePages", lambda h: fmt_bytes_kb(h.meminfo().get("AnonHugePages")) if h.meminfo() else "-"),
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
    for h in hosts:
        row = [h.name]
        for m, a in CLUSTER_METRICS:
            r = resolve_metric(h, m)
            v = _agg(r[2], a) if r else NAN
            if r and r[1]:
                unit_of[f"{m}:{a}"] = r[1]
            row.append(v)
            matrix.setdefault(f"{m}:{a}", []).append(v)
        rows.append(row)
    sortkey = _opt(args, "sort", None)
    if sortkey:
        if sortkey not in cols:
            raise SystemExit(f"ERROR: --sort: неизвестная колонка {sortkey!r}; доступны: {', '.join(cols)}")
        k = cols.index(sortkey) + 1
        rows.sort(key=lambda r: -(r[k] if r[k] == r[k] else -1e18))
    labels = [f"{c} [{unit_of[c]}]" if c in unit_of else c for c in cols]
    rep.table("Метрики по хостам", ["host"] + labels, rows,
              prec={lab: 0 for lab, c in zip(labels, cols) if c.split(":")[0].startswith(("disk.", "net.", "mem.", "top.java.rss", "top.java.threads", "proc."))},
              note="mean/p95/max/min — по всему периоду каждого хоста; сортировка: --sort <метрика:агрегат>, например cpu.busy:p95")
    # Выбросы: если покрытие хостов сильно различается, считаем в общем окне (иначе длинные файлы
    # с другой фазой нагрузки выглядят «выбросами» просто из-за периода)
    F = []
    out_rows = []
    w, c = _thr(thr, "CLUSTER_OUTLIER")
    groups = []
    out_matrix = matrix
    out_note = "по всему периоду каждого хоста"
    durs = [h.duration() for h in hosts if h.duration() > 0]
    if starts and ends and durs and max(durs) > 1.5 * min(durs):
        cs, ce = max(starts), min(ends)
        if ce > cs:
            hc = [h.slice([cs <= t <= ce for t in h.times]) for h in hosts]
            out_matrix = {}
            for h in hc:
                for m, a in CLUSTER_METRICS:
                    r = resolve_metric(h, m)
                    out_matrix.setdefault(f"{m}:{a}", []).append(_agg(r[2], a) if r else NAN)
            out_note = f"в общем окне {ts(cs)} .. {ts(ce)} (покрытие хостов различается более чем в 1.5 раза)"
    if len(hosts) >= 4:
        for key, vals in out_matrix.items():
            zs = robust_z(vals)
            med = fmedian(vals)
            cand = []
            for h, v, z in zip(hosts, vals, zs):
                if z != z or v != v or abs(z) < w:
                    continue
                # значимость: отличие от медианы не меньше 10% (или 2 п.п. для процентов)
                rel_ok = abs(v - med) >= max(0.10 * abs(med), 2.0 if key.split(":")[0].startswith("cpu.") else 1e-9)
                if not rel_ok:
                    continue
                cand.append((h, v, z))
            if not cand:
                continue
            if len(cand) > 0.25 * len(hosts):
                # не выбросы, а две группы узлов (например, разные роли/нагрузка)
                groups.append([key, len(cand), len(hosts), med, ", ".join(sorted(h.name for h, _, _ in cand)[:10])
                               + ("…" if len(cand) > 10 else "")])
                continue
            for h, v, z in cand:
                out_rows.append([h.name, key, v, med, z])
                sev = "CRIT" if abs(z) >= c else "WARN"
                F.append(Finding(sev, "CLUSTER_OUTLIER", h.name, key, v, f"|z| ≥ {w}",
                                 f"медиана по кластеру {med:.1f}, z={z:.1f}; агрегаты {out_note}",
                                 "узел отличается от остальных: смотрите его подробно (report/at)"))
        out_rows.sort(key=lambda r: -abs(r[4]))
        rep.table("Выбросы среди хостов (робастный z по медиане/MAD, отличие ≥ 10%)", ["host", "метрика", "значение", "медиана кластера", "z"],
                  out_rows[:40], total=len(out_rows), prec={"значение": 1, "медиана кластера": 1, "z": 1},
                  note=f"агрегаты {out_note}")
        if groups:
            rep.table("Метрики, по которым узлы делятся на группы (> 25% хостов отклоняются — не выброс, а разная нагрузка/роль)",
                      ["метрика", "хостов отклоняется", "всего", "медиана", "хосты"], groups, prec={"медиана": 1})
    else:
        rep.text("Выбросы среди хостов", "меньше 4 хостов — статистика выбросов не считается")
    # Синхронные события: корзины времени, в которых у ≥ доли хостов выброс
    bucket = max(60.0, fmedian([h.step() for h in hosts]) or 60.0)
    metrics = _opt(args, "metrics", None) or ["cpu.busy", "cpu.wait", "proc.blocked", "disk.busy_max", "disk.write", "disk.read", "net.read", "net.write", "top.java.cpu"]
    min_abs = {"cpu.busy": 10, "cpu.wait": 5, "proc.blocked": 3, "disk.busy_max": 15, "disk.write": 20000, "disk.read": 20000,
               "net.read": 10000, "net.write": 10000, "top.java.cpu": 100}
    zv = _opt(args, "z", None)
    z_thr = 4.0 if zv is None else float(zv)
    ref = datetime(2000, 1, 1)

    def bucket_of(t):
        return ref + timedelta(seconds=math.floor((t - ref).total_seconds() / bucket) * bucket)

    sync = defaultdict(lambda: defaultdict(dict))  # metric -> bucket_time -> {host: earliest exact time}
    unknown = {m for m in metrics if all(resolve_metric(h, m) is None for h in hosts)}
    for m in sorted(unknown):
        warn(f"cluster: метрика {m!r} неизвестна или отсутствует у всех хостов (список: команда metrics)")
    for h in hosts:
        for m in metrics:
            r = resolve_metric(h, m)
            if not r:
                continue
            for t, v, base, z in rolling_spikes(r[2], h.times, window=15, z_thr=z_thr, min_abs=min_abs.get(m), direction="up"):
                d = sync[m][bucket_of(t)]
                if h.name not in d or t < d[h.name]:
                    d[h.name] = t
    w, c = _thr(thr, "CLUSTER_SYNC")
    srows = []
    min_hosts = max(3, math.ceil(0.2 * len(hosts))) if len(hosts) >= 3 else 2
    for m, buckets in sync.items():
        for bt, hs in buckets.items():
            share = 100.0 * len(hs) / len(hosts)
            if len(hs) >= 2 and (len(hs) >= min_hosts or share >= w):
                first_host, first_t = min(hs.items(), key=lambda kv_: kv_[1])
                srows.append([bt, m, len(hs), share, f"{first_host} @ {first_t.strftime('%H:%M:%S')}",
                              ", ".join(sorted(hs)[:8]) + ("…" if len(hs) > 8 else "")])
                sev = _sev(share, w, c) if len(hosts) >= 3 else None
                if sev:
                    F.append(Finding(sev, "CLUSTER_SYNC", "*", f"{m}: доля хостов с одновременным выбросом, %", share, f"≥ {w}",
                                     f"{ts(bt)}: {len(hs)} хостов: {', '.join(sorted(hs)[:6])}; первый: {first_host} @ {ts(first_t)}",
                                     "кластерное событие: PME/rebalance/checkpoint по расписанию/снапшот/массовая нагрузка", time=bt))
    srows.sort(key=lambda r: (r[0], -r[2]))
    rep.table("Синхронные выбросы (одна корзина времени, несколько хостов)",
              ["время (корзина)", "метрика", "хостов", "% хостов", "первый хост", "хосты"],
              srows[:60], total=len(srows), prec={"% хостов": 0},
              note=f"корзина {fmt_dur(bucket)}; порядок «кто первый» надёжен только при синхронных часах и с точностью до интервала")
    # Кластерный таймлайн: агрегаты по корзинам времени
    if starts and ends:
        span = (max(ends) - min(starts)).total_seconds()
        step_s = 300 if span <= 3 * 3600 else (900 if span <= 12 * 3600 else 3600)
        spec = [("cpu.busy", "mean"), ("cpu.wait", "mean"), ("proc.blocked", "max"), ("disk.busy_max", "max"),
                ("disk.write", "sum"), ("disk.read", "sum"), ("net.read", "sum"), ("net.write", "sum"), ("top.java.cpu", "sum")]
        acc = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))  # bucket -> metric -> host -> values
        present = defaultdict(set)
        for h in hosts:
            per = {}
            for m, _a in spec:
                r = resolve_metric(h, m)
                if r:
                    per[m] = r[2]
            for i, t in enumerate(h.times):
                k = bucket_start(t, step_s)
                present[k].add(h.name)
                for m, vals in per.items():
                    v = vals[i]
                    if v == v:
                        acc[k][m][h.name].append(v)
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
                  note="для каждого хоста берётся среднее по его снимкам в корзине; сумма — по хостам, у которых метрика есть")
    # Покрытие: хосты без данных, когда у остальных есть
    all_start = min(h.start() for h in hosts if h.start())
    all_end = max(h.end() for h in hosts if h.end())
    w, c = _thr(thr, "CLUSTER_COVERAGE")
    covrows = []
    for h in hosts:
        if not h.times:
            continue
        step = h.step()
        late = (h.start() - all_start).total_seconds() / step
        early = (all_end - h.end()).total_seconds() / step
        if early >= w:
            sev = _sev(early, w, c)
            F.append(Finding(sev, "CLUSTER_COVERAGE", h.name, "данные закончились раньше других, снимков", early, f"≥ {w}",
                             f"конец {ts(h.end())}, у кластера {ts(all_end)}", "узел/nmon остановился раньше остальных: падение узла?", time=h.end()))
            covrows.append([h.name, "конец раньше", h.end(), early])
        if late >= w:
            covrows.append([h.name, "начало позже", h.start(), late])
        for a, b, d in h.gaps():
            covrows.append([h.name, "разрыв", a, d / step])
    if covrows:
        rep.table("Неполное покрытие", ["host", "вид", "время", "снимков"], covrows[:40], total=len(covrows), prec={"снимков": 0})
    rep.findings("Замечания уровня кластера", F)
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
    rep.worst = 2 if any(r[1] > 0 for r in hrows) else (1 if any(r[2] > 0 for r in hrows) else 0)
    return rep


def analyze_correlate(host, args=None):
    rep = Report("Корреляции между метриками (Пирсон)", host.name)
    metrics = _opt(args, "metrics", None) or ["cpu.busy", "cpu.sys", "cpu.wait", "proc.runq", "proc.blocked", "mem.free",
                                                "disk.busy_max", "disk.read", "disk.write", "disk.iops", "net.read", "net.write",
                                                "top.java.cpu", "top.java.sys", "vm.pgmajfault", "vm.kswapd_steal"]
    res = [(m, r[2]) for m, r in resolve_metrics(host, metrics, warn_missing=bool(_opt(args, "metrics", None)))
           if len(clean(r[2])) >= 5 and fstdev(r[2]) > 0]
    target = _opt(args, "target", None)
    rows = []
    if target:
        rt = resolve_metric(host, target)
        if not rt:
            rep.text("", f"метрика {target} недоступна")
            return rep
        for m, a in res:
            if m == target:
                continue
            rows.append([m, pearson(rt[2], a)])
        rows.sort(key=lambda r: -abs(r[1]) if r[1] == r[1] else 0)
        rep.table(f"Корреляция с {target}", ["метрика", "r"], rows, prec={"r": 2})
    else:
        pairs = []
        for i in range(len(res)):
            for j in range(i + 1, len(res)):
                r = pearson(res[i][1], res[j][1])
                if r == r:
                    pairs.append([res[i][0], res[j][0], r])
        pairs.sort(key=lambda p: -abs(p[2]))
        rep.table("Наиболее связанные пары (|r| ≥ 0.5)", ["метрика A", "метрика B", "r"],
                  [p for p in pairs if abs(p[2]) >= 0.5][:_opt(args, "limit", 40) or 40], prec={"r": 2},
                  note="корреляция ≠ причинность; r > 0.7 — сильная связь по времени (например, disk.write ↔ cpu.wait)")
    return rep


def analyze_export(host, args=None):
    """Выгрузка секции или набора метрик с реальным временем."""
    rep = Report("Экспорт", host.name)
    section = _opt(args, "section", None)
    metrics = _opt(args, "metrics", None)
    step_s = parse_duration(_opt(args, "step", None)) if _opt(args, "step", None) else 0
    if section:
        sec = section.upper()
        if sec == "TOP":
            rows = []
            for i, procs in enumerate(host.top):
                for p in procs:
                    rows.append([host.times[i], p.pid, p.cmd, p.cpu, p.usr, p.sys, p.size, p.rss, p.minflt, p.majflt, p.threads, p.iowait])
            rep.table("TOP", ["time", "pid", "command", "cpu_pct", "usr_pct", "sys_pct", "size_kb", "rss_kb", "minflt", "majflt", "threads", "iowait"],
                      rows, prec={"pid": 0, "size_kb": 0, "rss_kb": 0, "minflt": 0, "majflt": 0, "threads": 0, "iowait": 0})
            return rep
        if sec == "UARG":
            rows = []
            for pid, (prog, full, first) in host.uarg_cmdlines().items():
                rows.append([first, pid, prog, full])
            rep.table("UARG", ["first_seen", "pid", "prog", "cmdline"], rows, prec={"pid": 0})
            return rep
        if sec not in host.series:
            rep.text("", f"секция {sec} отсутствует; есть: {', '.join(sorted(host.series))}")
            return rep
        cols = host.cols(sec)
        colsel = _opt(args, "columns", None)
        if colsel:
            cols = [c for c in cols if any(re.fullmatch(p, c) for p in colsel)]
            if not cols:
                rep.text("", f"--columns {colsel}: ни одна колонка секции {sec} не подошла; есть: {', '.join(host.cols(sec))}")
                return rep
        rows = [[host.times[i]] + [host.series[sec][c][i] for c in cols] for i in range(host.n())]
        total = len(rows)
        limit = _opt(args, "limit", None)
        if limit and len(rows) > limit:
            rows = rows[:limit]
        rep.table(sec, ["time"] + cols, rows, prec={c: 3 for c in cols}, total=total)
        return rep
    explicit = bool(metrics)
    metrics = metrics or DEFAULT_TIMELINE
    res = [(m, r[2]) for m, r in resolve_metrics(host, metrics, warn_missing=explicit)]
    if step_s:
        tt = None
        agg = []
        for m, a in res:
            tt, vv = downsample(host.times, a, step_s, _opt(args, "agg", "mean") or "mean")
            agg.append((m, vv))
        rows = [[tt[k]] + [a[k] for _, a in agg] for k in range(len(tt))]
    else:
        rows = [[host.times[k]] + [a[k] for _, a in res] for k in range(host.n())]
    total = len(rows)
    limit = _opt(args, "limit", None)
    if limit and len(rows) > limit:
        rows = rows[:limit]
    rep.table("metrics", ["time"] + [m for m, _ in res], rows, prec={m: 3 for m, _ in res}, total=total)
    return rep


def analyze_bbbp(host, args=None):
    rep = Report("Конфигурация ОС на старте nmon (BBBP)", host.name)
    block = _opt(args, "block", None)
    pat = _opt(args, "grep", None)
    if not block and not pat:
        rep.table("Блоки", ["блок", "строк", "первая строка"],
                  [[c, len(host.bbbp[c]), (host.bbbp[c][0][:80] if host.bbbp[c] else "")] for c in host.bbbp_order])
        rep.text("Подсказка", "укажите --block <имя> (например lscpu, /proc/meminfo, /bin/df-m, /bin/mount, ifconfig) или --grep <regex>")
        return rep
    for c in host.bbbp_order:
        if block and not any(re.search(b, c) for b in block):
            continue
        lines = host.bbbp[c]
        if pat:
            lines = [ln for ln in lines if re.search(pat, ln)]
        if lines:
            rep.text(c, "\n".join(lines[:_opt(args, "limit", 400) or 400]) + (f"\n… ещё {len(lines) - 400} строк" if len(lines) > 400 else ""))
    return rep


AIX_SECTIONS = {"LPAR", "POOLS", "PAGE", "MEMNEW", "MEMUSE", "SEA", "SEACHPHY", "FCREAD", "FCWRITE", "FCXFERIN",
                "FCXFEROUT", "PROCAIO", "IOADAPT", "MEMAMS", "WLMCPU", "WLMMEM", "WLMBIO"}


def analyze_check(host, args=None):
    """Качество и согласованность данных: разбор, интервал, секции, «мёртвые» колонки, перекрёстные проверки."""
    rep = Report("Проверка качества данных nmon", host.name)
    issues = []
    n = host.n()
    for f in host.files:
        b = os.path.basename(f.path)
        if f.bad_lines:
            issues.append(("WARN", f"{b}: нераспознанных строк: {f.bad_lines}"))
        for w in f.warnings:
            issues.append(("WARN", f"{b}: {w}"))
        unknown = sorted(s for s in f.sections if s not in SECTION_INFO and not re.match(r"^CPU\d+$", s)
                         and Host._base_name(s) not in SECTION_INFO and s not in AIX_SECTIONS)
        if unknown:
            issues.append(("INFO", f"{b}: секции без специальной обработки (доступны через raw.<SECTION>.<col> и export): {', '.join(unknown)}"))
        aix = sorted(s for s in f.sections if s in AIX_SECTIONS)
        if aix:
            issues.append(("WARN", f"{b}: секции AIX ({', '.join(aix)}) — файл, вероятно, с AIX; Linux-интерпретация правил неприменима"))
        if not f.zzzz:
            issues.append(("CRIT", f"{b}: нет строк ZZZZ — время снимков оценено по интервалу"))
        planned = f.meta.get("snapshots", "")
        try:
            pl = int(planned)
            if 0 < pl < 9999999 and len(f.zzzz) < pl:
                issues.append(("INFO", f"{b}: записано {len(f.zzzz)} снимков из запланированных {pl} (nmon остановлен раньше или ещё писал файл)"))
        except ValueError:
            pass
        if not f.top:
            issues.append(("INFO", f"{b}: секция TOP отсутствует — nmon без -t; анализ процессов невозможен"))
        elif not f.uarg:
            issues.append(("INFO", f"{b}: UARG отсутствует — nmon без -T; командные строки/флаги JVM недоступны"))
    if len(host.files) > 1:
        issues.append(("INFO", f"файлов хоста: {len(host.files)}; отброшено дублирующих снимков при объединении: {host.duplicates_dropped}"))
    if n >= 3:
        deltas = [(host.times[i + 1] - host.times[i]).total_seconds() for i in range(n - 1)]
        med = fmedian(deltas)
        if host.interval and abs(med - host.interval) > 0.1 * host.interval:
            issues.append(("WARN", f"фактический медианный шаг {med:.0f}s отличается от заявленного interval={host.interval:.0f}s"))
        jit = [d for d in deltas if abs(d - med) > 0.25 * med]
        if jit:
            issues.append(("WARN", f"снимков с отклонением шага > 25% от медианы: {len(jit)} из {n - 1} (min {min(deltas):.0f}s, max {max(deltas):.0f}s) — "
                                   f"nmon запаздывал (перегрузка хоста) или файлы склеены"))
    back = sum(f.time_backwards for f in host.files)
    if back:
        issues.append(("WARN", f"в {back} переходах между строками ZZZZ время идёт назад (DST, коррекция NTP, склейка файлов); "
                               f"снимки переупорядочены по времени"))
    for a, b_, d in host.gaps()[:10]:
        issues.append(("WARN", f"разрыв {fmt_dur(d)}: {ts(a)} → {ts(b_)} (заморозка хоста / остановка nmon)"))
    if n >= 1:
        issues.append(("INFO", f"первый снимок {ts(host.times[0])} (T0001) охватывает неполный интервал; TOP начинается с T0002; "
                               f"для точных дельт используйте --skip-first"))
    # Перекрёстные проверки
    checks = []
    u, s_, wv, idv, st = (host.col("CPU_ALL", c) for c in ("User%", "Sys%", "Wait%", "Idle%", "Steal%"))
    if u is not None and idv is not None:
        bad = 0
        for i in range(n):
            tot = sum(x[i] for x in (u, s_, wv, idv, st) if x is not None and x[i] == x[i])
            if tot == tot and abs(tot - 100.0) > 3.0:
                bad += 1
        checks.append(["CPU_ALL: user+sys+wait+idle+steal ≈ 100%", "ok" if bad == 0 else f"{bad} снимков вне ±3%", bad == 0])
    aaa_cpus = host.meta.get("cpus", "")
    ncore = len(host.cpu_cores)
    c_all = host.col("CPU_ALL", "CPUs")
    ncpu_all = int(fmax(c_all)) if c_all is not None and fmax(c_all) == fmax(c_all) else None
    vals = {aaa_cpus or "?", str(ncore) if ncore else "?", str(ncpu_all) if ncpu_all else "?"} - {"?"}
    checks.append(["число CPU: AAA cpus / секций CPUnnn / CPU_ALL CPUs", f"{aaa_cpus} / {ncore} / {ncpu_all}", len(vals) <= 1])
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
        checks.append(["среднее busy по CPUnnn ≈ CPU_ALL busy (средняя |разница|, п.п.)", f"{diff:.2f}", diff == diff and diff < 3])
    po = host.col("VM", "pgpgout")
    dw = host.disk_total("DISKWRITE")
    if po is not None and dw is not None and fsum(dw) > 0:
        ratio = fsum(po) / (fsum(dw) * host.step())
        checks.append(["VM pgpgout (KB/интервал) ≈ Σ DISKWRITE физических дисков × интервал (отношение)", f"{ratio:.2f}", 0.7 <= ratio <= 1.3])
    pi = host.col("VM", "pgpgin")
    dr = host.disk_total("DISKREAD")
    if pi is not None and dr is not None and fsum(dr) > 0:
        ratio = fsum(pi) / (fsum(dr) * host.step())
        checks.append(["VM pgpgin ≈ Σ DISKREAD × интервал (отношение)", f"{ratio:.2f}", 0.7 <= ratio <= 1.3])
    slaves = host.bond_slaves()
    for bond in [i for i in host.net_ifaces() if i.startswith("bond")]:
        b_rd = host.col("NET", f"{bond}-read-KB/s")
        s_sum = 0.0
        for sl in slaves:
            a = host.col("NET", f"{sl}-read-KB/s")
            if a is not None:
                s_sum += fsum(a)
        if b_rd is not None and fsum(b_rd) > 0 and s_sum > 0:
            ratio = s_sum / fsum(b_rd)
            checks.append([f"{bond} rx ≈ Σ rx слейвов (отношение)", f"{ratio:.2f}", 0.8 <= ratio <= 1.2])
    xf = host.disk_total("DISKXFER")
    if xf is not None and dw is not None and dr is not None:
        bs_calc = (fsum(dw) + fsum(dr)) / fsum(xf) if fsum(xf) > 0 else NAN
        checks.append(["средний размер IO по (read+write)/IOPS, KB", f"{bs_calc:.1f}", True])
    mt = host.col("MEM", "memtotal")
    if mt is not None and clean(mt):
        checks.append(["MEM memtotal постоянен", "да" if fmin(mt) == fmax(mt) else f"нет: {fmin(mt):.0f}..{fmax(mt):.0f} MB", fmin(mt) == fmax(mt)])
    mi = host.meminfo()
    if mi.get("MemTotal") and mt is not None:
        ratio = fmax(mt) * 1024.0 / mi["MemTotal"]
        checks.append(["MEM memtotal ≈ /proc/meminfo MemTotal", f"{ratio:.3f}", 0.97 <= ratio <= 1.03])
    top_n = sum(1 for x in host.top if x)
    if top_n:
        checks.append(["снимков с данными TOP", f"{top_n} из {n}", top_n >= n - 1])
        sizes = [len(x) for x in host.top if x]
        checks.append(["процессов в снимке TOP: min / median / max", f"{min(sizes)} / {fmedian(sizes):.0f} / {max(sizes)}", True])
        pgmaj = host.col("VM", "pgmajfault")
        if pgmaj is not None:
            proc_ev = 0.0
            sys_ev = 0.0
            for i, procs in enumerate(host.top):
                if not procs or pgmaj[i] != pgmaj[i]:
                    continue
                proc_ev += sum(p.majflt for p in procs if p.majflt == p.majflt) * host.step()
                sys_ev += pgmaj[i]
            if sys_ev > 0:
                ratio = proc_ev / sys_ev
                checks.append(["Σ TOP MajorFault (/s × интервал) vs VM pgmajfault (отношение; ≫ 1 = колонка TOP ненадёжна)", f"{ratio:.1f}", ratio <= 10])
    av = host.mem_avail()
    mi_ = host.meminfo()
    if av and mi_.get("MemAvailable") and av[0] == av[0]:
        ratio = av[0] * 1024.0 / mi_["MemAvailable"]
        checks.append(["оценка avail (первый снимок) / MemAvailable ядра на старте", f"{ratio:.2f}", 0.7 <= ratio <= 1.5])
    if checks:
        rep.table("Перекрёстные проверки", ["проверка", "результат", "ok"], [[a, b, "да" if c else "НЕТ"] for a, b, c in checks])
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
                zeros.append(c)
            elif all(v < 0 for v in cl):
                na.append(c)
        if zeros or na:
            dead.append([sec, ", ".join(zeros)[:150], ", ".join(na)[:150]])
    if dead:
        rep.table("Колонки без информации за период (всегда 0 / всегда N/A)", ["секция", "всегда 0", "N/A (-1 или пусто)"], dead,
                  note="0 в VM для kswapd_steal/allocstall/pgscan_*/pgsteal_*/pgrefill_* на ядрах ≥ 4.x — норма (счётчики переименованы), "
                       "не признак отсутствия активности; -1 в PROC (syscall/read/write/exec/sem/msg) — nmon для Linux их не собирает")
    sev_rank = {"CRIT": 0, "WARN": 1, "INFO": 2}
    issues.sort(key=lambda x: sev_rank.get(x[0], 9))
    verdict = "непригодны" if any(s == "CRIT" for s, _ in issues) or n < 3 or not host.has("CPU_ALL") else \
        ("пригодны с оговорками" if any(s == "WARN" for s, _ in issues) or any(not c for _, _, c in checks) else "пригодны")
    rep.kv("Вердикт", [("данные", verdict), ("снимков", n), ("период", f"{ts(host.start())} .. {ts(host.end())}")])
    rep.text("Замечания", "\n".join(f"[{s}] {t}" for s, t in issues) if issues else "нет")
    return rep


def _parse_window(spec, host):
    """'HH:MM-HH:MM' или 'A..B' (любой формат времени) -> (datetime, datetime).
    Время суток без даты берётся на дату первого снимка; если оно раньше начала данных,
    а данные переходят через полночь — переносится на следующий день."""
    ref = host.times[0]
    if ".." in spec:
        a, b = spec.split("..", 1)
    else:
        m = re.match(r"^\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*-\s*(\d{1,2}:\d{2}(?::\d{2})?)\s*$", spec)
        if not m:
            raise ValueError(f"окно {spec!r}: ожидается 'HH:MM-HH:MM' или 'начало..конец'")
        a, b = m.group(1), m.group(2)
    ta = parse_user_time(a.strip(), ref)
    tb = parse_user_time(b.strip(), ref)
    tod = re.match(r"^\s*\d{1,2}:\d{2}(:\d{2})?\s*$", a) is not None
    crosses = host.times[-1].date() != ref.date()
    if tod and ta < ref and crosses and ta + timedelta(days=1) <= host.times[-1]:
        ta += timedelta(days=1)
        tb += timedelta(days=1)
    if tb < ta:
        if tod and crosses and tb + timedelta(days=1) <= host.times[-1] + timedelta(days=1):
            tb += timedelta(days=1)
        else:
            raise ValueError(f"окно {spec!r}: конец раньше начала")
    return ta, tb


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
    try:
        ta, tb = _parse_window(spec_a, host)
        tc, td = _parse_window(spec_b, host)
    except ValueError as e:
        raise SystemExit(f"ERROR: {e}")
    ha = host.slice([ta <= t <= tb for t in host.times])
    hb = host.slice([tc <= t <= td for t in host.times])
    rep.kv("Окна", [("A", f"{ts(ta)} .. {ts(tb)} ({ha.n()} снимков)"), ("B", f"{ts(tc)} .. {ts(td)} ({hb.n()} снимков)")])
    if ha.n() == 0 or hb.n() == 0:
        rep.text("", "в одном из окон нет снимков")
        return rep
    metrics = _opt(args, "metrics", None) or DEFAULT_TIMELINE + ["vm.pgmajfault", "mem.used", "top.java.sys", "cpu.core_max"]
    rows = []
    for m, ra in resolve_metrics(ha, metrics, warn_missing=bool(_opt(args, "metrics", None))):
        rb = resolve_metric(hb, m)
        if not rb or not clean(ra[2]) or not clean(rb[2]):
            continue
        ma, mb = fmean(ra[2]), fmean(rb[2])
        pa, pb = percentile(ra[2], 95), percentile(rb[2], 95)
        d_mean = 100.0 * (mb - ma) / abs(ma) if ma == ma and ma != 0 else NAN
        d_p95 = 100.0 * (pb - pa) / abs(pa) if pa == pa and pa != 0 else NAN
        rows.append([m, ra[1], ma, pa, fmax(ra[2]), mb, pb, fmax(rb[2]), d_mean, d_p95])
    rows.sort(key=lambda r: -(abs(r[8]) if r[8] == r[8] else -1))
    rep.table("Метрики: A vs B", ["метрика", "ед.", "A avg", "A p95", "A max", "B avg", "B p95", "B max", "Δavg %", "Δp95 %"], rows,
              prec={"Δavg %": 0, "Δp95 %": 0, "A avg": 1, "B avg": 1},
              note="отсортировано по |Δavg|; Δ = (B − A) / |A|")
    # процессы: кто появился/вырос
    if any(ha.top) and any(hb.top):
        def agg(h):
            d = defaultdict(float)
            cnt = defaultdict(int)
            n_top = sum(1 for x in h.top if x)
            for procs in h.top:
                for p in procs:
                    if p.cpu == p.cpu:
                        d[p.cmd] += p.cpu
                        cnt[p.cmd] += 1
            return {k: v / max(1, n_top) for k, v in d.items()}, cnt, n_top
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
    ("Можно ли доверять данным: разрывы, дрожание интервала, «мёртвые» колонки, перекрёстные проверки, вердикт?", "check"),
    ("Какие секции и колонки есть в файле?", "sections"),
    ("Общая картина: что не так с узлом? С чего начать?", "report (затем health, events)"),
    ("Есть ли проблемы по порогам (CPU, память, swap, диски, ФС, java)?", "health [--thr CODE=WARN,CRIT]"),
    ("Насколько загружен CPU, сколько времени выше 80/90%, когда пики, user vs sys vs iowait vs steal?", "cpu"),
    ("Есть ли «горячее» одно ядро (однопоточное узкое место)? Дисбаланс ядер? Топология NUMA/HT?", "cpu, cores [--sort max]"),
    ("Есть ли CPU steal (виртуализация)?", "cpu, health (CPU_STEAL)"),
    ("Длина очереди на CPU, число заблокированных (D-state) процессов, переключения контекста?", "proc"),
    ("Сколько памяти использовано/свободно/в page cache, минимум доступной памяти, тренд роста, до исчерпания?", "mem"),
    ("Был ли swap, reclaim (kswapd/direct), major faults, грязные страницы?", "vm, health"),
    ("Какие hugepages/THP/overcommit настройки (meminfo на старте)?", "mem, bbbp --block /proc/meminfo"),
    ("Как загружены диски: busy, IOPS, throughput, размер IO, время > 80%, пики, периодичность всплесков?", "disk [--all] [--dev nvme0n1]"),
    ("Какой диск за какой точкой монтирования (WAL, persistence, логи)? LVM-карта, df, fstab?", "diskmap"),
    ("Заполненность файловых систем, рост, когда заполнится, скачки?", "fs [--mount '/opt/ignite.*']"),
    ("Сетевой трафик по интерфейсам, пакеты, размер пакета, MTU, ошибки, простои интерфейса, пики?", "net [--link-mbit 10000]"),
    ("Какие процессы потребляли CPU/память, их RSS/threads/faults, перезапуски?", "top [--cmd java] [--sort rss]"),
    ("Как вёл себя процесс java (Ignite): CPU, sys-доля, RSS, потоки, паузы, перезапуски, конкуренты?", "java"),
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
                            "--format text|md|json|csv; --top N; --output file; --no-merge; --thr CODE=WARN[,CRIT]; --link-mbit N")
    return rep


def analyze_metrics_list(host, args=None):
    rep = Report("Доступные метрики", host.name)
    rows = []
    for name in list_metrics(host):
        r = resolve_metric(host, name)
        if r:
            rows.append([name, r[1], BASE_METRICS[name][0] if name in BASE_METRICS else r[0], len(clean(r[2]))])
    rep.table("Метрики", ["имя", "ед.", "описание", "значений"], rows,
              note="шаблоны: disk.<dev>.busy|read|write|iops|bsize, net.<if>.read|write|pkt_in|pkt_out, fs.<mount>.pct, "
                   "cpu.core<N>.busy|user|sys|wait, top.<cmd>.cpu|rss|threads|sys|majflt, top.pid<PID>.cpu, raw.<SECTION>.<column>")
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


def _parse_thr(items):
    out = {}
    for it in items or []:
        m = re.match(r"^([A-Z_]+)=([-\d.]+)(?:,([-\d.]+))?$", it.strip())
        if not m:
            raise SystemExit(f"ERROR: --thr ожидает CODE=WARN[,CRIT], получено {it!r}")
        code = m.group(1)
        if code not in DEFAULT_THRESHOLDS:
            raise SystemExit(f"ERROR: неизвестный код правила {code}; известные: {', '.join(sorted(DEFAULT_THRESHOLDS))}")
        out[code] = (float(m.group(2)), float(m.group(3)) if m.group(3) else None)
    return out


def build_parser():
    p = argparse.ArgumentParser(
        prog="nmon_analyzer.py",
        description="Анализ файлов nmon (Linux) для разбора работы узлов Apache Ignite. "
                    "Команда `questions` показывает, какой командой отвечать на какой вопрос.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Примеры:\n"
               "  python nmon_analyzer.py report node1.nmon\n"
               "  python nmon_analyzer.py cluster /var/log/nmon/ --format md\n"
               "  python nmon_analyzer.py at --time 03:52 --host node07 *.nmon\n"
               "  python nmon_analyzer.py timeline --metrics cpu.busy disk.write --step 5m --agg max node1.nmon\n"
               "  python nmon_analyzer.py disk --dev nvme0n1 --from 03:30 --to 04:10 node1.nmon --format json\n")
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
        sp.add_argument("--top", type=int, help="сколько строк/пиков показывать (по умолчанию зависит от команды)")
        sp.add_argument("--no-merge", action="store_true", help="не объединять файлы одного хоста")
        sp.add_argument("--thr", action="append", help="переопределить порог: CODE=WARN[,CRIT] (см. health)")
        sp.add_argument("--link-mbit", type=float, dest="link_mbit", help="скорость сетевого линка, Mbit/s (для оценки насыщения)")
        sp.add_argument("--no-info", action="store_true", help="не показывать INFO-замечания")
        sp.add_argument("--min-severity", dest="min_severity", choices=["CRIT", "WARN", "INFO"], help="показывать замечания не ниже уровня")
        sp.add_argument("--skip-first", dest="skip_first", action="store_true", help="отбросить первый снимок каждого файла (неполный интервал)")
        sp.add_argument("--tz-shift", dest="tz_shift", help="сдвинуть все метки времени, например -3h или +02:00 (для сопоставления с логами в другой зоне)")
        sp.add_argument("--verbose", "-v", action="store_true", help="печатать ход разбора в stderr")

    for name, (fn, help_) in {**PER_HOST_COMMANDS, **CLUSTER_COMMANDS}.items():
        sp = sub.add_parser(name, help=help_, description=help_)
        common(sp)
        if name in ("disk",):
            sp.add_argument("--dev", action="append", help="устройство (regex, полное совпадение), можно несколько; работает и по имени LV")
            sp.add_argument("--all", action="store_true", help="включая разделы и dm-*")
        if name == "fs":
            sp.add_argument("--mount", action="append", help="точка монтирования (regex, полное совпадение)")
        if name == "net":
            sp.add_argument("--iface", action="append", help="интерфейс (regex)")
            sp.add_argument("--all", action="store_true", help="включая интерфейсы без трафика")
        if name == "cores":
            sp.add_argument("--sort", choices=["avg", "p95", "max", "sys", "wait"], default="p95")
        if name == "top":
            sp.add_argument("--pid", type=int, action="append", help="только указанные PID")
            sp.add_argument("--cmd", action="append", help="только команды по regex")
            sp.add_argument("--by-cmd", dest="by_cmd", action="store_true", help="группировать по имени команды (все PID вместе)")
            sp.add_argument("--sort", choices=["cpu", "cpumax", "rss", "threads", "majflt", "sys", "snapshots"], default="cpu")
        if name == "uarg":
            sp.add_argument("--cmd", action="append", help="фильтр по regex (prog или командная строка)")
            sp.add_argument("--full", action="store_true", help="полные командные строки без обрезки")
        if name == "at":
            sp.add_argument("--time", help="момент времени ('HH:MM[:SS]' или 'YYYY-MM-DD HH:MM'); по умолчанию — пик CPU")
            sp.add_argument("--window-snaps", dest="window_snaps", type=int, default=2, help="снимков до/после (по умолчанию 2)")
            sp.add_argument("--metrics", nargs="+", help="какие метрики показать (см. metrics)")
        if name in ("timeline", "export"):
            sp.add_argument("--metrics", nargs="+", help="имена метрик (см. metrics)")
            sp.add_argument("--step", help="шаг агрегации: 5m, 1h ...")
            sp.add_argument("--agg", choices=["mean", "max", "min", "sum", "last"], default="mean")
            sp.add_argument("--limit", type=int, help="максимум строк")
        if name == "export":
            sp.add_argument("--section", help="секция nmon (CPU_ALL, MEM, DISKWRITE, TOP, UARG ...) вместо метрик")
            sp.add_argument("--columns", nargs="+", help="фильтр колонок секции (regex, полное совпадение)")
        if name == "events":
            sp.add_argument("--metrics", nargs="+", help="какие метрики проверять")
            sp.add_argument("--z", type=float, default=4.0, help="порог робастного z (по умолчанию 4)")
            sp.add_argument("--window-snaps", dest="window_snaps", type=int, default=15, help="окно скользящей медианы, снимков")
            sp.add_argument("--limit", type=int, default=200)
        if name == "correlate":
            sp.add_argument("--metrics", nargs="+")
            sp.add_argument("--target", help="считать корреляции только с этой метрикой")
            sp.add_argument("--limit", type=int, default=40)
        if name == "bbbp":
            sp.add_argument("--block", action="append", help="имя блока (regex): lscpu, /proc/meminfo, /bin/df-m, /bin/mount, ifconfig ...")
            sp.add_argument("--grep", help="regex по строкам всех блоков")
            sp.add_argument("--limit", type=int, default=400)
        if name == "compare":
            sp.add_argument("--a", help="окно A: 'HH:MM-HH:MM' или 'начало..конец'")
            sp.add_argument("--b", help="окно B: 'HH:MM-HH:MM' или 'начало..конец'")
            sp.add_argument("--metrics", nargs="+", help="имена метрик (см. metrics)")
        if name == "cluster":
            sp.add_argument("--sort", help="колонка сортировки, например cpu.busy:p95")
            sp.add_argument("--metrics", nargs="+", help="метрики для поиска синхронных выбросов")
            sp.add_argument("--z", type=float, default=4.0)
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
    except ValueError as e:
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
    try:
        hosts = apply_time_filter(hosts, args.t_from, args.t_to, args.around, args.window)
    except ValueError as e:
        raise SystemExit(f"ERROR: {e}")
    empty = [h.name for h in hosts if h.n() == 0]
    hosts = [h for h in hosts if h.n() > 0]
    if not hosts:
        raise SystemExit("ERROR: в выбранном окне времени нет снимков")
    if empty:
        warn("в выбранном окне времени нет снимков у хостов: " + ", ".join(empty))
    reports = []
    try:
        if args.command in CLUSTER_COMMANDS:
            reports.append(CLUSTER_COMMANDS[args.command][0](hosts, args))
        else:
            fn = PER_HOST_COMMANDS[args.command][0]
            for h in hosts:
                reports.append(fn(h, args))
    except ValueError as e:
        raise SystemExit(f"ERROR: {e}")
    except re.error as e:
        raise SystemExit(f"ERROR: неверное регулярное выражение: {e}")
    emit(reports, args)
    # код возврата: 2 при CRIT, 1 при WARN (для health/report/cluster), иначе 0
    if args.command in ("health", "report", "cluster"):
        worst = 0
        for r in reports:
            worst = max(worst, getattr(r, "worst", 0))
            for b in r.blocks:
                if b["type"] == "findings":
                    for f in b["items"]:
                        worst = max(worst, 2 if f.severity == "CRIT" else (1 if f.severity == "WARN" else 0))
        return worst
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)
