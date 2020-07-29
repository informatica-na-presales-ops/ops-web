import datetime
import pendulum

from typing import List, Dict


def timedelta_human(td: datetime.timedelta) -> str:
    parts = []
    dur = pendulum.Duration(seconds=td.total_seconds())
    if dur.days > 0:
        day_part = f'{dur.days} day'
        if dur.days > 1:
            day_part = f'{day_part}s'
        parts.append(day_part)
    if dur.hours > 0:
        hour_part = f'{dur.hours} hr'
        if dur.hours > 1:
            hour_part = f'{hour_part}s'
        parts.append(hour_part)
    if dur.minutes > 0:
        minute_part = f'{dur.minutes} min'
        if dur.minutes > 1:
            minute_part = f'{minute_part}s'
        parts.append(minute_part)
    return ' '.join(parts)


def add_running_time_human(col: List[Dict]) -> List[Dict]:
    new_col = []
    for i in col:
        new_i = dict(i)
        if i.get('running_time'):
            new_i['running_time_human'] = timedelta_human(i.get('running_time'))
        else:
            new_i['running_time_human'] = ''
        new_col.append(new_i)
    return new_col
