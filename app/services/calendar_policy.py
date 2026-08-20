from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class ScheduleDecision:
    mode: str
    reason: str
    local_datetime: datetime
    holiday_name: str | None = None


@dataclass(frozen=True)
class AutomationSchedule:
    timezone_name: str
    administrator_available_from: str
    administrator_available_to: str
    automatic_enabled: bool
    automatic_days: frozenset[int]
    automatic_allowed_actions: frozenset[str]
    observe_previous_day_when_sunday: bool
    fixed_holidays: dict[tuple[int, int], str]
    extra_holidays: dict[date, str]


def parse_clock(value: str) -> time:
    try:
        hour, minute = value.split(":", maxsplit=1)
        return time(hour=int(hour), minute=int(minute))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Heure invalide: {value!r}; format attendu HH:MM") from exc


def load_automation_schedule(path: Path) -> AutomationSchedule:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    weekdays = {
        "monday": 0,
        "tuesday": 1,
        "wednesday": 2,
        "thursday": 3,
        "friday": 4,
        "saturday": 5,
        "sunday": 6,
    }
    automatic_day_names = frozenset(
        str(value).lower() for value in data["automatic_days"]
    )
    unknown_days = automatic_day_names - weekdays.keys()
    if unknown_days:
        raise ValueError(f"Jours automatiques inconnus: {sorted(unknown_days)}")

    fixed_holidays: dict[tuple[int, int], str] = {}
    for holiday in data.get("holidays", []):
        key = (int(holiday["month"]), int(holiday["day"]))
        fixed_holidays[key] = str(holiday["name"])

    extra_holidays = {
        date.fromisoformat(str(holiday["date"])): str(holiday["name"])
        for holiday in data.get("extra_holidays", [])
    }
    schedule = AutomationSchedule(
        timezone_name=str(data["timezone"]),
        administrator_available_from=str(data["supervised_start_time"]),
        administrator_available_to=str(data["supervised_end_time"]),
        automatic_enabled=bool(data["automatic_remediation_enabled"]),
        automatic_days=frozenset(weekdays[name] for name in automatic_day_names),
        automatic_allowed_actions=frozenset(
            str(action) for action in data["automatic_allowed_actions"]
        ),
        observe_previous_day_when_sunday=bool(
            data.get("observe_previous_day_when_holiday_is_sunday", True)
        ),
        fixed_holidays=fixed_holidays,
        extra_holidays=extra_holidays,
    )
    parse_clock(schedule.administrator_available_from)
    parse_clock(schedule.administrator_available_to)
    ZoneInfo(schedule.timezone_name)
    return schedule


class CalendarPolicy:
    def __init__(self, schedule: AutomationSchedule) -> None:
        self.schedule = schedule
        self.timezone = ZoneInfo(schedule.timezone_name)
        self.available_from = parse_clock(schedule.administrator_available_from)
        self.available_to = parse_clock(schedule.administrator_available_to)

    @classmethod
    def from_file(cls, path: Path) -> "CalendarPolicy":
        return cls(load_automation_schedule(path))

    def holiday_name(self, day: date) -> str | None:
        if day in self.schedule.extra_holidays:
            return self.schedule.extra_holidays[day]

        fixed_name = self.schedule.fixed_holidays.get((day.month, day.day))
        if fixed_name:
            return fixed_name

        if self.schedule.observe_previous_day_when_sunday:
            following_day = day + timedelta(days=1)
            if following_day.weekday() == 6:
                observed_name = self.schedule.fixed_holidays.get(
                    (following_day.month, following_day.day)
                )
                if observed_name:
                    return f"{observed_name} (conge observe la veille)"
        return None

    def decide(self, when: datetime | None = None) -> ScheduleDecision:
        moment = when or datetime.now(self.timezone)
        if moment.tzinfo is None:
            local = moment.replace(tzinfo=self.timezone)
        else:
            local = moment.astimezone(self.timezone)

        holiday = self.holiday_name(local.date())
        if holiday:
            return self._outside_supervised_period(local, "public_holiday", holiday)

        if local.weekday() in self.schedule.automatic_days:
            reason = "weekend" if local.weekday() >= 5 else "automatic_day"
            return self._outside_supervised_period(local, reason)

        current_time = local.time().replace(tzinfo=None)
        if not self.available_from <= current_time < self.available_to:
            return self._outside_supervised_period(local, "night")

        return ScheduleDecision(
            mode="SUPERVISED",
            reason="administrator_availability_window",
            local_datetime=local,
        )

    def _outside_supervised_period(
        self,
        local: datetime,
        reason: str,
        holiday_name: str | None = None,
    ) -> ScheduleDecision:
        if not self.schedule.automatic_enabled:
            return ScheduleDecision(
                mode="SUPERVISED",
                reason=f"automatic_remediation_disabled:{reason}",
                local_datetime=local,
                holiday_name=holiday_name,
            )
        return ScheduleDecision(
            mode="AUTOMATIC",
            reason=reason,
            local_datetime=local,
            holiday_name=holiday_name,
        )
