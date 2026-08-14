from datetime import date, datetime
from zoneinfo import ZoneInfo

from pathlib import Path

from app.services.calendar_policy import CalendarPolicy


SCHEDULE = (
    Path(__file__).resolve().parents[1] / "config" / "automation_schedule.json"
)


def policy() -> CalendarPolicy:
    return CalendarPolicy.from_file(SCHEDULE)


def test_business_hours_require_human_approval():
    decision = policy().decide(
        datetime(2026, 8, 10, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa"))
    )
    assert decision.mode == "HUMAN_APPROVAL"


def test_night_allows_automatic_mode():
    decision = policy().decide(
        datetime(2026, 8, 10, 22, 0, tzinfo=ZoneInfo("Africa/Kinshasa"))
    )
    assert decision.mode == "AUTOMATIC"
    assert decision.reason == "night"


def test_weekend_allows_automatic_mode():
    decision = policy().decide(
        datetime(2026, 8, 15, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa"))
    )
    assert decision.mode == "AUTOMATIC"
    assert decision.reason == "weekend"


def test_public_holiday_allows_automatic_mode():
    decision = policy().decide(
        datetime(2026, 6, 30, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa"))
    )
    assert decision.mode == "AUTOMATIC"
    assert decision.reason == "public_holiday"
    assert decision.holiday_name == "Journee de l'Independance"


def test_sunday_holiday_is_observed_previous_day():
    assert "conge observe" in (policy().holiday_name(date(2022, 12, 31)) or "")
