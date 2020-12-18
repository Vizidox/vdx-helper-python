from datetime import datetime
from typing import Optional


def optional_datetime_from_string(dt: Optional[str]) -> Optional[datetime]:
    """
    Converts a datelike string to a datetime object.
    If the date is None, then returns None

    :param dt: The string to be converted
    :type dt: str, optional

    :return: A datetime in iso format
    :rtype: datetime, optional
    """
    return datetime.fromisoformat(dt) if dt is not None else None

