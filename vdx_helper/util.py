from datetime import datetime
from typing import Optional, List
from uuid import UUID


def datetime_from_string(dt: str) -> datetime:
    """
    Converts a datelike string to a datetime object.

    :param dt: The string to be converted
    :type dt: str

    :return: A datetime in iso format
    :rtype: datetime
    """
    return datetime.fromisoformat(dt)


def optional_datetime_from_string(dt: Optional[str]) -> Optional[datetime]:
    """
    Converts a datelike string to a datetime object.
    If the date is None, then returns None

    :param dt: The string to be converted
    :type dt: str, optional

    :return: A datetime in iso format
    :rtype: datetime, optional
    """
    return datetime_from_string(dt) if dt is not None else None


def uuid_to_string(uuid_: UUID) -> str:
    """
    Converts a UUID value to a string

    :param uuid_: A valid UUID value
    :type uuid_: UUID

    :return: The UUID value converted to string
    :rtype: str
    """
    return str(uuid_)


def optional_uuid_to_string(uuid_: Optional[UUID]) -> Optional[str]:
    """
    Converts a UUID value to a string, which can be None. If that is the case, then None is returned.

    :param uuid_: A valid UUID value
    :type uuid_: UUID, optional

    :return: The UUID value converted to string
    :rtype: str, optional
    """
    return uuid_to_string(uuid_) if uuid_ is not None else None


def optional_uuids_to_string(uids: Optional[List[UUID]]) -> Optional[List[str]]:
    """
    Convert a list of valid UUIDs to string, if the list is given. If not, then return None

    :param uids: List of UUIDs
    :type uids: List[UUID], optional

    :return: List of the UUID in string format
    :rtype: List[str], optional
    """
    return [uuid_to_string(uid) for uid in uids] if uids is not None else None


def uuids_to_string(uids: List[UUID]) -> List[str]:
    """
    Convert a list of valid UUIDs to string.
    :param uids: List of UUIDs
    :type uids: List[UUID]

    :return: List of the UUID in string format
    :rtype: List[str]
    """
    return [uuid_to_string(uid) for uid in uids]
