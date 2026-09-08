"""The only Q-to-P metadata channel. Error details must never enter P context."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, allow_inf_nan=False)


class Metadata(StrictModel):
    file_index: StrictInt = Field(ge=0, le=255)
    line_number: StrictInt = Field(ge=1, le=100_000)
    confidence: StrictFloat = Field(ge=0, le=1)
    actionable: StrictBool
    timezone: Literal["UTC", "Europe/London", "America/New_York"]


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


class TypeDirectedValidator:
    """Fixed schema, bounded input, no coercion, arbitrary strings, or extra fields."""

    @staticmethod
    def validate(payload: bytes) -> Metadata:
        if type(payload) is not bytes or len(payload) > 4096:
            raise ValueError("handoff rejected")
        try:
            data = json.loads(payload, object_pairs_hook=reject_duplicates)
            # StrictFloat permits integers in Pydantic; enforce exact wire type here.
            if type(data) is not dict or type(data.get("confidence")) is not float:
                raise ValueError()
            return Metadata.model_validate(data)
        except (ValueError, TypeError, RecursionError):
            raise ValueError("handoff rejected") from None
