from uuid import UUID

from pydantic import BaseModel, Field


class RegistrationOtpResponse(BaseModel):
    verification_id: UUID
    expires_in_seconds: int
    resend_after_seconds: int
    message: str


class RegistrationOtpVerify(BaseModel):
    verification_id: UUID
    otp: str = Field(pattern=r"^\d{6}$")
