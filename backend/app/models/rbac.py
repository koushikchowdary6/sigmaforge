"""RBAC models -- mirrors DATABASE_SCHEMA.md §2.1-2.2 exactly.

Five roles ship in the seed migration: admin, detection_lead,
detection_engineer, analyst, researcher (PRD.md §11.1, API_SPECIFICATION.md
§14). Permissions are additive, declarative strings (e.g. "rule:approve")
checked via the require_permission() dependency -- never inferred from a
role-name string comparison scattered through route handlers
(API_SPECIFICATION.md §14 closing note).
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, SmallInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    permissions: Mapped[list[Permission]] = relationship(
        secondary="role_permissions", back_populates="roles"
    )


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    roles: Mapped[list[Role]] = relationship(secondary="role_permissions", back_populates="permissions")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(SmallInteger, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )
