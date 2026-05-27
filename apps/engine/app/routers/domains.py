import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.dependencies import get_current_user
from app.models.audit_log import AuditLog
from app.models.domain import Domain
from app.models.user import User
from app.schemas.domain import (
    CreateDomainRequest,
    CreateDomainResponse,
    DnsInstructions,
    DomainListResponse,
    DomainOut,
    DomainWithInstructions,
    DnsTxtInstructions,
    VerificationInstructions,
    VerifyDomainRequest,
    VerifyResponse,
    WellKnownFileInstructions,
    WellKnownInstructions,
)
from app.services.domain_verification import verify_dns_txt, verify_well_known_file

router = APIRouter(prefix="/domains", tags=["domains"])

AuthDep = Annotated[User, Depends(get_current_user)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


def _build_instructions(domain_name: str, token: str) -> VerificationInstructions:
    return VerificationInstructions(
        domain=domain_name,
        token=token,
        dns_txt=DnsTxtInstructions(
            record_name=f"_recon-verify.{domain_name}",
            record_value=token,
        ),
        well_known_file=WellKnownFileInstructions(
            url=f"https://{domain_name}/.well-known/recon-verification.txt",
            file_path=".well-known/recon-verification.txt",
            content=token,
        ),
    )


async def _get_owned_domain(
    domain_id: uuid.UUID,
    user: User,
    session: AsyncSession,
) -> Domain:
    domain = await session.get(Domain, domain_id)
    if domain is None or domain.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    return domain


async def _write_audit(
    session: AsyncSession,
    user_id: uuid.UUID,
    action: str,
    target: str,
    request: Request,
    metadata: dict | None = None,
) -> None:
    log = AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        ip_address=request.client.host if request.client else None,
        metadata_=metadata or {},
    )
    session.add(log)


# ── GET /domains ──────────────────────────────────────────────────────────────

@router.get("", response_model=DomainListResponse)
async def list_domains(
    current_user: AuthDep,
    session: SessionDep,
) -> DomainListResponse:
    rows = await session.scalars(
        select(Domain)
        .where(Domain.user_id == current_user.id)
        .order_by(Domain.created_at.desc())
    )
    return DomainListResponse(domains=[DomainOut.model_validate(d) for d in rows])


# ── POST /domains ─────────────────────────────────────────────────────────────

@router.post("", response_model=CreateDomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    body: CreateDomainRequest,
    request: Request,
    current_user: AuthDep,
    session: SessionDep,
) -> CreateDomainResponse:
    token = f"recon-verify-{uuid.uuid4()}"
    domain = Domain(
        user_id=current_user.id,
        domain=body.domain,
        verification_token=token,
    )
    session.add(domain)
    try:
        await session.flush()
        await _write_audit(
            session, current_user.id, "domain_registered", body.domain, request,
            metadata={"domain_id": str(domain.id)},
        )
        await session.commit()
        await session.refresh(domain)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already registered for your account",
        )

    return CreateDomainResponse(
        domain_id=domain.id,
        verification_token=token,
        dns_instructions=DnsInstructions(
            name=f"_recon-verify.{domain.domain}",
            value=token,
        ),
        well_known_instructions=WellKnownInstructions(
            url=f"https://{domain.domain}/.well-known/recon-verification.txt",
            value=token,
        ),
    )


# ── GET /domains/{id} ─────────────────────────────────────────────────────────

@router.get("/{domain_id}", response_model=DomainWithInstructions)
async def get_domain(
    domain_id: uuid.UUID,
    current_user: AuthDep,
    session: SessionDep,
) -> DomainWithInstructions:
    domain = await _get_owned_domain(domain_id, current_user, session)
    return DomainWithInstructions(
        domain=DomainOut.model_validate(domain),
        instructions=_build_instructions(domain.domain, domain.verification_token),
    )


# ── POST /domains/{id}/verify ─────────────────────────────────────────────────

@router.post("/{domain_id}/verify", response_model=VerifyResponse)
async def verify_domain(
    domain_id: uuid.UUID,
    body: VerifyDomainRequest,
    request: Request,
    current_user: AuthDep,
    session: SessionDep,
) -> VerifyResponse:
    domain = await _get_owned_domain(domain_id, current_user, session)

    if domain.verification_status == "verified":
        return VerifyResponse(
            domain=DomainOut.model_validate(domain),
            already_verified=True,
        )

    if body.method == "dns_txt":
        success = await verify_dns_txt(domain.domain, domain.verification_token)
    else:
        success = await verify_well_known_file(domain.domain, domain.verification_token)

    domain.verification_status = "verified" if success else "failed"
    domain.verification_method = body.method
    domain.verified_at = datetime.now(timezone.utc) if success else None

    audit_action = "domain_verified" if success else "domain_verification_failed"
    await _write_audit(
        session,
        current_user.id,
        audit_action,
        domain.domain,
        request,
        metadata={"domain_id": str(domain.id), "method": body.method},
    )
    await session.commit()
    await session.refresh(domain)

    if not success:
        return VerifyResponse(
            domain=DomainOut.model_validate(domain),
            error=(
                f"Verification failed via {body.method}. "
                "Ensure the record / file is published and try again."
            ),
            instructions=_build_instructions(domain.domain, domain.verification_token),
        )

    return VerifyResponse(domain=DomainOut.model_validate(domain))


# ── DELETE /domains/{id} ──────────────────────────────────────────────────────

@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: uuid.UUID,
    current_user: AuthDep,
    session: SessionDep,
) -> None:
    domain = await _get_owned_domain(domain_id, current_user, session)
    await session.delete(domain)
    await session.commit()
