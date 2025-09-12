from audit.models import AuditLog
from django.utils import timezone

def create_audit_log(
    user,
    action_type,
    request,
    response_status,
    response_body=None,
    entity_type="AUTH",
    entity_id=0,
    changes=None
):
    """
    Crée un enregistrement dans AuditLog
    """
    AuditLog.objects.create(
        user=user if user and user.is_authenticated else None,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        ip_address=request.META.get("REMOTE_ADDR", "unknown"),
        user_agent=request.META.get("HTTP_USER_AGENT", "unknown"),
        session_id=getattr(request, "session", None).session_key if hasattr(request, "session") else None,
        request_method=request.method,
        request_url=request.build_absolute_uri(),
        request_headers={k: v for k, v in request.headers.items()},
        request_body=str(request.data),
        response_status=response_status,
        response_body=str(response_body),
        response_headers={},  # facultatif : à remplir si nécessaire
        related_model=None,
        related_object_id=None,
        changes=changes,
        timestamp=timezone.now()
    )
