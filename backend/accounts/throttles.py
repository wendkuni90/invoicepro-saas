from rest_framework.throttling import AnonRateThrottle
from audit.models import AuditLog
from django.utils import timezone

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'

    def allow_request(self, request, view):
        allowed = super().allow_request(request, view)
        if not allowed:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            user_agent = request.META.get("HTTP_USER_AGENT", "unknown")

            AuditLog.objects.create(
                user=None,  # pas encore d’utilisateur identifié
                action_type=AuditLog.ActionType.LOGIN_THROTTLED,
                entity_type="AUTH",
                entity_id=0,
                ip_address=ip,
                user_agent=user_agent,
                request_method=request.method,
                request_url=request.build_absolute_uri(),
                request_body=str(request.data),
                response_status=429,
                response_body="Too Many Requests",
                timestamp=timezone.now()
            )
        return allowed
