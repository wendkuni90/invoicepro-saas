from django.utils import timezone
from .models import UserSession

class UpdateLastActivityMiddleware:
    """
    Met à jour last_activity si le cookie 'session_id' est présent.
    À ajouter APRES l'auth middleware dans MIDDLEWARE.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        sid = request.COOKIES.get("session_id")
        if sid:
            try:
                UserSession.objects.filter(session_id=sid, revoked=False).update(last_activity=timezone.now())
            except Exception:
                pass
        return self.get_response(request)
