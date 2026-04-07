import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods


def deserialize_data(request):
    """Safely deserialize request data using json instead of pickle."""
    try:
        data = json.loads(request.body)
        return JsonResponse({"status": "success", "data": data})
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)
