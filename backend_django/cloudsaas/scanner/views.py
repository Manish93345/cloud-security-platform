from django.shortcuts import render
import os
import json
# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .services.scanner_engine import run_full_scan
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_view(request):
    report = run_full_scan()
    return Response(report)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def history_view(request):
    reports_dir = os.path.join(settings.BASE_DIR, "reports")

    history_data = []

    if os.path.exists(reports_dir):
        files = sorted(os.listdir(reports_dir), reverse=True)

        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(reports_dir, file), "r") as f:
                    data = json.load(f)
                    history_data.append({
                        "file": file,
                        "timestamp": data["timestamp"],
                        "summary": data["summary"]
                    })

    return Response(history_data)