from django.contrib import admin
from .models import GoogleMeetTranscript, ZoomTranscript, YouTubeTranscript, GoogleDriveWebhook

# Register your models here.
admin.site.register(GoogleMeetTranscript)
admin.site.register(ZoomTranscript)
admin.site.register(YouTubeTranscript)
admin.site.register(GoogleDriveWebhook)

