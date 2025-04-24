from django.urls import path
from . import views

urlpatterns = [
    path('google-drive-webhook/', views.google_drive_webhook, name='google_drive_webhook'),
    path('google/', views.GoogleRecordingsView.as_view(), name='google-recordings'),
    path('zoom/', views.ZoomRecordingsView.as_view(), name='zoom-recordings'),
    path('teams/', views.TeamsRecordingsView.as_view(), name='teams-recordings'),
    # path('youtube/', views.YouTubeTranscriptsView.as_view(), name='youtube-recordings'),
    path('youtube-transcripts/', views.YouTubeTranscriptsView.as_view(), name='youtube_transcripts'),
    path('youtube-transcripts/delete/', views.YouTubeTranscriptDeleteView.as_view(), name='youtube_transcript_delete'),
    path('scrape-website/', views.WebsiteScraperView.as_view(), name='scrape_website'),
    path('api/task-status/<str:task_id>/', views.TaskStatusView.as_view()),
]