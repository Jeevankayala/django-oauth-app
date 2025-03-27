from django.urls import path
from . import views

urlpatterns = [
    path('auth/google/', views.GoogleAuthView.as_view(), name='google_auth'),
    path('auth/google/callback/', views.GoogleCallbackView.as_view(), name='google_callback'),
    path('calendar/events/', views.GetCalendarEventsView.as_view(), name='calendar_events'),
    path('auth/google/token/', views.GetGoogleTokenView.as_view(), name='get_google_token'),
    # Zoom endpoints
    path('auth/zoom/', views.ZoomAuthView.as_view(), name='zoom_auth'),
    path('auth/zoom/callback/', views.ZoomCallbackView.as_view(), name='zoom_callback'),
    # Teams endpoints
    path('auth/teams/', views.TeamsAuthView.as_view(), name='teams_auth'),
    path('auth/teams/callback/', views.TeamsCallbackView.as_view(), name='teams_callback'),
    path('teams/calendar/', views.GetTeamsCalendarEventsView.as_view(), name='teams_calendar'),
]