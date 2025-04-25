from django.urls import path
from . import views

urlpatterns = [
    path('clerk/webhook/', views.ClerkWebhookView.as_view(), name='clerk-webhook'),
    path('auth/google/', views.GoogleAuthView.as_view(), name='google-auth'),
    path('auth/google/', views.google_auth_options, name='google-auth-options'),
    path('auth/google/callback/', views.GoogleCallbackView.as_view(), name='google-callback'),
    path('auth/google/delete/', views.GoogleDeleteView.as_view(), name='google-delete'),
    path('auth/zoom/', views.ZoomAuthView.as_view(), name='zoom-auth'),
    path('auth/zoom/callback/', views.ZoomCallbackView.as_view(), name='zoom-callback'),
    path('auth/zoom/delete/', views.ZoomDeleteView.as_view(), name='zoom-delete'),
    path('auth/teams/', views.TeamsAuthView.as_view(), name='teams-auth'),
    path('auth/teams/callback/', views.TeamsCallbackView.as_view(), name='teams-callback'),
    path('auth/teams/delete/', views.TeamsDeleteView.as_view(), name='teams-delete'),
]