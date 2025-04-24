from django.db import models
from django.contrib.auth.models import User


class GoogleMeetTranscript(models.Model):
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('generated', 'Generated'),
        ('missing', 'Missing'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_id = models.CharField(max_length=255)  # Google Drive file ID
    video_url = models.URLField(blank=True, null=True)  # Web view link
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='missing')
    source_name = models.CharField(max_length=255, blank=True, null=True)  # Recording name
    created_time = models.DateTimeField(blank=True, null=True)  # File creation time
    file_size = models.CharField(max_length=50, blank=True, null=True)  # File size
    is_vector_stored = models.BooleanField(default=False)  # Indicates if transcript is in Pinecone
    processed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'file_id')
        indexes = [
            models.Index(fields=['user', 'file_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_time']),
        ]

    def __str__(self):
        return f"Google Meet Transcript for {self.source_name} ({self.user})"


class GoogleDriveWebhook(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    channel_id = models.CharField(max_length=255, unique=True)
    resource_id = models.CharField(max_length=255)
    channel_token = models.CharField(max_length=255)
    last_page_token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Webhook for {self.user} (Channel: {self.channel_id})"


class ZoomTranscript(models.Model):
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('generated', 'Generated'),
        ('missing', 'Missing'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_id = models.CharField(max_length=255)  # Zoom recording file ID
    meeting_id = models.CharField(max_length=255)  # Zoom meeting ID
    video_url = models.URLField(blank=True, null=True)  # Download URL for the recording
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='missing')
    source_name = models.CharField(max_length=255, blank=True, null=True)  # Meeting topic
    start_time = models.DateTimeField(blank=True, null=True)  # Meeting start time
    file_size = models.IntegerField(blank=True, null=True)  # File size in bytes
    is_vector_stored = models.BooleanField(default=False)  # Indicates if transcript is in Pinecone
    processed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'file_id')
        indexes = [
            models.Index(fields=['user', 'file_id']),
            models.Index(fields=['status']),
            models.Index(fields=['start_time']),
        ]

    def __str__(self):
        return f"Zoom Transcript for {self.source_name} ({self.user})"
    

class YouTubeTranscript(models.Model):
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('failed', 'Failed'),
        ('processing', 'Processing'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    video_id = models.CharField(max_length=255)  # YouTube video ID
    video_url = models.URLField()  # Video URL
    title = models.CharField(max_length=255, blank=True, null=True)  # Video title
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='processing')
    is_vector_stored = models.BooleanField(default=False)  # Indicates if transcript is in Pinecone
    channel_url = models.URLField(blank=True, null=True)  # Source channel URL (if from channel)
    processed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'video_id')
        indexes = [
            models.Index(fields=['user', 'video_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"YouTube Transcript for {self.title or self.video_id} ({self.user})"