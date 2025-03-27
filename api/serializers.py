from rest_framework.serializers import ModelSerializer
from .models import *

class GoogleTokenSerializer(ModelSerializer):
    class Meta:
        model = GoogleToken
        fields = '__all__'


class ZoomTokenSerializer(ModelSerializer):
    class Meta:
        model = ZoomToken
        fields = '__all__'

class TeamsTokenSerializer(ModelSerializer):
    class Meta:
        model = TeamsToken
        fields = '__all__'
    