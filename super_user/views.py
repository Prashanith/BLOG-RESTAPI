from django.shortcuts import render,get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from super_user.models import Post
from super_user.serializers import PostSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


#authentication imports here
from rest_framework.generics import ListAPIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from idna.core import unicode
from pytz import unicode

class PostList(APIView):
    def get(self,request):
        Post_new=Post.objects.all().order_by('-date_posted')
        serializer=PostSerializer(Post_new,many=True)
        return Response(serializer.data)

    def post(self,request,format=None):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        post = self.get_object(pk)
        serializer = PostSerializer(post, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        post= self.get_object(pk)
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class Login(ListAPIView):
    authentication_class = (JSONWebTokenAuthentication,JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        content = {
            'user': unicode(request.user),  # `django.contrib.auth.User` instance.
            'auth': unicode(request.auth),  # None
        }
        return Response(content)
