from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework.response import Response
# from .models import User
from rest_framework.exceptions import AuthenticationFailed
import jwt
import datetime

from django.contrib.auth import get_user_model
User = get_user_model()


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
        

class LoginView(APIView):
    def post(self, request):
        email =  request.data['email']
        password =  request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User Not Found')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')


        payload={
            'id':user.id,
            'exp':datetime.datetime.utcnow()  + datetime.timedelta(minutes=10),
            'iat':datetime.datetime.utcnow()
        }

        # encoded_jwt = jwt.encode(payload, "secret", algorithm="HS256")
        # token = jwt.decode(encoded_jwt, "secret", algorithms=["HS256"])

        token = jwt.encode(payload, "secret", algorithm="HS256").decode('utf-8') 
        response =  Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt':token
        }

        return response     

class UserView(APIView):
    # credential = True for getting cookies by frontend
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Your are not authenticated')

        try:
            payload = jwt.decode(token, "secret", algorithm=["HS256"])
        except jwt.ExpiredSignatureError:       
            raise AuthenticationFailed('Your are not authenticated')

        user = User.objects.filter(id=payload['id']).first()  

        serializer = UserSerializer(user)  

        return Response(serializer.data)


class LogoutView(APIView):

    def post(self, request):
        response = Response()

        response.delete_cookie('jwt')
        response.data={
            'message':"Logout successful"
        }
        return response