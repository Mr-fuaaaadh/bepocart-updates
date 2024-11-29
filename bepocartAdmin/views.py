import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .serializers import *
from bepocartBackend.serializers import *
from django.db import IntegrityError, DatabaseError
from .models import *
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from django.http import HttpResponse
import pandas as pd
from django.utils import timezone
import openpyxl
import pytz
from django.db.models import Sum
from .utils import send_order_status_email
from .sms_utils import send_order_status_sms
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.contrib.auth.models import User

class AdminRegister(APIView):
    def post(self, request):
        try:
            serializer = AdminSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "User registration is successfully completed", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"message": "Invalid request", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"message": "An error occurred", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        




class AdminLogin(APIView):
    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')


            user = User.objects.filter(email=email).first()
            if user:
                if check_password(password, user.password):
                    try:
                        payload = {
                            'id': user.pk,
                            'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES),
                        }
                        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

                        if isinstance(token, bytes):
                            token = token.decode('utf-8')

                        

                        response = Response({"token": token}, status=status.HTTP_200_OK)
                        response.set_cookie('token', token, httponly=True, secure=True)
                        return response
                    except Exception as e:
                        return Response({"error": "Token generation failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response({"error": "Invalid or Incorrect Email Or Password"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



###################################################### Carousal ##################################################333####3

class CarousalAdd(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = CarousalSerializers(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Carousal added successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






class CarousalView(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            carousal = Carousal.objects.all()
            serializer = CarousalSerializers(carousal, many=True)
            return Response({"status": "success", "message": "Fetched all Carousals", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class CarousalUpdate(APIView):
    def get(self, request, pk):
        try:
            carousal = Carousal.objects.filter(pk=pk).first()
            if carousal is None:
                return Response({"status": "error", "message": "Banner image not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = CarousalSerializers(carousal)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                carousal = Carousal.objects.get(pk=pk)
            except Carousal.DoesNotExist:
                return Response({"message": "Carousal not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = CarousalSerializers(carousal, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Carousal updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CarousalDelete(APIView):
    def get(self, request, pk):
        try:
            carousal = Carousal.objects.filter(pk=pk).first()
            if carousal is None:
                return Response({"status": "error", "message": "Banner image not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = CarousalSerializers(carousal)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                carousal = Carousal.objects.get(pk=pk)
                carousal.delete()
                return Response({"status": "success", "message": "Banner image deleted successfully"}, status=status.HTTP_200_OK)
            except Carousal.DoesNotExist:
                return Response({"status": "error", "message": "Banner image not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




################################################################# OFFER BANNER ##########################################################################



class OfferBannerAdd(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            try:
                serializer = OfferBannerSerializers(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({"status": "success", "message": "Offer banner added successfully"}, status=status.HTTP_201_CREATED)
                else:
                    return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"status": "error", "message": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class OfferBannerView(APIView):
     def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            banner = OfferBanner.objects.all()
            serializer = OfferBannerSerializers(banner, many=True)
            return Response({"status": "success", "message": "Fetched all offer banner", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class OfferBannerDelete(APIView):
    def get(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            banner = OfferBanner.objects.filter(pk=pk).first()
            if banner is None:
                return Response({"status": "error", "message": "Offer Banner image not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = OfferBannerSerializers(banner)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                banner = OfferBanner.objects.get(pk=pk)
                banner.delete()
                return Response({"status": "success", "message": "Pffer Banner image deleted successfully"}, status=status.HTTP_200_OK)
            except OfferBanner.DoesNotExist:
                return Response({"status": "error", "message": "Offer Banner image not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class OfferBannerUpdate(APIView):
    def get(self, request, pk):
        try:
            banner = OfferBanner.objects.filter(pk=pk).first()
            if banner is None:
                return Response({"status": "error", "message": " Offer Banner image not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = OfferBannerSerializers(banner)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                banner = OfferBanner.objects.get(pk=pk)
            except OfferBanner.DoesNotExist:
                return Response({"message": "Offer banner  not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = OfferBannerSerializers(banner, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Offer Banner updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




    


            








##################################################################3  Category #############################################################################

class CategoryAdd(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError as e:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError as e:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            id = payload.get('id')
            if id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user = User.objects.filter(pk=id).first()
            if user is None:
                return Response({"error":"user not found"},status=status.HTTP_404_UNAUTHORIZED)

            return Response({"message": "User authenticated", "id": id}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request):
        try:
            serializer = CategorySerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Category added successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class Categories(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            categories = Category.objects.all().order_by('id')
            serializer = CategorySerializer(categories, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CategoryDelete(APIView):
    def get(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
            serializer = CategorySerializer(category, many=False)
            return Response({"message": "Category fetch successfully completed", "data": serializer.data}, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            category = Category.objects.get(pk=pk)
            category.delete()
            return Response({"message": "Category deleted successfully"}, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CategoryUpdate(APIView):

    def get(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
            serializer = CategorySerializer(category)
            return Response({"message": "Category fetch successful", "data": serializer.data}, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
            serializer = CategorySerializer(category, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Category.DoesNotExist:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




###############################################   SUBACTEGORY     ###################################################




class SubcategoryAdd(APIView):
    def post(self, request):        
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return None, Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return None, Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return None, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = SubcategoryModelSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Subcategory successfully created"}, status=status.HTTP_201_CREATED)
            return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class SubcategoryView(APIView):
    def get(self, request):
       
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return None, Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return None, Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return None, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            subcategories = Subcategory.objects.all()
            serializer = SubcategorySerializer(subcategories, many=True)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SubcategoryUpdate(APIView):
    def get(self, request,pk):
        try:
            subcategories = Subcategory.objects.get(pk=pk)
            serializer = SubCategoryUpdateSerializers(subcategories, many=False)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    def put(self,request,pk):
        try :
            token = request.headers.get('Authorization')
            if not token:
                return None, Response({"status": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return None, Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return None, Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return None, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            subcategory = Subcategory.objects.get(pk=pk)
            serializer = SubcategoryModelSerializer(subcategory, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Sub Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Category.DoesNotExist:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SubcategoryDelete(APIView):
    def get(self, request,pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return None, Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return None, Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return None, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            subcategories = Subcategory.objects.get(pk=pk)
            serializer = SubcategorySerializer(subcategories, many=False)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try :
            token = request.headers.get('Authorization')
            if not token:
                return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return None, Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except DecodeError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            except InvalidTokenError:
                return None, Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return None, Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return None, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            subcategory = Subcategory.objects.get(pk=pk)
            subcategory.delete()
            return Response({"status":"success","messege":"Subcatecory delete successfuly completed"},status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



#######################################  PRODUCT MANAGEMENT ########################################

class ProductAdd(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = ProductSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Product successfully created"}, status=status.HTTP_201_CREATED)
            return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class ProductView(APIView):
    def get(self, request):
        try :
            # token = request.headers.get('Authorization')
            # if token is None:
            #     return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            # try:
            #     payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # except ExpiredSignatureError:
            #     return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            # except (DecodeError, InvalidTokenError):
            #     return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # user_id = payload.get('id')
            # if user_id is None:
            #     return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # user = User.objects.filter(pk=user_id).first()
            # if user is None:
            #     return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            products = Product.objects.all().order_by('id')
            serializer = ProductSerializerView(products,many=True)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


            
        
    

    
class ProductUpdate(APIView):

    def get(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
        
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = ProductSerializer(product, many=False)
            return Response({"message": "Product details retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)
        
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = ProductSerializer(product, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Product updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class ProductDelete(APIView):
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            
            product.delete()
            return Response({"message": "Product deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        




################################################### ORDER MANAGEMENT #######################################################


class AllOrders(APIView):
    def get(self, request):
        try:
            # token = request.headers.get('Authorization')
            # if not token:
            #     return Response({"status": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            # try:
            #     payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            #     user_id = payload.get('id')
            #     if not user_id:
            #         return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            #     user = User.objects.filter(pk=user_id).first()
            #     if not user:
            #         return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

                order_products = Order.objects.all().order_by('-id')
                serializer = AdminOrderViewsSerializers(order_products, many=True)
                return Response({"message": "Orders fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)

            # except ExpiredSignatureError:
            #     return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            # except (DecodeError, InvalidTokenError):
            #     return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class OrderStatusUpdation(APIView):
    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('id')
                if not user_id:
                    return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

                user = User.objects.filter(pk=user_id).first()
                if not user:
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

                order = Order.objects.filter(pk=pk).first()
                if not order:
                    return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

                new_status = request.data.get('status')
                if not new_status:
                    return Response({"error": "No status provided"}, status=status.HTTP_400_BAD_REQUEST)

                if new_status == "Completed":
                    coin_value = CoinValue.objects.first()  
                    if coin_value:
                        user_orders = Order.objects.filter(customer=order.customer.pk, status="Completed").count()
                        if user_orders == 0:
                            coins_to_add = coin_value.first_payment_value
                        else:
                            order_total_amount = float(order.total_amount)
                            coins_to_add = (order_total_amount * coin_value.payment_value) / 100

                        Coin.objects.create(user=order.customer, amount=coins_to_add, source="Order reward")

                order.status = new_status
                order.save()

                send_order_status_email(order)

                return Response({"status": "Order status updated successfully"}, status=status.HTTP_200_OK)

            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

class AllOrderItems(APIView):
    def get(self, request,customer):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('id')
                if not user_id:
                    return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

                user = User.objects.filter(pk=user_id).first()
                if not user:
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

                # Fetch orders belonging to the authenticated user
                order = Order.objects.filter(pk=customer).first()
                order_products = OrderItem.objects.filter(order=customer)
                serializer = CustomerOrderItems(order_products, many=True)
                order_items_serializer = OrderInvoiceBillSerializer(order, many=False)
                return Response({"message": "Orders fetched successfully", "data": serializer.data,"order":order_items_serializer.data}, status=status.HTTP_200_OK)

            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            
        
            

class ProductImageCreateView(APIView):
    def post(self, request, pk):
        try:
            product = Product.objects.filter(pk=pk).first()
        except Product.DoesNotExist:
            return Response({'status': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError as db_error:
            return Response({'status': 'Database error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        data = request.data
        data['product'] = product.pk

        if product.type == "single":
            serializer = SingleProductSerilizers(data=data)
        else:
            serializer = VariantProductColorStock(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        



class ProductBasdMultipleImageView(APIView):
    def get(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            

            product = Product.objects.filter(pk=pk).first()
            if product is None:
                return Response({"message": "Product Not Found"}, status=status.HTTP_404_NOT_FOUND)
            
            if product.type == "single" :
                single_product = ProductColorStock.objects.filter(product=product.pk)
                serializer = SingleProductSerilizers(single_product, many=True)
            else :
                variant_product = ProductVariant.objects.filter(product=product.pk)
                serializer = VariantProductColorStock(variant_product, many=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class ProductMultipleImageDelete(APIView):
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            productType = request.data.get('productType')
            if productType not in ["single", "variant"]:
                return Response({"error": "Invalid product type"}, status=status.HTTP_400_BAD_REQUEST)

            if productType == "single":
                product_image = ProductColorStock.objects.filter(pk=pk).first()
                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)
                product_image.delete()
            else:
                product_image = ProductVariant.objects.filter(pk=pk).first()
                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)
                product_image.delete()

            return Response({"message": "Product Image deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductMultipleImageUpdate(APIView):
    def get(self, request, pk):
        try:
            productType = request.query_params.get('productType')

            if productType not in ["single", "variant"]:
                return Response({"error": "Invalid product type"}, status=status.HTTP_400_BAD_REQUEST)

            if productType == "single":
                product_image = ProductColorStock.objects.filter(pk=pk).first()
                

                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)
                
                serializer = SingleProductSerilizers(product_image)
                return Response({"message": "Product Image retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                
            else:
                product_image = ProductVariant.objects.filter(pk=pk).first()

                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)
                
                serializer = VariantProductColorStock(product_image)
                return Response({"message": "Product Image retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            productType = request.data.get('productType')
            if productType not in ["single", "variant"]:
                return Response({"error": "Invalid product type"}, status=status.HTTP_400_BAD_REQUEST)

            if productType == "single":
                product_image = ProductColorStock.objects.filter(pk=pk).first()
                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)

                serializer = SingleProductSerilizers(product_image, data=request.data, partial=True)
            else:
                product_image = ProductVariant.objects.filter(pk=pk).first()
                if product_image is None:
                    return Response({"message": "Product Image not found"}, status=status.HTTP_404_NOT_FOUND)

                serializer = VariantProductColorStock(product_image, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Product Image updated successfully"}, status=status.HTTP_200_OK)

            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        
class VarientProductAdding(APIView):
    def post(self, request, pk):
        try:
            productType = request.data.get('productType')
            if productType == "variant":
                product_image = ProductVariant.objects.filter(pk=pk).first()
                if product_image is None:
                    return Response({"error": "Product color not found"}, status=status.HTTP_404_NOT_FOUND)
                
                data = request.data
                data['product_variant'] = product_image.pk  

                serializer = ProductVarientSizeStockSerializers(data=data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as db_error:
            return Response({'status': 'Database error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class VarientProductDataView(APIView):
    def get(self, request, pk):
        try:
            product_image = ProductVarientSizeStock.objects.filter(product_variant=pk)
            if product_image is None:           
                return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = ProductImageVarientModelSerilizers(product_image,many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except DatabaseError as db_error:
            return Response({'status': 'Database error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VarientProductSizeDelete(APIView):
    def delete(self,request,pk):
        try:
            product_image = ProductVarientSizeStock.objects.filter(pk=pk).first()
            if product_image is None:
                return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            product_image.delete()
            return Response({"message": "Product deleted successfully"}, status=status.HTTP_200_OK)
        except DatabaseError as db_error:
            return Response({'status': 'Database error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VarientProductDataupdate(APIView):
    def put(self, request, pk):
        try:
            product_image = ProductVarientSizeStock.objects.filter(pk=pk).first()
            if product_image is None:
                return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serilizer = ProductVarientSizeStockSerializers(product_image, request.data, partial=True)
            if serilizer.is_valid():
                serilizer.save()
                return Response(serilizer.data, status=status.HTTP_200_OK)
            return Response(serilizer.errors, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as db_error:
            return Response({'status': 'Database error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
            
        

        



class AdminCouponCreation(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            data = request.data.copy()  # Make a copy of request data
            data['discount_product'] = list(map(int,data.get('discount_product', [])))
            data['discount_category'] = list(map(int, data.get('discount_category', [])))

            serializer = AdminCoupenSerializers(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Coupon created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as ve:
            return Response({"error": "Validation Error", "details": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as ie:
            return Response({"error": "Integrity Error", "details": str(ie)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as de:
            return Response({"error": "Database Error", "details": str(de)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": "Server Error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminCoupensView(APIView):
    def get(self, request):
        try:
            # token = request.headers.get('Authorization')
            # if token is None:
            #     return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            # try:
            #     payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # except ExpiredSignatureError:
            #     return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            # except (DecodeError, InvalidTokenError):
            #     return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # user_id = payload.get('id')
            # if user_id is None:
            #     return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # user = User.objects.filter(pk=user_id).first()
            # if user is None:
            #     return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            coupons = Coupon.objects.all()
            
            serializer = AdminallCoupenSerializers(coupons, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Server Error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class AdminCouponDelete(APIView):
    def delete(self,request,pk):
        try :
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            coupons = Coupon.objects.filter(pk=pk).first()
            if coupons is None:
                return Response({"error": "Coupon not found"}, status=status.HTTP_404_NOT_FOUND)
            coupons.delete()
            return Response({"status": "success", "message": "Coupon deleted successfully"}, status=status.HTTP_200_OK)  


        except Exception as e:
            return Response({"error": "Server Error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AdminCouponUpdate(APIView):
    
    def get(self, request, pk):
        try:
            coupon = Coupon.objects.filter(pk=pk).first()
            if not coupon:
                return Response({"error": f"Coupon with id {pk} does not exist"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = AdminCoupenSerializers(coupon)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"error": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                coupon = Coupon.objects.get(pk=pk)
            except Coupon.DoesNotExist:
                return Response({"error": f"Coupon with id {pk} does not exist"}, status=status.HTTP_404_NOT_FOUND)

            serializer = AdminCoupenSerializers(coupon, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class AdminBlogCreate(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = BlogSerializers(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class AdminBlogView(APIView):
    def get(self, request,):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            blog = Blog.objects.all()
            serializer = BlogSerializers(blog, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AdminBlogDelete(APIView):
    def get(self, request, pk):
        try:
            blog = Blog.objects.filter(pk=pk).first()
            if blog is None:
                return Response({'error': "Blog not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = BlogSerializers(blog)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            blog = Blog.objects.filter(pk=pk).first()
            if blog is None:
                return Response({"error": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)
            
            blog.delete()
            return Response({"success": "Blog deleted successfully"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AdminBlogUpdate(APIView):
    def get(self, request, pk):
        try:
            blog = Blog.objects.filter(pk=pk).first()
            if blog is None:
                return Response({'error': "Blog not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = BlogSerializers(blog)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            blog = Blog.objects.filter(pk=pk).first()
            if blog is None:
                return Response({"error": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = BlogSerializers(blog, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Blog update successfully completed", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid data", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class AdminCustomerView(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            customers = Customer.objects.all()
            serializer = AdminCustomerViewSerilizers(customers, many=True)  
            return Response({"message": "Customers data fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CustomersDelete(APIView):
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            

            customer = Customer.objects.filter(pk=pk).first()
            if customer is None:
                return Response({"error": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)
            customer.delete()
            return Response({"message": "Customer deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CustomerUpdate(APIView):
    def get(self,request,pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            

            customer = Customer.objects.filter(pk=pk).first()
            if customer is None:
                return Response({"error": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = AdminCustomerViewSerilizers(customer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self, request, pk):
        try:

            token = request.headers.get('Authorization')
            if token is None:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (DecodeError, InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if user_id is None:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if user is None:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            customer = Customer.objects.filter(pk=pk).first()
            if customer is None:
                return Response({"error": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = AdminCustomerViewSerilizers(customer, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

        

class ExportOrdersToExcel(APIView):
    def post(self, request, *args, **kwargs):
        # Get start_date and end_date from request data
        start_date_str = request.data.get('startDate')
        end_date_str = request.data.get('endDate')
        status_filter = request.data.get('status')  # status filter can be null

        if not start_date_str or not end_date_str:
            return Response({"error": "Please provide both startDate and endDate in YYYY-MM-DD format"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        # Filter orders by date range and status (if status is provided)
        if status_filter:
            orders = Order.objects.filter(created_at__range=[start_date, end_date], status=status_filter)
        else:
            orders = Order.objects.filter(created_at__range=[start_date, end_date])

        if not orders:
            return Response({"error": "No orders found for the given date range."}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminOrderViewsSerializers(orders, many=True)

        # Prepare data for DataFrame
        data = []
        for order in serializer.data:
            for item in order.get('order_items', []):
                data.append({
                    "Order ID": order.get('order_id'),
                    "Name": order.get('customerName'),  # Fixed typo from 'ame'
                    "Phone": order.get('phone'),
                    "City": order.get('city'),
                    "State": order.get('state'),
                    "Pincode": order.get('pincode'),
                    "Coupon Code ": item.get('couponName'),
                    "Total Amount": order.get('total_amount'),
                    "Created At": order.get('created_at'),
                    "Payment Method": order.get('payment_method'),
                    "Payment ID": order.get('payment_id'),
                    "Status": order.get('status'),
                    "Product": f"{item.get('name')} - {item.get('color')} - {item.get('size')}",
                    "Quantity": item.get('quantity'),
                    "Price": item.get('price'),
                })

        df = pd.DataFrame(data)

        # Create an HTTP response with the Excel file
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename="orders_{start_date_str}_to_{end_date_str}.xlsx"'

        with pd.ExcelWriter(response, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Orders')

        return response
    
            
class OrderInvoiceBillCreating(APIView):
    def get(self, request, order_id):
        try:
            order = Order.objects.get(order_id=order_id)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            order_items = OrderItem.objects.filter(order=order)
            if not order_items.exists():
                return Response({"error": "Order Items not found"}, status=status.HTTP_404_NOT_FOUND)

            order_serializer = OrderInvoiceBillSerializer(order)
            order_items_serializer = CustomerOrderItems(order_items, many=True)

            return Response({
                "message": "Order data fetched successfully",
                "data": order_serializer.data,
                "order_items": order_items_serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


            

class AdminCoinCreating(APIView):
    def post(self, request):
        serializer = CoinModelSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Coin created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class AdminCoinFetching(APIView):
    def get(self, request):
        try:
            coins = CoinValue.objects.all()
            serializer = CoinModelSerializer(coins, many=True)
            return Response({"message": "Coins fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": "Error fetching coins", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AdminCoinDelete(APIView):
    def delete(self, request, pk):
        try:
            coin = CoinValue.objects.get(id=pk)
            coin.delete()
            return Response({"message": "Coin deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": "Error deleting coin", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    

class AdminCoinUpdate(APIView):
    def put(self, request, pk):
        try:
            coin = CoinValue.objects.get(pk=pk)
            serializer = CoinModelSerializer(coin, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Coin updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except CoinValue.DoesNotExist:
            return Response({"message": "Coin not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": "Error updating coin", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        



class AdminCustomerCOinDAtaView(APIView):
    def get(self, request, pk):
        try:
            # Retrieve token from request headers
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # Extract user ID from token payload
            user_id = payload.get('id')
            if not user_id:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user (admin) based on user ID
            user = User.objects.filter(pk=user_id).first()
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Fetch customer based on provided pk
            customer = Customer.objects.filter(pk=pk).first()
            if not customer:
                return Response({"message": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Fetch coin data associated with the customer
            coin_data = Coin.objects.filter(user=customer.pk)
            serializer = AdminCustomerCoinSerializer(coin_data, many=True)
            
            return Response({"message": "Customer data fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class AdminViewAllProductReviw(APIView):
    def get(self, request):
        try:
            # Retrieve token from request headers
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # Extract user ID from token payload
            user_id = payload.get('id')
            if not user_id:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user (admin) based on user ID
            user = User.objects.filter(pk=user_id).first()
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            

            product_reviews = Review.objects.all().order_by("id")
            serializer = AdminProductReviewSerializer(product_reviews, many=True)
            return Response({"data":serializer.data,"message":"Review fetching successfully completed"})

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class UpdateReviewStatus(APIView):
    def put(self, request, pk):
        try:
            # Retrieve token from request headers
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # Extract user ID from token payload
            user_id = payload.get('id')
            if not user_id:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user (admin) based on user ID
            user = User.objects.filter(pk=user_id).first()
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Fetch the review based on review ID
            review = Review.objects.filter(pk=pk).first()
            if not review:
                return Response({"error": "Review not found"}, status=status.HTTP_404_NOT_FOUND)

            # Update the review status to "Approved"
            review.status = "Approved"
            review.save()

            return Response({"message": "Review status updated to Approved"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request, pk):
        try:
            review = Review.objects.filter(pk=pk).first()
            if not review:
                return Response({"error": "Review not found"}, status=status.HTTP_404_NOT_FOUND)
            
            review.delete()
            return Response({"message": "Review deletd successfuly"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
            
           


# class AdminDeleteReview(APIView):
#     def delete(self, request, pk):
#         try:
#             token = request.headers.get()



from django.db import transaction

class AdminOfferCreating(APIView):
    def post(self, request):
        try:
            # Retrieve token from request headers
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"status": "error", "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"status": "error", "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # Extract user ID from token payload
            user_id = payload.get('id')
            if not user_id:
                return Response({"status": "error", "message": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user (admin) based on user ID
            user = User.objects.filter(pk=user_id).first()
            if not user:
                return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Serialize and save the offer within a transaction
            serializer = OfferProductModelSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Offer created successfully"}, status=status.HTTP_201_CREATED)
            return Response({"status": "error", "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminSheduledOfferDeleting(APIView):
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"status": "error", "message": "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"status": "error", "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"status": "error", "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = payload.get('id')
            if not user_id:
                return Response({"status": "error", "message": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            user = User.objects.filter(pk=user_id).first()
            if not user:
                return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            offer = OfferSchedule.objects.filter(pk=pk).first()
            if not offer:
                return Response({"status": "error", "message": "Offer not found"}, status=status.HTTP_404_NOT_FOUND)
            offer.delete()
            return Response({"status": "success", "message": "Offer deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": "Internal server error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            


class OfferScheduling(APIView):
    def put(self, request):
        try:
            now = timezone.now()
            offer_data = OfferSchedule.objects.filter(offer_active=False).all()
            offers_updated = False

            # Get the current timezone
            local_tz = timezone.get_current_timezone()

            for offer in offer_data:
                # Convert UTC time to local time
                local_start_date = offer.start_date.astimezone(local_tz)
                local_end_date = offer.end_date.astimezone(local_tz)

                if local_start_date <= now <= local_end_date:
                    offer.offer_active = True
                    offer.save()
                    offers_updated = True

            if offers_updated:
                return Response({"status": "success", "message": "Offers scheduled successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"status": "error", "message": "No offers to schedule"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"status": "error", "message": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AllOffers(APIView):
    def get(self, request):
        try:
            offer= OfferSchedule.objects.all()
            serializer = OfferModelSerilizers(offer, many=True)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"status": "error", "message": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class  toggle_offer_active(APIView):
    def put(self,request,pk):
        try :
            offer = OfferSchedule.objects.filter(pk=pk).first()
            offer.offer_active = not offer.offer_active
            offer.save()
            return Response({'offer_active': offer.offer_active}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"status": "error", "message": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TotalSaledProductsView(APIView):
   
    def get(self, request):
        try:
            # Aggregate total sold quantities for each product
            sold_products_data = (
                OrderItem.objects
                .values('product')  # Get product IDs
                .annotate(total_sold=Sum('quantity'))
                .order_by('-total_sold')
            )
            
            if not sold_products_data:
                return Response({"message": "No products have been sold."}, status=status.HTTP_404_NOT_FOUND)

            # Fetch detailed product information for each product ID
            product_ids = [data['product'] for data in sold_products_data]
            products = Product.objects.filter(id__in=product_ids).prefetch_related('category')

            # Map total sold quantities to product instances
            product_data = []
            for product in products:
                # Find corresponding sold data
                sold_data = next(item for item in sold_products_data if item['product'] == product.id)
                serialized_product = ProductViewSerializer(product).data
                serialized_product['total_sold'] = sold_data['total_sold']
                product_data.append(serialized_product)

            # Return the serialized data
            return Response({"total_saled_products": product_data}, status=status.HTTP_200_OK)

        except DatabaseError as db_error:
            return Response({
                "error": "Database error occurred. Please try again later.",
                "details": str(db_error)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except Exception as e:
            return Response({
                "error": "An unexpected error occurred.",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




