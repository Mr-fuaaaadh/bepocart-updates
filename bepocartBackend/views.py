import razorpay
import logging
import jwt
import hashlib
from django.shortcuts import render
from django.db.models import Avg,Sum, Count
import requests
from django.shortcuts import get_object_or_404
from django.db.models import Sum
import random
from datetime import datetime
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from rest_framework import generics
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from rest_framework import status
from django.conf import settings
from bepocartBackend.serializers import *
from bepocartAdmin.serializers import *
from bepocartBackend.models import *
from bepocartAdmin.models import *
from datetime import datetime, timedelta
from django.db.models import Count
from django.db.models import Q
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth.hashers import check_password, make_password
from django.template.loader import render_to_string
from django.db import transaction
from decimal import Decimal
from requests.exceptions import RequestException
from django.core.exceptions import ValidationError
from rest_framework.exceptions import ValidationError as DRFValidationError
from .utils import *
from django.core.cache import cache

logger = logging.getLogger(__name__)

class CustomerRegistration(APIView):
    def post(self, request):
        try:
            serializer = CustomerRegisterSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "status": "success",
                    "message": "Registration successfully completed",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "status": "error",
                    "message": "Registration failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

logger = logging.getLogger(__name__)

class GoogleLoginAPIView(APIView):
    def post(self, request):
        try:
            user_email = request.data.get('email')
            user_first_name = request.data.get('name')
            user_phone = request.data.get('phone', None)  # Handle if phone is provided

            # Validate input fields
            if not user_email or not user_first_name:
                raise DRFValidationError('Both email and name are required.')

            # Basic email format validation
            if '@' not in user_email:
                raise DRFValidationError('Invalid email format.')

            # Update or create customer
            customer, created = Customer.objects.update_or_create(
                email=user_email,
                defaults={'first_name': user_first_name, 'phone': user_phone}
            )

            message = 'Customer created successfully' if created else 'Customer updated successfully'

            # Generate JWT token
            payload = {
                'id': customer.pk,
                'email': customer.email,
                'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

            return Response({
                'message': message,
                'customer_id': customer.pk,
                'token': token,
                'exp': payload['exp'],
                'iat': datetime.utcnow()
            }, status=status.HTTP_200_OK)

        except DRFValidationError as e:
            logger.error(f"Validation Error: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except DjangoValidationError as e:
            logger.error(f"Django Validation Error: {e.message_dict}", exc_info=True)
            return Response({'error': e.message_dict}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Unexpected Error: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CustomerLogin(APIView):
    def post(self, request):
        serializer = CustomerLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "status": "error",
                "message": "Invalid data",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email_or_phone = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
        
        # Retrieve customer based on email or phone
        customer = Customer.objects.filter(
            Q(email=email_or_phone) | Q(phone=email_or_phone)
        ).first()
        
        if not customer or not customer.check_password(password):
            return Response({
                "status": "error",
                "message": "Invalid email or password"
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Generate JWT token
        expiration_time = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
        user_token = {
            'id': customer.pk,
            'email': customer.email,
            'exp': expiration_time,
            'iat': datetime.utcnow()
        }
        token = jwt.encode(user_token, settings.SECRET_KEY, algorithm='HS256')
        
        # Set JWT token in cookies
        response = Response({
            "status": "success",
            "message": "Login successful",
            "token": token
        }, status=status.HTTP_200_OK)
        response.set_cookie(
            key='token',
            value=token,
            httponly=True,
            samesite='Lax',
            secure=settings.SECURE_COOKIE
        )
        
        # Add coins to user account
        coin_value = CoinValue.objects.first()
        if coin_value:
            coins_to_add = coin_value.login_value
            Coin.objects.create(user=customer, amount=coins_to_add, source="Login")
        
        return response


################################################  HOME    #############################################


class CategoryListView(APIView):
    def get(self, request):
        try:
            queryset = Category.objects.all().order_by('id')
            serializer = CategoryModelSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
class CategoryView(APIView):
    def get(self, request):
        try:
            categories = Category.objects.all()  
            serializer = CategoryModelSerializer(categories, many=True) 
            return Response({
                "status": "success",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AllSubCategoryView(APIView):
    def get(self, request):
        try:
            subcategories = Subcategory.objects.all()
            serializer = SubcategorySerializer(subcategories, many=True)
            return Response({
                "status": "success",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SubcategoryView(APIView):
    def get(self, request,pk):
        try :
            subcategories = Subcategory.objects.filter(category=pk)
            serializer = SubcatecorySerializer(subcategories, many=True)
            return Response({
                "status": "success",
                "data": serializer.data
            },status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CustomerProductView(APIView):
    def get(self, request):
        try:
            products = Product.objects.all().order_by('-id')
            serializer = ProductViewSerializer(products, many=True)
            return Response({"products": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CustomerCarousalView(APIView):
    def get(self, request):
        try:
            banner = Carousal.objects.all()
            serializer = CarousalSerializers(banner, many=True)
            return Response({"banner": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class CustomerOfferBannerView(APIView):
    def get(self, request):
        try:
            banner = OfferBanner.objects.all()
            serializer = OfferBannerSerializers(banner, many=True)
            return Response({"banner": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        

class SubcategoryBasedProducts(APIView):
    def get(self, request, slug):
        try:
            subcategory = get_object_or_404(Subcategory,slug=slug)
        except Subcategory.DoesNotExist:
            return Response({"message": "Subcategory not found"}, status=status.HTTP_404_NOT_FOUND)

        products = Product.objects.filter(category=subcategory)
        serializer = SubcatecoryBasedProductView(products, many=True)
        return Response({"products": serializer.data}, status=status.HTTP_200_OK)




from django.db import IntegrityError

class CustomerAddProductInWishlist(APIView):
    def post(self, request, pk):
        token = request.headers.get('Authorization')
        if not token:
            return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token userToken"}, status=status.HTTP_401_UNAUTHORIZED)

            # Check if the user exists
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Check if the product exists
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

            # Check if the product is already in the user's wishlist
            if Wishlist.objects.filter(user=user, product=product).exists():
                return Response({"message": "Product already exists in the wishlist"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Update or create the recently viewed product entry
            RecentlyViewedProduct.objects.update_or_create(
                user=user,
                product=product,
                defaults={'viewed_at': timezone.now()}
            )

            # Add the product to the wishlist
            wishlist_data = {'user': user.pk, 'product': product.pk}
            wishlist_serializer = WishlistSerializers(data=wishlist_data)
            if wishlist_serializer.is_valid():
                wishlist_serializer.save()
                return Response({"message": "Product added to wishlist successfully"}, status=status.HTTP_201_CREATED)
            return Response({"message": "Unable to add product to wishlist", "errors": wishlist_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)
        except IntegrityError:
            return Response({"message": "Product already exists in the wishlist"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CustomerWishlist(APIView):
    def get(self, request):
        token = request.headers.get('Authorization')
        if not token:
            return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token userToken"}, status=status.HTTP_401_UNAUTHORIZED)

            # Check if the user exists
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Retrieve the user's wishlist
            wishlist = Wishlist.objects.filter(user=user)
            serializer = WishlistSerializersView(wishlist, many=True)

            return Response({
                "status": "success",
                "message": "User wishlist products",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class CustomerProductDeleteInWishlist(APIView):
    def delete(self, request, pk):
        try:
            product = Wishlist.objects.filter(pk=pk).first()
            if product is None:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            product.delete()
            return Response({"message": "Product deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CustomerProductInCart(APIView):
    def post(self, request, pk):
        try:
            # Validate Authorization token
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve user and product
            user = get_object_or_404(Customer, pk=user_id)
            product = get_object_or_404(Product, pk=pk)

            # Manage Recently Viewed Products
            recently_viewed, created = RecentlyViewedProduct.objects.get_or_create(user=user, product=product)
            if not created:
                recently_viewed.viewed_at = timezone.now()
                recently_viewed.save()

            # Retrieve product color and size
            product_color = request.data.get('color')
            product_size = request.data.get('size')
            product_qty =  request.data.get('quantity',1)


            # Check if the product is already in the user's Cart
            # First, check for single product without variants
            if product.type == "single":
                if Cart.objects.filter(customer=user, product=product, color=product_color, size=None).exists():
                    return Response({"message": "Product already exists in the cart as a single item"}, status=status.HTTP_400_BAD_REQUEST)
                cart_data = {'customer': user.pk, 'product': product.pk, 'color': product_color, 'quantity':product_qty, 'size': None}

            # Then, check for the product with variants (color, size)
            else:
                if Cart.objects.filter(customer=user, product=product, color=product_color, size=product_size).exists():
                    return Response({"message": "Product already exists in the cart with the same variant"}, status=status.HTTP_400_BAD_REQUEST)
                cart_data = {'customer': user.pk, 'product': product.pk, 'color': product_color,'quantity':product_qty, 'size': product_size}

            # Serialize and save cart data
            serializer = CartModelSerializers(data=cart_data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Product added to cart successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "Unable to add product to cart", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response({"message": "Product already exists in the cart"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None


class CustomerCartProducts(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                userToken = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": "Invalid token: " + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = userToken.get('id')

            if not user_id:
                return Response({"message": "Invalid token userToken"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                
            cart = Cart.objects.filter(customer=user)
            if not cart:
                return Response({"message": "Cart is empty"}, status=status.HTTP_404_NOT_FOUND)
        
            

            offer = OfferSchedule.objects.filter(offer_active=True).first()
            if offer:
                offer_approved_products = list(offer.offer_products.values_list('pk', flat=True))
                offer_approved_category = list(offer.offer_category.values_list('pk', flat=True))

                # Discount approved products and categories
                discount_approved_products = list(offer.discount_approved_products.values_list('pk', flat=True))
                discount_approved_category = list(offer.discount_approved_category.values_list('pk', flat=True))

                # Fetch all products that belong to offer-approved category products
                approved_category_products = Product.objects.filter(category__pk__in=offer_approved_category)
                approved_category_product_pks = list(approved_category_products.values_list('pk', flat=True))

                # Fetch all products that belong to discount-approved category products
                approved_discount_category_products = Product.objects.filter(category__pk__in=discount_approved_category)
                approved_discount_category_product_pks = list(approved_discount_category_products.values_list('pk', flat=True))

                products_in_cart = [item.product.pk for item in cart]


                # Find products in cart that are either approved by the offer or belong to approved categories
                matched_product_pks = [product_pk for product_pk in products_in_cart 
                       if product_pk in offer_approved_products or product_pk in approved_category_product_pks]
                
                # Find products in cart that are either approved for discount or  categories
                allowed_discount_products = [product_pk for product_pk in products_in_cart 
                                            if product_pk in discount_approved_products or product_pk in approved_discount_category_product_pks]
                            
                if offer.is_active:
                    try:
                        # Fetch the first active OfferSchedule object
                        offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()
                        if offer_schedule.offer_type == "BUY" and offer_schedule.method == "FREE":

                            # Retrieve the buy and get values
                            buy = offer_schedule.get_option
                            get = offer_schedule.get_value

                            # Combine matched product pks with allowed discount products
                            if matched_product_pks:
                                combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                            else:
                                combined_product_pks = set(approved_category_product_pks)

                            # Get user cart items
                            user_cart = Cart.objects.filter(customer=user)

                            offer_products = []
                            discount_allowed_products = []
                            
                            total_combined_quantity = 0
                            total_free_quantity = 0
                            total_sale_price = 0
                            sub_total_sale_price = 0

                            for item in user_cart:
                                if item.product.pk in combined_product_pks:
                                    total_combined_quantity += item.quantity

                                    # Calculate the free quantity for the current item
                                    free_quantity = int(item.quantity / buy) * get
                                    total_free_quantity += free_quantity

                                total_price = item.product.salePrice * item.quantity

                                if item.product.pk in matched_product_pks:
                                    offer_products.append(item)
                                if item.product.pk in allowed_discount_products:
                                    discount_allowed_products.append(item)

                                # Calculate subtotal and total sale price for each item
                                sub_total_sale_price += item.product.price * item.quantity
                                total_sale_price += item.product.salePrice * item.quantity

                            # Calculate the total free quantity based on the combined quantity
                            total_combined_free_quantity = int(total_combined_quantity / buy) * get


                            serializer = CartSerializers(user_cart, many=True)
                            total_discount_after_adjustment = sub_total_sale_price - total_sale_price

                            shipping_fee = 60 if total_sale_price <= 500 else 0

                            response_data = {
                                "status": "User cart products",
                                "data": serializer.data,
                                "free":total_combined_free_quantity,
                                "Discount": total_discount_after_adjustment,
                                "Shipping": shipping_fee,
                                "TotalPrice": sub_total_sale_price,
                                "Subtotal": total_sale_price
                            }

                            return Response(response_data, status=status.HTTP_200_OK)
                        else:
                            try:
                                spend_amount = offer_schedule.amount
                                discount_percentage = offer_schedule.discount_percentage

                                # Combine matched product pks with allowed discount products
                                combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products)) if matched_product_pks else set(approved_category_product_pks)

                                # Get user cart items
                                user_cart = Cart.objects.filter(customer=user)

                                if not user_cart.exists():
                                    return Response({"message": "Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)

                                # Calculate total amounts
                                user_cart_total_amount = sum(item.product.price * item.quantity for item in user_cart)
                                total_cart_value = sum(item.product.salePrice * item.quantity for item in user_cart)

                                # Calculate total value of items in the cart eligible for the offer
                                total_spend_offer_cart_value = sum(item.product.salePrice * item.quantity for item in user_cart if item.product.pk in combined_product_pks)

                                # Initialize variables for discount calculations
                                discount_value = user_cart_total_amount - total_cart_value
                                after_discount = discount_value
                                total_cart_value_after_discount = total_cart_value

                                # Check if total cart value meets the spend amount requirement
                                if total_spend_offer_cart_value >= spend_amount:
                                    # Calculate the discount
                                    discount_value_discount = total_spend_offer_cart_value * (discount_percentage / 100)
                                    after_discount += discount_value_discount
                                    total_cart_value_after_discount -= discount_value_discount

                                # Serialize cart data
                                serializer = CartSerializers(user_cart, many=True)

                                # Calculate shipping fee
                                shipping_fee = 60 if total_cart_value <= 500 else 0

                                # Prepare response data
                                response_data = {
                                    "status": "User cart products",
                                    "data": serializer.data,
                                    "Discount": after_discount,
                                    "Shipping": shipping_fee,
                                    "TotalPrice": user_cart_total_amount,
                                    "Subtotal": total_cart_value_after_discount,
                                    "message": "SPEND OFFER APPLIED" if total_spend_offer_cart_value >= spend_amount else "Cart offer products total is less than the spend amount required for the offer"
                                }

                                return Response(response_data)

                            except Exception as e:
                                return Response({"message": "An error occurred during offer processing"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                    except Exception as e:
                        return Response({"message": "An error occurred during offer processing"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    try:
                        if offer.offer_type == "BUY" and offer.method == "FREE":
                            buy = offer.get_option
                            get = offer.get_value

                            combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                            user_cart = Cart.objects.filter(customer=user, product__in=combined_product_pks)

                            # Fetch product data in a single query
                            offer_products_data = Product.objects.filter(pk__in=matched_product_pks)
                            discount_allowed_products_data = Product.objects.filter(pk__in=allowed_discount_products)

                            # Check if there are intersection products
                            intersection_exists = offer_products_data.filter(pk__in=discount_allowed_products_data.values('pk')).exists()

                            total_sale_price = sum(item.product.salePrice * item.quantity for item in cart)
                            sub_total_sale_price = sum(item.product.price * item.quantity for item in cart)

                            offer_products = []
                            discount_allowed_products = []
                            total_free_quantity = 0

                            for item in user_cart:
                                if item.product.pk in matched_product_pks:
                                    free_quantity = item.quantity * get
                                    offer_products.append(item)
                                else:
                                    free_quantity = 0

                                if item.product.pk in allowed_discount_products:
                                    discount_allowed_products.append(item)

                                total_free_quantity += free_quantity
                            
                            if intersection_exists:

                                if discount_allowed_products:
                                    discount_allowed_products.sort(key=lambda item: item.product.salePrice)

                                    remaining_free_quantity = int(total_free_quantity //  2)

                                    total_cart_value = total_sale_price
                                    total_discount = 0

                                    for item in discount_allowed_products:
                                        product = item.product
                                        product_price = product.salePrice
                                        product_quantity = item.quantity


                                        if remaining_free_quantity <= 0:
                                            break

                                        discount_quantity = min(product_quantity, remaining_free_quantity)
                                        discount_amount = product_price * discount_quantity
                                        total_cart_value -= discount_amount
                                        remaining_free_quantity -= discount_quantity
                                        total_discount += discount_amount


                                    total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                    shipping_fee = 60 if total_cart_value <= 500 else 0

                                    response_data = {
                                        "status": "User cart products",
                                        "data": CartSerializers(cart, many=True).data,
                                        "Discount": total_discount_after_adjustment,
                                        "Shipping": shipping_fee,
                                        "TotalPrice": sub_total_sale_price,
                                        "Subtotal": total_cart_value,
                                        "TotalDiscount": total_discount
                                    }

                                    return Response(response_data, status=status.HTTP_200_OK)

                            else:
                                total_free_quantity = 0
                                for item in user_cart:
                                    if item.product.pk in matched_product_pks:
                                        free_quantity = item.quantity * get
                                    else:
                                        free_quantity = 0

                                    total_quantity = item.quantity + free_quantity
                                    total_price = item.product.salePrice * item.quantity

                                    if item.product.pk in matched_product_pks:
                                        offer_products.append(item)
                                    if item.product.pk in allowed_discount_products:
                                        discount_allowed_products.append(item)


                                total_sale_price = sum(i.product.salePrice * i.quantity for i in cart)
                                sub_total_sale_price = sum(i.product.price * i.quantity for i in cart)


                                if discount_allowed_products:
                                    discount_allowed_products.sort(key=lambda i: i.product.salePrice)

                                    offer_products_in_cart = cart.filter(product__in=matched_product_pks)
                                    remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                    total_free_quantity = remaining_free_quantity * get


                                    total_cart_value = total_sale_price
                                    total_discount = 0
                                    processed_products = set()  # Track processed products

                                    for item in discount_allowed_products:
                                        product = item.product
                                        product_price = product.salePrice
                                        product_quantity = item.quantity

                                        if product.pk in processed_products:
                                            continue  # Skip if product is already processed


                                        if total_free_quantity <= 0:
                                            break  # Exit the loop once the free quantity is exhausted

                                        # Calculate the quantity that can be discounted
                                        discount_quantity = min(product_quantity, total_free_quantity)
                                        
                                        # Calculate the discount amount
                                        discount_amount = product_price * discount_quantity

                                        # Subtract the discount amount from the total cart value
                                        total_cart_value -= discount_amount
                                        
                                        # Subtract the discounted quantity from the total free quantity
                                        total_free_quantity -= discount_quantity
                                        
                                        # Accumulate the total discount
                                        total_discount += discount_amount

                                        processed_products.add(product.pk)  # Mark product as processed


                                    # Calculate the total discount after adjustment
                                    total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                    shipping_fee = 60 if total_cart_value <= 500 else 0

                                    response_data = {
                                        "status": "User cart products",
                                        "data": CartSerializers(cart, many=True).data,
                                        "Discount": total_discount_after_adjustment,
                                        "Shipping": shipping_fee,
                                        "TotalPrice": sub_total_sale_price,
                                        "Subtotal": total_cart_value,
                                        "TotalDiscount": total_discount
                                    }

                                    return Response(response_data, status=status.HTTP_200_OK)


                        elif offer.offer_type == "SPEND" and offer.method == "% OFF":
                            return Response({"message": "Offer coming soon"}, status=status.HTTP_501_NOT_IMPLEMENTED)

                        else:
                            return Response({"message": "Offer type or method not recognized"}, status=status.HTTP_400_BAD_REQUEST)

                    except Exception as e:
                        return Response({"message": "An error occurred during offer processing"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


            serializer = CartSerializers(cart, many=True)

            total_price = 0
            total_discounted_price = 0
            for item in cart:
                product = item.product
                original_price = product.price if product.price is not None else product.salePrice
                sale_price = product.salePrice if product.salePrice is not None else 0
                quantity = item.quantity
                
                total_price += original_price * quantity
                total_discounted_price += sale_price * quantity

            if total_discounted_price <= 500:
                shipping_fee = 0
            else:
                shipping_fee = 0
                
            subtotal = total_discounted_price + shipping_fee
            discount_offer = total_price - total_discounted_price

            

            response_data = {
                "status": "User cart products",
                "data": serializer.data,
                "Discount": discount_offer,
                "Shipping": shipping_fee,
                "TotalPrice": total_price,
                "Subtotal": subtotal
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CartProductDelete(APIView):
    def get(self,request,pk):
        try :
            product = Cart.objects.filter(pk=pk).first()
            if product is None :
                return Response({"message": "Product not found in cart"}, status=status.HTTP_404_NOT_FOUND)
            serializer = CartModelSerializers(product, many=False)
            return Response({"message": "Product Fetch from cart",'data':serializer.data}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def delete(self,request,pk):
        try :
            product = Cart.objects.filter(pk=pk).first()
            if product is None :
                return Response({"message": "Product not found in cart"}, status=status.HTTP_404_NOT_FOUND)
            product.delete()
            return Response({"message": "Product Delete from cart"}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

            

class IncrementProductQuantity(APIView):

    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            cart_item = Cart.objects.filter(customer=user,pk=pk).first()
            if not cart_item:
                return Response({"message": "Product not found in the cart"}, status=status.HTTP_404_NOT_FOUND)

            cart_item.quantity += 1
            cart_item.save()

            return Response({"message": "Product quantity increased successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None

class DecrementProductQuantity(APIView):
    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            cart_item = Cart.objects.filter(customer=user, pk=pk).first()
            if not cart_item:
                return Response({"message": "Product not found in the cart"}, status=status.HTTP_404_NOT_FOUND)

            if cart_item.quantity > 1:
                cart_item.quantity -= 1
                cart_item.save()
                return Response({"message": "Product quantity decreased successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Quantity cannot be less than 1"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None



class OfferBanerBasedProducts(APIView):
    def post(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            offer = OfferBanner.objects.filter(pk=pk).first()
            if not offer:
                return Response({"message": "Offer banner not found"}, status=status.HTTP_404_NOT_FOUND)

            products = Product.objects.filter(offer_banner=offer.pk)
            serializer = ProductViewSerializers(products, many=True)
            if serializer:
                return Response({'products':serializer.data}, status=status.HTTP_200_OK)
            return Response({'message': "Products not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None
        


class ProductBigView(APIView):
    def get(self, request, slug):
        try:
            product = Product.objects.filter(slug=slug).first()
            if product:
                # Serialize the product details
                serializer = CustomerAllProductSerializers(product)

                if product.type == "single":
                    # Filter and serialize product color stocks for single products
                    product_images = ProductColorStock.objects.filter(product=product)
                    single_product = SingleProductSerializer(product_images, many=True)
                    image_serializer = single_product.data

                else:
                    # Filter and serialize product variants and their stock info for variant products
                    product_variants = ProductVariant.objects.filter(product=product)
                    variant_serializer = VariantProductSerializer(product_variants, many=True)
                    image_serializer = variant_serializer.data

                return Response({'product': serializer.data, 'images': image_serializer}, status=status.HTTP_200_OK)

            return Response({'message': "Product not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





# class ProductBigView(APIView):
#     def get(self, request, slug):
#         try:
#             product = Product.objects.filter(slug=slug).first()
#             if product:
#                 # Serialize main product details
#                 serializer = CustomerAllProductSerializers(product)

#                 # Fetch and serialize product images
#                 product_images = ProducyImage.objects.filter(product=product)
#                 image_serializer = ProductSerializerWithMultipleImage(product_images, many=True)

#                 # Fetch and serialize product variants based on colors from product images
#                 product_colors = product_images.values_list('id', flat=True)  # Assuming id is the correct field
#                 product_variants = Productverient.objects.filter(color_id__in=product_colors)
#                 variant_serializer = ProductVarientModelSerilizers(product_variants, many=True)

#                 # Return response with product details, images, and variants
#                 return Response({
#                     'product': serializer.data,
#                     'images': image_serializer.data,
#                     'variants': variant_serializer.data
#                 }, status=status.HTTP_200_OK)
            
#             return Response({'message': "Product not found"}, status=status.HTTP_404_NOT_FOUND)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class MianCategoryBasedProducts(APIView):
    def get(self, request, slug):
        try:
            main_category = Category.objects.filter(slug=slug).first()
            if main_category:
                products = Product.objects.filter(category__category=main_category)
                serializer = ProductViewSerializers(products, many=True)
                return Response({'products':serializer.data}, status=status.HTTP_200_OK)
            return Response({'message':"Category not found"},status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class UserPasswordReset(APIView):
    def put(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = PasswordResetSerializer(data=request.data)
            if serializer.is_valid():
                old_password = serializer.validated_data.get('old_password')
                new_password = serializer.validated_data.get('new_password')
                confirm_password = serializer.validated_data.get('confirm_password')

                # Check if the old password matches the user's current password
                if old_password and not check_password(old_password, user.password):
                    return Response({"message": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

                # Check if the new password and confirm password match
                if new_password != confirm_password:
                    return Response({"message": "New password and confirm password do not match"}, status=status.HTTP_400_BAD_REQUEST)

                # Update the user's password
                user.password = make_password(new_password)
                user.save()

                return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None


class UserAddressAdd(APIView):
    def post(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            address_data = request.data.copy()
            address_data['user'] = user.id
            serializer = AddressSerializer(data=address_data)

            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Address added successfully"}, status=status.HTTP_201_CREATED)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response({"message": "Address already exists"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            return Response({"message": f"Invalid token: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        


class UserAddressView(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            userAddress = Address.objects.filter(user=user.pk)
            serializer = AddressSerializer(userAddress, many=True)
            return Response({'address': serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None




class UserAddressUpdate(APIView):
    def put(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            userAddress = Address.objects.filter(pk=pk).first()
            if not userAddress:
                return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = AddressUpdateSerializer(userAddress, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None



class UserAddressDelete(APIView):
    def delete(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            userAddress = Address.objects.filter(pk=pk).first()
            if not userAddress:
                return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

            userAddress.delete()
            return Response({"message": "Address deleted successfully"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None



class UserSearchProductView(APIView):
    def get(self, request):
        try:
            query = request.query_params.get('q', '').strip()
            
            if not query:
                return Response({"message": "No search query provided"}, status=status.HTTP_400_BAD_REQUEST)

            products = Product.objects.filter(
                Q(name__icontains=query) |
                Q(description__icontains=query) |
                Q(short_description__icontains=query)
            )

            if products.exists():
                serializer = ProductViewSerializer(products, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"message": "No products found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            

class HighToLowProducts(APIView):
    def get(self, request, pk):
        try:
            sort_order = request.query_params.get('sort', 'high_to_low')
            category = Subcategory.objects.filter(pk=pk).first()
            
            if not category:
                return Response({"message": "Subcategory not found"}, status=status.HTTP_404_NOT_FOUND)

            if sort_order == 'high_to_low':
                products = Product.objects.filter(category=category.pk).order_by('-salePrice')
            elif sort_order == 'low_to_high':
                products = Product.objects.filter(category=category.pk).order_by('salePrice')
            else:
                return Response({"message": "Invalid sort order"}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ProductViewSerializer(products, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LowToHighProducts(APIView):
    def get(self, request,pk):
        try:
            sort_order = request.query_params.get('sort', 'low_to_high')
            category = Subcategory.objects.filter(pk=pk).first()

            if not category:
                return Response({"message": "Subcategory not found"}, status=status.HTTP_404_NOT_FOUND)

            if sort_order == 'low_to_high':
                products = Product.objects.filter(category=category.pk).order_by('salePrice')
            elif sort_order == 'high_to_low' : 
                products = Product.objects.filter(category=category.pk).order_by('-salePrice')
            else:
                return Response({"message": "Invalid sort order"}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ProductViewSerializer(products, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = Customer.objects.filter(email=email).first()
            
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            otp_instance = OTP.objects.filter(user=user).first()
            otp = random.randint(100000, 999999)
            if otp_instance:
                otp_instance.otp = otp
                otp_instance.save()
            else:
                OTP.objects.create(user=user, otp=otp)
            
            # Render email template with OTP value
            try:
                email_body = render_to_string('otp.html', {'otp': otp})
                
                # Send email
                send_mail(
                    'Bepocart Reset Password OTP',
                    '',  # Email body (plain text)
                    settings.EMAIL_HOST_USER,  
                    [email],  
                    fail_silently=False,
                    html_message=email_body
                )
                return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"message": f"Error sending email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            if not otp :
                return Response({"message": "OTP not found"}, status=status.HTTP_404_NOT_FOUND)


            user = Customer.objects.filter(email=email).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            valid_otp = OTP.objects.filter(user=user, otp=otp).first()
            if not valid_otp:
                return Response({"message": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            # OTP verified, proceed to change password
            return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_password = serializer.validated_data['new_password']
            confirm_password = serializer.validated_data['confirm_password']


            user = Customer.objects.filter(email=email).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            if new_password != confirm_password :
                return Response({"message": "Password is not match !"}, status=status.HTTP_404_NOT_FOUND)
            
            user.password = make_password(new_password)
            user.save()

            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class UserProfileUpdate(APIView):
    def get(self,request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            
            serializer = UserProfileSErilizers(user, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None

    def put(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = UserProfileSErilizers(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None





class CreateOrder(APIView):
    def post(self, request, pk):
        token = request.headers.get('Authorization')
        if not token:
            return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        user_id = user_token.get('id')
        if not user_id:
            return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        user = Customer.objects.filter(pk=user_id).first()
        if not user:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        cart_items = Cart.objects.filter(customer=user)
        if not cart_items.exists():
            return Response({"message": "Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)
        
        offer_approved_products = []
        offer_approved_category = []
        discount_approved_products =[]
        discount_approved_category = []
        coupon_approved_products = []
        coupon_approved_categories = []

        offer = OfferSchedule.objects.filter(offer_active=True).first()

        # Get active coupons
        active_coupons = Coupon.objects.filter(status='Active')

        if offer:

            coupon_approved_products = list()
            offer_approved_products = list(offer.offer_products.values_list('pk', flat=True))
            offer_approved_category = list(offer.offer_category.values_list('pk', flat=True))

            # Discount approved products and categories
            discount_approved_products = list(offer.discount_approved_products.values_list('pk', flat=True))
            discount_approved_category = list(offer.discount_approved_category.values_list('pk', flat=True))

            # Fetch all products that belong to offer-approved category products
            approved_category_products = Product.objects.filter(category__pk__in=offer_approved_category)
            approved_category_product_pks = list(approved_category_products.values_list('pk', flat=True))

            # Fetch all products that belong to discount-approved category products
            approved_discount_category_products = Product.objects.filter(category__pk__in=discount_approved_category)
            approved_discount_category_product_pks = list(approved_discount_category_products.values_list('pk', flat=True))

            for coupon in active_coupons:
                # Extend the lists with products and categories from each coupon
                coupon_approved_products.extend(coupon.discount_product.values_list('pk', flat=True))
                coupon_approved_categories.extend(coupon.discount_category.values_list('pk', flat=True))

            # Remove duplicates from the lists
            coupon_approved_products = list(set(coupon_approved_products))
            coupon_approved_categories = list(set(coupon_approved_categories))

            products_in_cart = [item.product.pk for item in cart_items]


            # Find products in cart that are either approved by the offer or belong to approved categories
            matched_product_pks = [product_pk for product_pk in products_in_cart 
                    if product_pk in offer_approved_products or product_pk in approved_category_product_pks]
            
            # Find products in cart that are either approved for discount or  categories
            allowed_discount_products = [product_pk for product_pk in products_in_cart 
                                        if product_pk in discount_approved_products or product_pk in approved_discount_category_product_pks]
                                        
                        
            if offer.is_active: 
                try :
                    if offer and offer.offer_type == "BUY" and offer.method == "FREE":
                        # Retrieve the buy and get values
                        buy = offer.get_option
                        get = offer.get_value
                        

                        # Combine matched product pks with allowed discount products
                        if matched_product_pks:
                            combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                        else:
                            combined_product_pks = set(approved_category_product_pks)

                        # Get user cart items
                        user_cart = Cart.objects.filter(customer=user)
                        offer_products = []
                        discount_allowed_products = []

                        total_free_quantity = 0
                        total_sale_price = 0
                        sub_total_sale_price = 0
                        total_combined_quantity = 0


                        for item in user_cart:
                            free_quantity = 0
                            if item.product.pk in combined_product_pks:
                                total_combined_quantity += item.quantity

                                # Calculate the free quantity for the current item
                                free_quantity = int(item.quantity / buy) * get
                                total_free_quantity += free_quantity




                            if item.product.pk in matched_product_pks:
                                offer_products.append(item)
                            if item.product.pk in allowed_discount_products:
                                discount_allowed_products.append(item)

                            # Calculate subtotal and total sale price for each item
                            sub_total_sale_price += item.product.price * item.quantity
                            total_sale_price += item.product.salePrice * item.quantity





                        # Calculate the total free quantity based on the combined quantity
                        total_combined_free_quantity = int(total_combined_quantity / buy) * get
                        serializer = CartSerializers(cart_items, many=True)


                        address = Address.objects.filter(pk=pk, user=user).first()
                        if not address:
                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                        total_amount = total_sale_price
                        
                        
                        coupon_code = request.data.get('coupon_code')
                        coupon = None  # Initialize coupon as None

                        if coupon_code:
                            coupon = Coupon.objects.filter(code=coupon_code).first()
                            if not coupon or coupon.status != 'Active':
                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                        # Calculate the total amount before applying the coupon
                        try:
                            if coupon:
                                discount_amount = apply_coupon(coupon.code, total_amount, cart_items)
                                total_amount -= discount_amount
                        except ValueError as e:
                            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

                        payment_method = request.data.get('payment_method')
                        if not payment_method:
                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                        if payment_method not in ['COD', 'razorpay']:
                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)
                
                        
                        cart_items_list = [
            
                            {
                                
                                'name': item.product.name,
                                'quantity': item.quantity,
                                'price': item.product.salePrice,
                                'image':item.product.image.url
                            }
                            
                            for item in cart_items]
                        try:
                            if payment_method == "COD":
                                with transaction.atomic():
                                    order = Order.objects.create(
                                        customer=user,
                                        address=address,
                                        status='pending',
                                        payment_method=payment_method,
                                        free_quantity=total_combined_free_quantity,
                                        coupon=coupon if coupon else None 

                                    )

                                    for item in user_cart:
                                        # Fetch active offers related to the product or its category
                                        offers = OfferSchedule.objects.filter(
                                            Q(offer_active=True) &
                                            (Q(offer_products=item.product.pk) | Q(offer_category=item.product.category.pk))
                                        )

                                        # Collect offer details (assuming you want to use the first offer if multiple are found)
                                        offer_details = []
                                        for offer in offers:
                                            offer_detail = f"{offer.offer_type} {offer.get_option} GET {offer.get_value} {offer.method}"
                                            offer_details.append(offer_detail)

                                        # Use the first offer detail or a combined string if there are multiple offers
                                        offer_type_string = ", ".join(offer_details) if offer_details else "No offer"

                                        # Create the order item with offer details
                                        OrderItem.objects.create(
                                            customer=user,
                                            order=order,
                                            product=item.product,
                                            quantity=item.quantity,
                                            price=item.product.salePrice,
                                            color=item.color,
                                            size=item.size,
                                            offer_type=offer_type_string  # Include the offer details in the order item
                                        )

                                        if item.product.type == "single":
                                            check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                            if not check_color.exists():
                                                return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                            update_single_product_stock(check_color, item)
                                        else:
                                            update_variant_stock(item)
                                            
                                

                                # Determine shipping charge based on total_amount
                                if total_amount <= Decimal('500.00'):
                                    order.shipping_charge = Decimal('60.00')
                                else:
                                    order.shipping_charge = Decimal('0.00')

                                # Add COD charge
                                order.cod_charge = Decimal('40.00')
                                total_amount += order.shipping_charge + order.cod_charge

                                # Update order total amount and save
                                order.total_amount = total_amount
                                order.save()

                                # Send order email and delete cart items
                                send_order_email(order, cart_items_list)
                                cart_items.delete()

                                # Serialize the order data and return response
                                serializer = OrderSerializer(order)
                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)


                            else:
                                logging.info(f"Total amount before applying shipping and coupon: {total_amount}")

                                # Create a Razorpay order
                                razorpay_order_id = create_razorpay_order(total_amount)
                                
                                return Response({
                                    "message": "Razorpay order created successfully.",
                                    "razorpay_order_id": razorpay_order_id,
                                }, status=status.HTTP_200_OK)   
                        except Exception as e:
                            logging.info(f"error {e}")
                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else:
                        try:
                            spend_amount = offer.amount
                            discount_percentage = offer.discount_percentage

                            # Combine matched product pks with allowed discount products
                            combined_product_pks = set(matched_product_pks or set()).union(set(allowed_discount_products) or set(approved_category_product_pks))

                            # Get user cart items
                            user_cart = Cart.objects.filter(customer=user)

                            if not user_cart.exists():
                                    return Response({"message": "Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)


                            # Calculate total amounts
                            user_cart_total_amount = sum(item.product.price * item.quantity for item in user_cart)
                            total_cart_value = sum(item.product.salePrice * item.quantity for item in user_cart)

                            # Calculate total value of items in the cart eligible for the offer
                            total_spend_offer_cart_value = sum(item.product.salePrice * item.quantity for item in user_cart if item.product.pk in combined_product_pks)

                            # Initialize variables for discount calculations
                            discount_value = user_cart_total_amount - total_cart_value

                            if total_spend_offer_cart_value >= spend_amount:
                                # Calculate the discount
                                discount_value_discount = total_spend_offer_cart_value * (discount_percentage / 100)
                                after_discount = discount_value_discount + discount_value
                                total_cart_value_after_discount = total_cart_value - discount_value_discount
                            else:
                                after_discount = discount_value
                                total_cart_value_after_discount = total_cart_value

                            # Serialize cart data
                            serializer = CartSerializers(user_cart, many=True)

                            address = Address.objects.filter(pk=pk, user=user).first()
                            if not address:
                                return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                            total_amount = total_cart_value_after_discount
                            
                            
                            coupon_code = request.data.get('coupon_code')
                            coupon = None  # Initialize coupon as None

                            if coupon_code:
                                coupon = Coupon.objects.filter(code=coupon_code).first()
                                if not coupon or coupon.status != 'Active':
                                    return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                            # Calculate the total amount before applying the coupon
                            try:
                                if coupon:
                                    discount_amount = apply_coupon(coupon.code, total_amount, cart_items)
                                    total_amount -= discount_amount
                            except ValueError as e:
                                return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

                            payment_method = request.data.get('payment_method')
                            if not payment_method:
                                return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                            if payment_method not in ['COD', 'razorpay']:
                                return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)
                        
                        
                            
                            cart_items_list = [
            
                                    {
                                        
                                        'name': item.product.name,
                                        'quantity': item.quantity,
                                        'price': item.product.salePrice,
                                        'image':item.product.image.url
                                    }
                                    
                                    for item in cart_items]
                            
                            if payment_method == 'COD': 
                                with transaction.atomic():
                                    order = Order.objects.create(
                                        customer=user,
                                        address=address,
                                        status='pending',
                                        payment_method=payment_method,
                                        coupon=coupon if coupon else None 

                                    )

                                    for item in user_cart:
                                        # Fetch active offers related to the product or its category (including subcategories)
                                        offers = OfferSchedule.objects.filter(
                                                    Q(offer_products=item.product.pk) | Q(offer_category=item.product.category.pk),
                                                    offer_active=True  
                                                )
                                        # Collect offer details (assuming you want to use the first offer if multiple are found)
                                        offer_details = [f"{offer.offer_type} {offer.amount} {offer.discount_percentage} {offer.method}" for offer in offers]
                                        offer_type_string = ", ".join(offer_details) if offer_details else "No offer"

                                        # Create the order item with offer details
                                        OrderItem.objects.create(
                                            customer=user,
                                            order=order,
                                            product=item.product,
                                            quantity=item.quantity,
                                            price=item.product.salePrice,
                                            color=item.color,
                                            size=item.size,
                                            offer_type=offer_type_string  
                                        )

                                        # Update stock based on the product type
                                        if item.product.type == "single":
                                            check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                            if not check_color.exists():
                                                return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                            update_single_product_stock(check_color, item)
                                        else:
                                            update_variant_stock(item)
                                            


                                # Determine shipping charge based on total_amount
                                if total_amount <= Decimal('500.00'):
                                    order.shipping_charge = Decimal('60.00')
                                else:
                                    order.shipping_charge = Decimal('0.00')

                                # Add COD charge
                                order.cod_charge = Decimal('40.00')
                                total_amount += order.shipping_charge + order.cod_charge

                                # Update order total amount and save
                                order.total_amount = total_amount
                                order.save()

                                # Send order email and delete cart items
                                send_order_email(order, cart_items_list)
                                cart_items.delete()

                                # Serialize the order data and return response
                                serializer = OrderSerializer(order)
                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)

                            else:
                                logging.info(f"Total amount before applying shipping and coupon: {total_amount}")

                                # Create a Razorpay order
                                razorpay_order_id = create_razorpay_order(total_amount)
                                return Response({
                                    "message": "Razorpay order created successfully.",
                                    "razorpay_order_id": razorpay_order_id,
                                }, status=status.HTTP_200_OK)        
                        except Exception as e:
                            logging.info(f"error {e}")
                            return Response({"message": f"An error occurred during order processing: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                except Exception as e:
                    logging.info(f"error {e}")
                    return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                try :                   
                    if offer.offer_type == "BUY" and offer.method == "FREE":
                        buy = offer.get_option
                        get = offer.get_value

                        combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                        user_cart = Cart.objects.filter(customer=user, product__in=combined_product_pks)

                        # Fetch product data in a single query
                        offer_products_data = Product.objects.filter(pk__in=matched_product_pks)
                        discount_allowed_products_data = Product.objects.filter(pk__in=allowed_discount_products)

                        # Check if there are intersection products
                        intersection_exists = offer_products_data.filter(pk__in=discount_allowed_products_data.values('pk')).exists()

                        total_sale_price = sum(item.product.salePrice * item.quantity for item in cart_items)
                        sub_total_sale_price = sum(item.product.price * item.quantity for item in cart_items)

                        offer_products = []
                        discount_allowed_products = []
                        total_free_quantity = 0

                        for item in user_cart:
                            if item.product.pk in matched_product_pks:
                                free_quantity = item.quantity * get
                                offer_products.append(item)
                            else:
                                free_quantity = 0

                            if item.product.pk in allowed_discount_products:
                                discount_allowed_products.append(item)

                            total_free_quantity += free_quantity

                        if intersection_exists:



                            if discount_allowed_products:
                                discount_allowed_products.sort(key=lambda item: item.product.salePrice)

                                remaining_free_quantity = int(total_free_quantity // 2)
                                total_cart_value = total_sale_price
                                total_discount = 0

                                for item in discount_allowed_products:
                                    product = item.product
                                    product_price = product.salePrice
                                    product_quantity = item.quantity

                                    if remaining_free_quantity <= 0:
                                        break

                                    discount_quantity = min(product_quantity, remaining_free_quantity)
                                    discount_amount = product_price * discount_quantity
                                    total_cart_value -= discount_amount
                                    remaining_free_quantity -= discount_quantity
                                    total_discount += discount_amount






                                address = Address.objects.filter(pk=pk, user=user).first()
                                if not address:
                                    return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                total_amount = total_cart_value
                                
                                
                                coupon_code = request.data.get('coupon_code')
                                coupon = None  # Initialize coupon as None

                                if coupon_code:
                                    coupon = Coupon.objects.filter(code=coupon_code).first()
                                    if not coupon or coupon.status != 'Active':
                                        return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                # Calculate the total amount before applying the coupon
                                try:
                                    if coupon:
                                        discount_amount = apply_coupon(coupon.code, total_amount, cart_items)
                                        total_amount -= discount_amount
                                except ValueError as e:
                                    return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

                                payment_method = request.data.get('payment_method')
                                if not payment_method:
                                    return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                if payment_method not in ['COD', 'razorpay']:
                                    return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)
                                
                                
                                cart_items_list = [
            
                                        {
                                            
                                            'name': item.product.name,
                                            'quantity': item.quantity,
                                            'price': item.product.salePrice,
                                            'image':item.product.image.url
                                        }
                                        
                                        for item in cart_items]
                                
                                try:
                                    if payment_method == "COD":
                                        with transaction.atomic():
                                            order = Order.objects.create(
                                                customer=user,
                                                address=address,
                                                status='pending',
                                                payment_method=payment_method,
                                                coupon=coupon if coupon else None 


                                            )

                                            for item in cart_items:
                                                # Fetch active offers related to the product or its category
                                                offers = OfferSchedule.objects.filter(
                                                    Q(offer_active=True) &
                                                    (Q(offer_products=item.product.pk) | Q(offer_category=item.product.category.pk))
                                                )
                                                
                                                # Fetch discount-approved products or categories
                                                discount_products = OfferSchedule.objects.filter(
                                                    Q(offer_active=True) & Q(is_active=False) &
                                                    (Q(discount_approved_products=item.product.pk) | Q(discount_approved_category=item.product.category.pk))
                                                )

                                                # Collect offer details
                                                offer_details = []
                                                for offer in offers:
                                                    offer_detail = f"{offer.offer_type} {offer.get_option} GET {offer.get_value} {offer.method}"
                                                    offer_details.append(offer_detail)

                                                # Collect discount details
                                                discount_details = []
                                                if discount_products.exists():
                                                    discount_details.append("Discount Allowed")

                                                # Combine offer and discount details into a single string
                                                offer_type_string = ", ".join(offer_details + discount_details) if offer_details or discount_details else "No offer"

                                                # Create the order item with offer details
                                                OrderItem.objects.create(
                                                    customer=user,
                                                    order=order,
                                                    product=item.product,
                                                    quantity=item.quantity,
                                                    price=item.product.salePrice,
                                                    color=item.color,
                                                    size=item.size,
                                                    offer_type=offer_type_string  # Include the offer details in the order item
                                                )

                                                if item.product.type == "single":
                                                    check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                                    if not check_color.exists():
                                                        return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                                    update_single_product_stock(check_color, item)
                                                else:
                                                    update_variant_stock(item)
                                                    


                                        
                                        # Determine shipping charge based on total_amount
                                        if total_amount <= Decimal('500.00'):
                                            order.shipping_charge = Decimal('60.00')
                                        else:
                                            order.shipping_charge = Decimal('0.00')

                                        # Add COD charge
                                        order.cod_charge = Decimal('40.00')
                                        total_amount += order.shipping_charge + order.cod_charge

                                        # Update order total amount and save
                                        order.total_amount = total_amount
                                        order.save()

                                        # Send order email and delete cart items
                                        send_order_email(order, cart_items_list)
                                        cart_items.delete()

                                        # Serialize the order data and return response
                                        serializer = OrderSerializer(order)
                                        return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)

                                    else:
                                        logging.info(f"Total amount before applying shipping and coupon: {total_amount}")


                                        # Create a Razorpay order
                                        razorpay_order_id = create_razorpay_order(total_amount)
                                        return Response({
                                            "message": "Razorpay order created successfully.",
                                            "razorpay_order_id": razorpay_order_id,
                                        }, status=status.HTTP_200_OK)
                                        
                                except Exception as e:
                                    logging.info(f"error {e}")
                                    return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        
                        try:
                            total_free_quantity = 0
                            for item in user_cart:
                                if item.product.pk in matched_product_pks:
                                    free_quantity = item.quantity * get
                                else:
                                    free_quantity = 0

                                if item.product.pk in matched_product_pks:
                                    offer_products.append(item)
                                if item.product.pk in allowed_discount_products:
                                    discount_allowed_products.append(item)


                            total_sale_price = sum(i.product.salePrice * i.quantity for i in cart_items)
                            sub_total_sale_price = sum(i.product.price * i.quantity for i in cart_items)


                            if discount_allowed_products:
                                discount_allowed_products.sort(key=lambda i: i.product.salePrice)

                                offer_products_in_cart = cart_items.filter(product__in=matched_product_pks)
                                remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                total_free_quantity = remaining_free_quantity * get


                                total_cart_value = total_sale_price
                                total_discount = 0
                                processed_products = set()  # Track processed products

                                for item in discount_allowed_products:
                                    product = item.product
                                    product_price = product.salePrice
                                    product_quantity = item.quantity

                                    if product.pk in processed_products:
                                        continue  # Skip if product is already processed


                                    if total_free_quantity <= 0:
                                        break  # Exit the loop once the free quantity is exhausted

                                    # Calculate the quantity that can be discounted
                                    discount_quantity = min(product_quantity, total_free_quantity)
                                    
                                    # Calculate the discount amount
                                    discount_amount = product_price * discount_quantity

                                    # Subtract the discount amount from the total cart value
                                    total_cart_value -= discount_amount
                                    
                                    # Subtract the discounted quantity from the total free quantity
                                    total_free_quantity -= discount_quantity
                                    
                                    # Accumulate the total discount
                                    total_discount += discount_amount

                                    processed_products.add(product.pk)  # Mark product as processed


                                address = Address.objects.filter(pk=pk, user=user).first()
                                if not address:
                                    return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                # Calculate the total amount before applying the coupon
                                total_amount = total_cart_value
                                 
                                coupon_code = request.data.get('coupon_code')
                                coupon = None  # Initialize coupon as None

                                if coupon_code:
                                    coupon = Coupon.objects.filter(code=coupon_code).first()
                                    if not coupon or coupon.status != 'Active':
                                        return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                # Calculate the total amount before applying the coupon
                                try:
                                    if coupon:
                                        discount_amount = apply_coupon(coupon.code, total_amount, cart_items)
                                        total_amount -= discount_amount
                                except ValueError as e:
                                    return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

                                payment_method = request.data.get('payment_method')
                                if not payment_method:
                                    return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                if payment_method not in ['COD', 'razorpay']:
                                    return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)
                                
                                try:
                                    if payment_method == "COD":
                                        with transaction.atomic():
                                            order = Order.objects.create(
                                                customer=user,
                                                address=address,
                                                status='pending',
                                                payment_method=payment_method,
                                                coupon=coupon if coupon else None 

                                            )

                                            for item in cart_items:
                                                # Fetch active offers related to the product or its category
                                                offers = OfferSchedule.objects.filter(
                                                    Q(offer_active=True) &
                                                    (Q(offer_products=item.product.pk) | Q(offer_category=item.product.category.pk))
                                                )
                                                
                                                # Fetch discount-approved products or categories
                                                discount_products = OfferSchedule.objects.filter(
                                                    Q(offer_active=True) & Q(is_active=False) &
                                                    (Q(discount_approved_products=item.product.pk) | Q(discount_approved_category=item.product.category.pk))
                                                )

                                                # Collect offer details
                                                offer_details = []
                                                for offer in offers:
                                                    offer_detail = f"{offer.offer_type} {offer.get_option} GET {offer.get_value} {offer.method}"
                                                    offer_details.append(offer_detail)

                                                # Collect discount details
                                                discount_details = []
                                                if discount_products.exists():
                                                    discount_details.append("Discount Allowed")

                                                # Combine offer and discount details into a single string
                                                offer_type_string = ", ".join(offer_details + discount_details) if offer_details or discount_details else "No offer"

                                                # Create the order item with offer details
                                                OrderItem.objects.create(
                                                    customer=user,
                                                    order=order,
                                                    product=item.product,
                                                    quantity=item.quantity,
                                                    price=item.product.salePrice,
                                                    color=item.color,
                                                    size=item.size,
                                                    offer_type=offer_type_string  # Include the offer details in the order item
                                                )

                                                if item.product.type == "single":
                                                    check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                                    if not check_color.exists():
                                                        return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                                    update_single_product_stock(check_color, item)
                                                else:
                                                    update_variant_stock(item)

                                        

                                        # Determine shipping charge based on total_amount
                                        if total_amount <= Decimal('500.00'):
                                            order.shipping_charge = Decimal('60.00')
                                        else:
                                            order.shipping_charge = Decimal('0.00')

                                        # Add COD charge
                                        order.cod_charge = Decimal('40.00')
                                        total_amount += order.shipping_charge + order.cod_charge

                                        # Update order total amount and save
                                        order.total_amount = total_amount
                                        order.save()

                                        # Send order email and delete cart items
                                        send_order_email(order, cart_items_list)
                                        cart_items.delete()

                                        # Serialize the order data and return response
                                        serializer = OrderSerializer(order)
                                        return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)

                                    else:
                                        
                                        logging.info(f"Total amount before applying shipping and coupon: {total_amount}")

                                        # Create a Razorpay order
                                        razorpay_order_id = create_razorpay_order(total_amount)
                                        
                                        return Response({
                                            "message": "Razorpay order created successfully.",
                                            "razorpay_order_id": razorpay_order_id,
                                        }, status=status.HTTP_200_OK)
                                        
                                except Exception as e:
                                    logging.info(f"error {e}")
                                    return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        except Exception as e:
                            logging.info(f"error {e}")
                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else:
                        return Response({"message":"No matching offer type found"})
                except Exception as e :
                    logging.info(f"error {e}")
                    return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
        address = Address.objects.filter(pk=pk, user=user).first()
        if not address:
            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)
        
        total_amount = sum(item.product.salePrice * item.quantity for item in cart_items)

        coupon_code = request.data.get('coupon_code')
        coupon = None  # Initialize coupon as None

        if coupon_code:
            coupon = Coupon.objects.filter(code=coupon_code).first()
            if not coupon or coupon.status != 'Active':
                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

        # Calculate the total amount before applying the coupon
        try:
            if coupon:
                discount_amount = apply_coupon(coupon.code, total_amount, cart_items)
                total_amount -= discount_amount
        except ValueError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        payment_method = request.data.get('payment_method')
        if not payment_method:
            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
        if payment_method not in ['COD', 'razorpay']:
            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

        
        cart_items_list = [
            
            {
                
                'name': item.product.name,
                'quantity': item.quantity,
                'price': item.product.salePrice,
                'image':item.product.image.url
            }
            
            for item in cart_items]
        
        
        try:
            if payment_method == "COD":
                with transaction.atomic():
                    order = Order.objects.create(
                        customer=user,
                        address=address,
                        status='pending',
                        payment_method=payment_method,
                        coupon=coupon if coupon else None 
                    )

                    

                    for item in cart_items:
                        order_item = OrderItem.objects.create(
                            customer=user,
                            order=order,
                            product=item.product,
                            quantity=item.quantity,
                            price=item.product.salePrice,
                            color=item.color,
                            size=item.size
                        )

                        if item.product.type == "single":
                            check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                            if not check_color.exists():
                                return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                            update_single_product_stock(check_color, item)
                        else:
                            update_variant_stock(item)
                            
                            
                    
                                    

                    if total_amount <= Decimal('500.00'):
                        order.shipping_charge = Decimal('60.00')
                    else:
                        order.shipping_charge = Decimal('0.00')

                    order.cod_charge = Decimal('40.00')
                    total_amount += order.shipping_charge + order.cod_charge

                    order.total_amount = total_amount
                    order.save()

                    send_order_email(order, cart_items_list)
                    cart_items.delete()

                    serializer = OrderSerializer(order)
                    return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)


            else:
                # Log the calculated total amount for tracking purposes
                logging.info(f"Total amount before applying shipping and coupon: {total_amount}")
                
                razorpay_order_id = create_razorpay_order(total_amount)
                
                return Response({
                    "message": "Razorpay order created successfully.",
                    "razorpay_order_id": razorpay_order_id,
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def update_single_product_stock(check_color, item):
    for stock in check_color:
        if stock.stock >= item.quantity:
            stock.stock -= item.quantity
            stock.save()
            break
    else:
        raise ValueError(f"Insufficient stock for {item.product.name} - {item.color}")

def update_variant_stock(item):
    product_variants = ProductVariant.objects.filter(product=item.product, color=item.color)
    if not product_variants.exists():
        raise ValueError(f"No variants found for {item.product.name} - {item.color}")

    for variant in product_variants:
        size_stocks = ProductVarientSizeStock.objects.filter(product_variant=variant, size=item.size)
        for stock in size_stocks:
            if stock.stock >= item.quantity:
                stock.stock -= item.quantity
                stock.save()
                break
        else:
            raise ValueError(f"Insufficient stock for {item.product.name} - {item.color} - {item.size}")




def apply_coupon(coupon_code, total_amount, cart_items):

    # Fetch a single coupon from the database or raise a 404 error
    check_coupon = get_object_or_404(Coupon, code=coupon_code)

    # Validate the coupon
    if not check_coupon.is_valid():
        raise ValueError("Coupon is invalid or inactive.")

    is_applicable = False
    approved_products = []

    # Get applicable product and category IDs
    applicable_products = set(check_coupon.discount_product.values_list('id', flat=True))
    applicable_categories = set(check_coupon.discount_category.values_list('id', flat=True))

    # Check cart items against the coupon's applicable products/categories
    for cart_item in cart_items:
        product = cart_item.product

        if product.id in applicable_products or product.category.pk in applicable_categories:
            approved_products.append(product)
            is_applicable = True

    if not is_applicable:
        raise ValueError("Coupon is not applicable to the products in your cart.")

    # Calculate total price of approved products
    total_approved_products_price = sum(cart_item.product.salePrice * cart_item.quantity for cart_item in cart_items if cart_item.product in approved_products)

    # Calculate discount based on coupon type
    if check_coupon.coupon_type == 'Percentage':
        discount_amount = (check_coupon.discount / 100) * total_approved_products_price
    elif check_coupon.coupon_type == 'Fixed Amount':
        discount_amount = min(check_coupon.discount, total_approved_products_price)
    else:
        raise ValueError("Invalid coupon type.")

    # Ensure the discount does not exceed the total amount
    if discount_amount > total_amount:
        raise ValueError("Discount exceeds total amount.")

    return discount_amount






def send_order_email(order, cart_items_list):
    try:
        # Email details
        email_subject = 'New Order Created'
        
        # Render the email template with order and cart details
        email_body = render_to_string('new_order.html', {'order': order, 'user_cart': cart_items_list})
        
        # List of recipient emails: admin and the user's email
        recipient_list = [settings.EMAIL_HOST_USER, order.customer.email]  # Assuming order.customer.email is the user's email
        
        # Create and send the email
        email = EmailMessage(
            subject=email_subject, 
            body=email_body, 
            from_email=settings.EMAIL_HOST_USER, 
            to=recipient_list
        )
        email.content_subtype = 'html'  # Specify HTML content type
        email.send()

    except Exception as email_error:
        # Log the error if email fails
        logging.error(f"Error sending email: {email_error}")

def create_razorpay_order(total_amount):
    # Validate total_amount
    if total_amount <= 0:
        raise ValueError("Total amount must be greater than 0")
    
    if total_amount <= 500:
        total_amount += 60  # Add ₹60 shipping charge
    
    try:
        # Initialize Razorpay client
        razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': int(total_amount * 100),  # Amount in paise
            'currency': 'INR',
            'payment_capture': 1  # Auto capture
        })

        # Return Razorpay order ID
        _id = razorpay_order['id']
        return _id

    except razorpay.errors.BadRequestError as e:
        raise ValueError("Invalid Razorpay request.") from e

    except Exception as e:
        raise ValueError("An unexpected error occurred during Razorpay order creation.") from e
        


class VerifyRazorpayPaymentAPIView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError):
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            cart_items = Cart.objects.filter(customer=user)
            
            if not cart_items.exists():
                return Response({"message": "Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)
            
             # Extract payment details from the request
            razorpay_order_id = request.data.get('order_id')
            razorpay_payment_id = request.data.get('payment_id')
            razorpay_signature = request.data.get('razorpay_signature')
            total_amount = Decimal(request.data.get('total_amount', 0))
            coupon_code = request.data.get('coupon_code',None)
            address_id = request.data.get('address_id')
            shipping_charge = request.data.get('shipping_charge', 0)
            
            
            

            
            
            
            
            coupon = None
            if coupon_code:
                coupon = Coupon.objects.filter(code=coupon_code).first()
                if not coupon:
                    return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)
            
            address = Address.objects.filter(pk=address_id, user=user).first()
            if not address:
                return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)
            
           

        
        
            # Verify Razorpay signature
            razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            try:
                razorpay_client.utility.verify_payment_signature({
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': razorpay_payment_id,
                    'razorpay_signature': razorpay_signature
                })

                # Fetch payment details from Razorpay
                payment_details = razorpay_client.payment.fetch(razorpay_payment_id)
                if payment_details['status'] == 'captured':
                    with transaction.atomic():
                        order = Order.objects.create(
                            customer=user,
                            address=address,
                            status='pending',
                            payment_method='razorpay',
                            razorpay_order_id=razorpay_order_id,
                            payment_id = razorpay_payment_id,
                            total_amount = total_amount,
                            coupon=coupon if coupon else None ,
                            shipping_charge = shipping_charge
                        )

                        for item in cart_items:
                            order_item = OrderItem.objects.create(
                                customer=user,
                                order=order,
                                product=item.product,
                                quantity=item.quantity,
                                price=item.product.salePrice,
                                color=item.color,
                                size=item.size
                            )

                            if item.product.type == "single":
                                check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                if check_color is None :
                                    return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                for stock in check_color :
                                    if stock.stock >= item.quantity:
                                        stock.stock -= item.quantity
                                        stock.save()

                            else :
                                product_variants = ProductVariant.objects.filter(product=item.product, color=item.color)

                                if not product_variants.exists():
                                    return Response({"message": f"No variants found for {item.product.name} - {item.color}"}, status=status.HTTP_404_NOT_FOUND)

                                for variant in product_variants:
                                    # Filter the size stocks related to the current variant
                                    size_stocks = ProductVarientSizeStock.objects.filter(product_variant=variant, size=item.size)
                                    
                                    for stock in size_stocks:
                                        if stock.stock >= item.quantity:
                                            # Update stock
                                            stock.stock -= item.quantity
                                            stock.save()
                                            break  # Break out of the inner loop if stock is updated
                                        else:
                                            return Response({"message": f"Insufficient stock for {item.product.name} - {item.color} - {item.size}"}, status=status.HTTP_400_BAD_REQUEST)

                            total_amount += item.product.salePrice * item.quantity

                    

                        cart_items_list = [
                        {
                            'product_name': item.product.name,
                            'quantity': item.quantity,
                            'price': item.product.salePrice,
                            'image':item.product.image.url
                        }
                        for item in cart_items

                        ]
                        send_order_razorpay_email(order, cart_items_list)
                        serializer = OrderSerializer(order)
                        return Response({"message": "Payment already captured.","success":serializer.data}, status=status.HTTP_200_OK)

                payment_capture_response = razorpay_client.payment.capture(razorpay_payment_id, int(total_amount * 100))

                # Check if the payment capture was successful
                if payment_capture_response['status'] == 'captured':
                    order.payment_id = razorpay_payment_id
                    order.total_amount = total_amount
                    order.save()
                    
                    cart_items_list = [
                        {
                            'product_name': item.product.name,
                            'quantity': item.quantity,
                            'price': item.product.salePrice,
                            'image':item.product.image.url
                        }
                        for item in cart_items

                        ]
                    send_order_razorpay_email(order, cart_items_list)

                    return Response({"message": "Payment verified and captured successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "Payment capture failed.", "details": payment_capture_response}, status=status.HTTP_400_BAD_REQUEST)

            except razorpay.errors.SignatureVerificationError as e:
                return Response({"error": "Invalid payment signature."}, status=status.HTTP_400_BAD_REQUEST)
            except Order.DoesNotExist:
                return Response({"error": "Order not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logging.error(f"Error during Razorpay payment verification: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
        
def send_order_razorpay_email(order, cart_items_list):
    try:
        # Email details
        email_subject = 'New Order Created'
        
        # Render the email template with order and cart details
        email_body = render_to_string('new_order.html', {'order': order, 'user_cart': cart_items_list})
        
        # List of recipient emails: admin and the user's email
        recipient_list = [settings.EMAIL_HOST_USER, order.customer.email]  # Assuming order.customer.email is the user's email
        
        # Create and send the email
        email = EmailMessage(
            subject=email_subject, 
            body=email_body, 
            from_email=settings.EMAIL_HOST_USER, 
            to=recipient_list
        )
        email.content_subtype = 'html'  # Specify HTML content type
        email.send()

    except Exception as email_error:
        # Log the error if email fails
        logging.error(f"Error sending email: {email_error}")


class RelatedProduct(APIView):
    def get(self, request, slug):
        try:
            product = Product.objects.get(slug=slug)
            related_products = Product.objects.filter(category=product.category).exclude(slug=product.slug)[:8]
            serializer = ProductSerializer(related_products, many=True)
            return Response({"data":serializer.data})
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)




class DiscountSaleProducts(APIView):
    def get(self, request):
        try:
            offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()
            if offer_schedule:
                offer_products = offer_schedule.offer_products.all()
                if not offer_products.exists():
                    offer_category_products = offer_schedule.offer_category.all()
                    offer_products = Product.objects.filter(category__in=offer_category_products)
                    if not offer_products.exists():
                        return Response({'error': 'No products found for the offer categories'}, status=status.HTTP_404_NOT_FOUND)
                serializer = ProductViewSerializer(offer_products, many=True)
                return Response({"data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No offer schedule found'}, status=status.HTTP_404_NOT_FOUND)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for discount sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BestSellerProductsAPIView(APIView):
    def get(self, request):
        # Annotate each product with the total quantity sold and order by it
        best_selling_products = Product.objects.annotate(
            total_sold=Sum('orderitem__quantity')
        ).order_by('-total_sold')[:10]  # Limit to top 10

        # Serialize the data
        serializer = BestSellerProductSerializer(best_selling_products, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
        

class FIftypercontageProducts(APIView):
    def get(self, request):
        try:
            discount_sale = Product.objects.filter(offer_type="50 %").order_by('-pk')
            serializer = SubcatecoryBasedProductView(discount_sale, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for 50 percantage sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class BuyOneGetOneOffer(APIView):
    def get(self, request):
        try:
            discount_sale = Product.objects.filter(offer_type="BUY 1 GET 1").order_by('-pk')
            serializer = SubcatecoryBasedProductView(discount_sale, many=True)
            return Response({"data":serializer.data}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for BUY 1 GET 1 sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BuyOneGetOneOfferFree(APIView):
    def get(self, request):
        try:
            discount_sale = Product.objects.filter(offer_type="BUY 1 GET 1").order_by('-pk')[:4]
            serializer = SubcatecoryBasedProductView(discount_sale, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for BUY 1 GET 1 sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class BuyToGetOne(APIView):
    def get(self, request):
        try:
            discount_sale = Product.objects.filter(offer_type="BUY 2 GET 1").order_by('-pk')
            serializer = SubcatecoryBasedProductView(discount_sale, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for BUY 2 GET 1 sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# class ProducViewWithMultipleImage(APIView):
#     def get(self, request, pk):
#         try:
#             product_images = ProducyImage.objects.filter(product_id=pk)

#             for product_image in product_images:
#                 sizes = product_image.size.all()  # Fetch all related sizes
#                 size_names = [size.name for size in sizes]  # List comprehension to get the names

#             if not product_images.exists():
#                 return Response({'error': 'Product images not found'}, status=status.HTTP_404_NOT_FOUND)
            
#             serializer = ProductSerializerWithMultipleImage(product_images, many=True)
#             return Response({"product": serializer.data}, status=status.HTTP_200_OK)
#         except ProducyImage.DoesNotExist:
#             return Response({'error': 'Product images not found'}, status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserProfileView(APIView):
    def get(self,request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            
            serializer = UserProfileSErilizers(user, many=False)
            return Response({"data":serializer.data}, status=status.HTTP_200_OK)
        

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None



class CustomerOrders(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            user_orders = Order.objects.filter(customer=user).order_by('-id')
            if not user_orders.exists():
                return Response({"message": "No orders found for this user"}, status=status.HTTP_404_NOT_FOUND)

            serializer = OrderSerializer(user_orders, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None


class CustomerAllOrderItems(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            user_orders = OrderItem.objects.filter(customer=user)
            if not user_orders.exists():
                return Response({"message": "No orders found for this user"}, status=status.HTTP_404_NOT_FOUND)

            serializer = CustomerAllOrderSerializers(user_orders, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None
            

class CustomerOrderItems(APIView):
    def get(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            user_orders = OrderItem.objects.filter(order=pk)
            if not user_orders.exists():
                return Response({"message": "No orders found for this user"}, status=status.HTTP_404_NOT_FOUND)

            serializer = CustomerAllOrderSerializers(user_orders, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None
        
            


        



        


class RecentlyViewedProductsView(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            recently_viewed = RecentlyViewedProduct.objects.filter(user=user).select_related('product').order_by('-pk')[:5]
            products = [item.product for item in recently_viewed]
            serializer = RecomendedProductSerializer(products, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # def post(self, request, product_id):
    #     try:
    #         token = request.COOKIES.get('token')
    #         if not token:
    #             return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    #         user_id = self._validate_token(token)
    #         if not user_id:
    #             return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

    #         user = Customer.objects.filter(pk=user_id).first()
    #         if not user:
    #             return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    #         product = Product.objects.get(pk=product_id)
    #         recently_viewed, created = RecentlyViewedProduct.objects.get_or_create(user=user, product=product)
    #         if not created:
    #             recently_viewed.viewed_at = timezone.now()
    #             recently_viewed.save()

    #         return Response({"message": "Product added to recently viewed"}, status=status.HTTP_200_OK)
    #     except Product.DoesNotExist:
    #         return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
    #     except Exception as e:
    #         return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None
        


class RecommendedProductsView(APIView):
    def get(self, request):
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Fetch recently viewed products by the user
            recently_viewed_products = RecentlyViewedProduct.objects.filter(user=user).values_list('product', flat=True).order_by('-pk')

            # Fetch products from user's orders
            ordered_products = OrderItem.objects.filter(order__customer=user).values_list('product', flat=True)

            # Combine recently viewed and ordered products to find similar ones
            product_ids = list(set(recently_viewed_products) | set(ordered_products))

            if not product_ids:
                return Response({"message": "No recommendations is  available"}, status=status.HTTP_200_OK)

            # Fetch products that are similar to the ones the user interacted with
            similar_products = Product.objects.filter(category__products__id__in=product_ids).exclude(id__in=product_ids).distinct()[:10]

            # Serialize the recommended products
            serializer = RecomendedProductSerializer(similar_products, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    def _validate_token(self, token):
        try:
            user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            return user_token.get('id')
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None


class FilteredProductsView(APIView):
    def post(self, request,pk):
        try:
            min_price = request.data.get('min_price', 0)
            max_price = request.data.get('max_price', 1000000)
            category = Subcategory.objects.filter(pk=pk).first()
            

            filtered_products = Product.objects.filter(category=category,salePrice__gte=min_price, salePrice__lte=max_price)
            serializer = ProductSerializerView(filtered_products, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class UserProfileImageSetting(APIView):
    def post(self,request):

        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            # Decode the JWT token
            try:
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token: user ID not found"}, status=status.HTTP_401_UNAUTHORIZED)

            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = UserProfileSerializers(user,partial=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        try:
            # Fetch the token from cookies
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            # Decode the JWT token
            try:
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token: user ID not found"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch the user from the database
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Handle the uploaded file
            serializer = UserProfileSerializers(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CoupensAll(APIView):
    def get(self, request):
        try:
            coupon = Coupon.objects.all()
            serializer = CouponSerilizers(coupon, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)







class BlogView(APIView):
    def get(self, request):
        try:
            blog = Blog.objects.all().order_by('id')
            serializer = BlogSerializer(blog, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CustomerCoinView(APIView):
    def get(self, request):
        try:
            # Retrieve token from request headers
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve user ID from token payload
            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token: user ID not found"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user based on user ID
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Fetch coins related to the user
            coins = Coin.objects.filter(user=user)
            serializer = CustomerCoinSerializers(coins, many=True)

            # Fetch coin value
            coin_value = CoinValue.objects.first()
            if not coin_value:
                return Response({"message": "No coin value found"}, status=status.HTTP_404_NOT_FOUND)
            
            coin_value_serializer = CoinValueModelSerilizers(coin_value)
            
            return Response({
                "message": "Success", 
                "data": serializer.data, 
                "coinValue": coin_value_serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class CreateProductReview(APIView):
    def post(self, request, pk):
        try:
            token = request.headers.get('Authorization')
            if token is None:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                # Decode JWT token
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token: user ID not found"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user based on user ID
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Fetch product based on product ID (pk)
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

            # Extract review details from request data
            data = {
                'user': user.pk,
                'product': product.pk,
                'rating': request.data.get('rating'),
                'review_text': request.data.get('review_text'),
            }

            # Validate and save review
            serializer = ReviewAddingModelSerilizers(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CustomerProductReviewView(APIView):
    def get(self, request, pk):
        try:
            product = Product.objects.filter(pk=pk).first()
            if not product:
                return Response({"status": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            
            reviews = Review.objects.filter(product=product,status="Approved").all()
            serializer = ReviewModelSerilizers(reviews, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                

class AllOfferpRODUCTS(APIView):
    def get(self, request):
        try:
            offer = OfferSchedule.objects.all()
            serializer = OfferModelSerilizers(offer,many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



            



class SendOtpView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone')

        if not phone_number:
            return Response({'error': 'Phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
        phone_number = phone_number.strip()  # Clean up phone number

        # Validate phone number format (example: check if it's a 10-digit number)
        if not phone_number.isdigit() or len(phone_number) != 10:
            return Response({'error': 'Invalid phone number format'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create or get the customer instance using the phone number
            customer, created = Customer.objects.get_or_create(
                phone=phone_number
            )

            if created:
                # Customer was created
                logger.info(f"Created new customer with phone number {phone_number}")
            else:
                # Customer already exists
                logger.info(f"Customer with phone number {phone_number} already exists")

            # Generate and send OTP
            otp = generate_otp()
            send_status = send_otp(phone_number, otp)
            if send_status:
                cache.set(phone_number, otp, timeout=300)  # Cache OTP for 5 minutes
                OTP.objects.create(user=customer, otp=otp)
                return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
            else:
                # Log the failure reason
                logger.error(f"Failed to send OTP to phone number {phone_number}. Status: {send_status}")
                return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Error in SendOtpView: {e}", exc_info=True)
            return Response({'error': 'An unexpected error occurred. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)       



class VerifyOtpView(APIView):
    def post(self, request):
        phone_number = request.data.get('phone')
        otp = request.data.get('otp')

        if not phone_number or not otp:
            return Response({'error': 'Phone number and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Retrieve the user associated with the phone number
        user = Customer.objects.filter(phone=phone_number).first()
        if not user:
            return Response({'error': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Verify the OTP
        check_otp = OTP.objects.filter(user=user, otp=otp).first()
        if check_otp:
            # Optionally, delete the OTP record after verification
            check_otp.delete()

            # Generate JWT token
            payload = {
                'id': user.pk,
                'email': user.email,
                'exp': datetime.utcnow() + timedelta(hours=1),  # Token expires in 1 hour
                'iat': datetime.utcnow(),
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

            return Response({
                'message': 'OTP verified and token generated successfully',
                'id': user.pk,
                'token': token
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)



class AllProductsSchemaAPIView(APIView):
    def get(self, request, *args, **kwargs):
        products = Product.objects.all().order_by('pk')
        schemas = []

        for product in products:
            # Fetch reviews for the current product
            reviews = Review.objects.filter(product=product)
            review_count = reviews.count()
            rating_value = 0

            if review_count > 0:
                # Calculate average rating
                rating_value = reviews.aggregate(Avg('rating'))['rating__avg']

            schema = {
                "@context": "https://schema.org",
                "@type": "Product",
                "@id": f"{settings.FRONTEND_URL}/single-product/{product.slug}/",
                "name": product.name,
                "image": product.image.url if product.image else "",
                "description": product.description,
                "sku": str(product.pk),  # Ensure sku is a string
                "brand": {
                    "@type": "Brand",
                    "name": "bepocart"
                },
                "offers": {
                    "@type": "Offer",
                    "url": f"{settings.FRONTEND_URL}/single-product/{product.slug}/",
                    "priceCurrency": "INR",
                    "price": "{:.2f}".format(product.salePrice),  # Format price to two decimal places
                    "priceValidUntil": "2050-11-20T23:59:59Z",  # ISO 8601 format for date
                    "itemCondition": "https://schema.org/NewCondition",
                    "availability": "https://schema.org/InStock",
                    "seller": "bepocart"
                },
                "aggregateRating": {
                    "@type": "AggregateRating",
                    "ratingValue": "{:.1f}".format(rating_value),  # Format rating to one decimal place
                    "reviewCount": review_count,
                },
            }
            schemas.append(schema)

        return JsonResponse(schemas, safe=False)
    



from django.shortcuts import render
import json

class ProductSchemaAPIView(APIView):
    def get(self, request, slug, *args, **kwargs):
        # Fetch the product by slug
        product = Product.objects.filter(slug=slug).first()
        if not product:
            return JsonResponse({"error": "Product not found"}, status=404)

        # Fetch reviews for the current product
        reviews = Review.objects.filter(product=product)
        review_count = reviews.count()
        rating_value = 0

        if review_count > 0:
            # Calculate average rating
            rating_value = reviews.aggregate(Avg('rating'))['rating__avg']

        # Fetch additional product data based on type
        if product.type == "single":
            product_data = ProductColorStock.objects.filter(product=product).values('color', 'stock', 'image1', 'image2', 'image3', 'image4', 'image5')
        else:
            product_data = ProductVariant.objects.filter(product=product).values('color', 'image1', 'image2', 'image3', 'image4', 'image5')

        # Prepare image list for schema, filter out None values
        images = [image for item in product_data for image in [item['image1'], item['image2'], item['image3'], item['image4'], item['image5']] if image]

        # Construct the schema
        schema = {
            "@context": "https://schema.org",
            "@type": "Product",
            "name": product.name,
            "image": images,  # Insert the list of images here
            "description": product.description,
            "sku": str(product.pk),  # Ensure SKU is a string
            "brand": {
                "@type": "Brand",
                "name": "bepocart"
            },
            "offers": {
                "@type": "Offer",
                "url": f"{settings.FRONTEND_URL}/single-product/{product.slug}/",
                "priceCurrency": "INR",
                "price": "{:.2f}".format(product.salePrice),  # Format price to two decimal places
                "priceValidUntil": "2050-11-20T23:59:59Z",  # ISO 8601 format for date
                "itemCondition": "https://schema.org/NewCondition",
                "availability": "https://schema.org/InStock"
            },
            "aggregateRating": {
                "@type": "AggregateRating",
                "ratingValue": "{:.1f}".format(rating_value) if rating_value else None,  # Format rating to one decimal place
                "reviewCount": review_count,
            }
        }

        # Convert schema to JSON
        schema_json = json.dumps(schema)

        # Render HTML with the schema embedded in the <script> tag
        context = {
            "schema_json": schema_json,
            "product": product,
        }
        return render(request, 'product_schema.html', context)







class CustomerDeleteAccount(APIView):
    def delete(self, request):
        try:
            # Extract and validate token
            token = request.headers.get('Authorization')
            if token is None :
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        
            try:
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_token.get('id')
            if not user_id:
                return Response({"message": "Invalid token: user ID not found"}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch user based on user ID
            user = Customer.objects.filter(pk=user_id).first()
            if not user:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Perform deletion in a transaction
            with transaction.atomic():
                user.delete()

            return Response({"message": "Account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            logging.error(f"Error deleting account: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
