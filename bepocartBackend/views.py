import razorpay
import jwt
from django.shortcuts import get_object_or_404
import random
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
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
from django.contrib.auth.hashers import check_password, make_password
from django.template.loader import render_to_string
from django.db import transaction
from decimal import Decimal

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




class CustomerLogin(APIView):
    def post(self, request):
        serializer = CustomerLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            customer = Customer.objects.filter(email=email).first()

            if customer and customer.check_password(password):
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
                    secure=settings.SECURE_COOKIE  # Ensure this matches your settings
                )
                coin_value = CoinValue.objects.first()  
                if coin_value:
                    coins_to_add = coin_value.login_value
                    coin_record = Coin.objects.create(user=customer, amount=coins_to_add, source="Login")
                    coin_record.save()
                return response
            else:
                return Response({
                    "status": "error",
                    "message": "Invalid email or password"
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                "status": "error",
                "message": "Invalid data",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


################################################  HOME    #############################################

class CategoryView(APIView):
    def get(self, request):
        try :
            
            categories = Category.objects.all()
            serializer = CategorySerializer(categories, many=True)
            return Response({
                "status": "success",
                "data": serializer.data
            },status=status.HTTP_200_OK)

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
        try:
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                user_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return Response({"message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                return Response({"message": f"Invalid token: {e}"}, status=status.HTTP_401_UNAUTHORIZED)

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
            recently_viewed, created = RecentlyViewedProduct.objects.get_or_create(user=user, product=product)
            if not created:
                recently_viewed.viewed_at = timezone.now()
                recently_viewed.save()

            # Add the product to the wishlist
            wishlist_data = {'user': user.pk, 'product': product.pk}
            wishlist_serializer = WishlistSerializers(data=wishlist_data)
            if wishlist_serializer.is_valid():
                wishlist_serializer.save()
                return Response({"message": "Product added to wishlist successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "Unable to add product to wishlist", "errors": wishlist_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response({"message": "Product already exists in the wishlist"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CustomerWishlist(APIView):
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
                
            wishlist = Wishlist.objects.filter(user=user.pk)
            serializer = WishlistSerializersView(wishlist, many=True)
            return Response({"status":"User wishlist products","data":serializer.data},status=status.HTTP_200_OK)
                
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
            token = request.headers.get('Authorization')
            if not token:
                return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = self._validate_token(token)
            if not user_id:
                return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

            user = get_object_or_404(Customer, pk=user_id)

            product = get_object_or_404(Product, pk=pk)
            
            recently_viewed, created = RecentlyViewedProduct.objects.get_or_create(user=user, product=product)
            if not created:
                recently_viewed.viewed_at = timezone.now()
                recently_viewed.save()
                
            # Check if the product is already in the user's Cart
            if Cart.objects.filter(customer=user, product=product).exists():
                return Response({"message": "Product already exists in the cart"}, status=status.HTTP_400_BAD_REQUEST)
            
            if product.type == "single":
                product_color = request.data.get('color')
                cart_data = {'customer': user.pk, 'product': product.pk, 'color': product_color}
                serializer = CartModelSerializers(data=cart_data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({"message": "Product added to cart successfully"}, status=status.HTTP_201_CREATED)
                else:
                    return Response({"message": "Unable to add product to cart", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            product_color = request.data.get('color')
            product_size = request.data.get('size')

            cart_data = {'customer': user.pk, 'product': product.pk, 'color': product_color, 'size': product_size}
            serializer = CartModelSerializers(data=cart_data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Product added to cart successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "Unable to add product to cart", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
        except IntegrityError:
            return Response({"message": "Product already exists in the cart"}, status=status.HTTP_400_BAD_REQUEST)
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



from datetime import datetime
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
                        if offer_schedule:
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
                                total_free_quantity = 0
                                total_sale_price = 0
                                sub_total_sale_price = 0

                                for item in user_cart:
                                    free_quantity = 0
                                    if item.product.pk in combined_product_pks:
                                        free_quantity = int(item.quantity / buy) * get
                                        total_free_quantity += free_quantity

                                    total_quantity = int(item.quantity + free_quantity)
                                    total_price = item.product.salePrice * item.quantity
                                    print(f"Item: {item.product.pk}, Quantity: {item.quantity}, Total Quantity : {total_quantity}, Total Price: {total_price}")


                                    if item.product.pk in matched_product_pks:
                                        offer_products.append(item)
                                    if item.product.pk in allowed_discount_products:
                                        discount_allowed_products.append(item)

                                    # Calculate subtotal and total sale price for each item
                                    sub_total_sale_price += item.product.price * item.quantity
                                    total_sale_price += item.product.salePrice * item.quantity

                                print("Subtotal Sale Price:", sub_total_sale_price)
                                print("Total Sale Price:", total_sale_price)


                                serializer = CartSerializers(cart, many=True)
                                total_discount_after_adjustment = sub_total_sale_price - total_sale_price
                                print("Total Discount After Adjustment:", total_discount_after_adjustment)

                                if total_sale_price <= 500:
                                    shipping_fee = 60
                                else:
                                    shipping_fee = 0
                                print("Shipping Fee:", shipping_fee)

                                response_data = {
                                    "status": "User cart products",
                                    "data": serializer.data,
                                    "Discount": total_discount_after_adjustment,
                                    "Shipping": shipping_fee,
                                    "TotalPrice": sub_total_sale_price,
                                    "Subtotal": total_sale_price
                                }

                                return Response(response_data, status=status.HTTP_200_OK)
                            else:
                                print("SPEND OFFER IS COMING SOON")
                                return Response({"message": "SPEND OFFER IS COMING SOON"})
                        else:
                            print("OFFER IS NOT ACTIVE")
                            return Response({"message": "OFFER IS NOT ACTIVE"})
                    except Exception as e:
                        print("An error occurred:", e)
                        return Response({"message": "An error occurred during offer processing"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    try:
                        offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()
                        print(f"Discount offer")
                        total = 0
                        for data in cart:
                            total_product_value = data.quantity * data.product.salePrice
                            total += total_product_value

                        print("Total Product Value:", total)

                        if matched_product_pks and allowed_discount_products:
                            print("Matched Product PKs:", matched_product_pks)
                            print("Allowed Discount Products:", allowed_discount_products)
                            
                            if offer_schedule.offer_type == "BUY" and offer_schedule.method == "FREE":
                                buy = offer_schedule.get_option
                                get = offer_schedule.get_value

                                combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                                user_cart = Cart.objects.filter(customer=user, product__in=combined_product_pks)

                                offer_products = []
                                discount_allowed_products = []

                                offer_products_data = Product.objects.filter(pk__in=matched_product_pks)
                                discount_allowed_products_data = Product.objects.filter(pk__in=allowed_discount_products)

                                intersection_products = offer_products_data.filter(pk__in=discount_allowed_products_data.values('pk'))
                                print("Intersection Products:", intersection_products)

                                if intersection_products.exists():
                                    print("-------------------------------------------SAME PRODUCTS OFFER AND DISCOUNT IS AVAILABLE----------------------------------------")
                                
                                    total_free_quantity = 0
                                    for item in cart:
                                        if item.product.pk in matched_product_pks:
                                            free_quantity = (item.quantity) * get
                                        else:
                                            free_quantity = 0
                                        total_quantity = item.quantity + free_quantity
                                        total_price = item.product.salePrice * item.quantity

                                        if item.product.pk in matched_product_pks:
                                            offer_products.append(item)
                                        if item.product.pk in allowed_discount_products:
                                            discount_allowed_products.append(item)

                                        print(f"Item: {item.product.pk}, Free Quantity: {free_quantity}, Total Quantity: {total_quantity}, Total Price: {total_price}")
                                        

                                    total_sale_price = sum(i.product.salePrice * i.quantity for i in cart)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart)

                                    print("Total Sale Price:", total_sale_price)
                                    print("Sub Total Sale Price:", sub_total_sale_price)


                                    if discount_allowed_products:
                                        discount_allowed_products.sort(key=lambda i: i.product.salePrice)
                                        offer_products_in_cart = user_cart.filter(product__in=matched_product_pks)
                                        remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                        total_free_quantity = int(remaining_free_quantity / 2) * get

                                        print("Total Free Quantity:", total_free_quantity)
                                        total_discount = 0  

                                        total_cart_value = total_sale_price
                                        for item in discount_allowed_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            print(f"Product: {product.pk}, Product Price: {product_price}, Product Quantity: {product_quantity}")


                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0

                                            total_discount += discount_amount  # Accumulate discount amount
                                            print(f"Discount Amount: {discount_amount}, Total Cart Value: {total_cart_value}, Remaining Free Quantity: {total_free_quantity}")


                                        serializer = CartSerializers(cart, many=True)
                                        total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                        shipping_fee = 60 if total_cart_value <= 500 else 0

                                        print("Total after udgestment   :",total_cart_value)


                                        response_data = {
                                            "status": "User cart products",
                                            "data": serializer.data,
                                            "Discount": total_discount_after_adjustment,
                                            "Shipping": shipping_fee,
                                            "TotalPrice": sub_total_sale_price,
                                            "Subtotal": total_cart_value
                                        }

                                        return Response(response_data, status=status.HTTP_200_OK)

                                else:
                                    print("-------------------------------------------SAME PRODUCTS OFFER AND DISCOUNT IS NOT AVAILABLE----------------------------------------")
                                    total_free_quantity = 0
                                    for item in user_cart:
                                        if item.product.pk in matched_product_pks:
                                            free_quantity = (item.quantity) * get
                                        else:
                                            free_quantity = 0
                                        total_quantity = item.quantity + free_quantity
                                        total_price = item.product.salePrice * item.quantity

                                        if item.product.pk in matched_product_pks:
                                            offer_products.append(item)
                                        if item.product.pk in allowed_discount_products:
                                            discount_allowed_products.append(item)

                                        print(f"Item: {item.product.pk}, Free Quantity: {free_quantity}, Total Quantity: {total_quantity}, Total Price: {total_price}")

                                    total_sale_price = sum(i.product.salePrice * i.quantity for i in cart)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart)

                                    print("Total Sale Price:", total_sale_price)
                                    print("Sub Total Sale Price:", sub_total_sale_price)

                                    if discount_allowed_products:
                                        discount_allowed_products.sort(key=lambda i: i.product.salePrice)

                                        offer_products_in_cart = user_cart.filter(product__in=matched_product_pks)
                                        remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                        total_free_quantity = int(remaining_free_quantity) * get

                                        print("Total Free Quantity:", total_free_quantity)

                                        total_cart_value = total_sale_price
                                        total_discount = 0  # Initialize total discount
                                        for item in discount_allowed_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            print(f"Product: {product.pk}, Product Price: {product_price}, Product Quantity: {product_quantity}")

                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0

                                            total_discount += discount_amount  # Accumulate discount amount
                                            print(f"Discount Amount: {discount_amount}, Total Cart Value: {total_cart_value}, Remaining Free Quantity: {total_free_quantity}")

                                        serializer = CartSerializers(cart, many=True)
                                        total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                        shipping_fee = 60 if total_cart_value <= 500 else 0

                                        print("Total after udgestment   :",total_cart_value)

                                        response_data = {
                                            "status": "User cart products",
                                            "data": serializer.data,
                                            "Discount": total_discount_after_adjustment,
                                            "Shipping": shipping_fee,
                                            "TotalPrice": sub_total_sale_price,
                                            "Subtotal": total_cart_value,
                                            "TotalDiscount": total_discount  # Include total discount in response
                                        }

                                        return Response(response_data, status=status.HTTP_200_OK)


                            elif offer_schedule.offer_type == "SPEND" and offer_schedule.method == "% OFF":
                                print("Offer coming soon for SPEND % OFF")
                                return Response({"message": "offer coming soon"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                            else:
                                print("Offer coming soon for other types")
                                return Response({"message": "offer coming soon"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        else:
                            print("No matched products or allowed discount products")
                            return Response({"message": "offer coming soon"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    except Exception as e:
                        print("An error occurred:", e)
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
                shipping_fee = 60
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
            if otp_instance:
                otp = random.randint(100000, 999999)
                otp_instance.otp = otp
                otp_instance.save()
            else:
                otp = random.randint(100000, 999999)
                OTP.objects.create(user=user, otp=otp)
            
            # Render email template with OTP value
            email_body = render_to_string('otp.html', {'otp': otp})

            # Send email
            send_mail(
                'Your OTP Code',
                '',
                settings.EMAIL_HOST_USER,  
                [email],  
                fail_silently=False,
                html_message=email_body
            )
            return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
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

        offer = OfferSchedule.objects.filter(offer_active=True).first()
        if offer:
            offer_approved_products = list(offer.offer_products.values_list('pk', flat=True))
            offer_approved_category = list(offer.offer_category.values_list('pk', flat=True))

            # Discount approved products and categories
            discount_approved_products = list(offer.discount_approved_products.values_list('pk', flat=True))
            discount_approved_category = list(offer.discount_approved_category.values_list('pk', flat=True))

            products_in_cart = [item.product.pk for item in cart_items]

            matched_product_pks = [product_pk for product_pk in offer_approved_products if product_pk in products_in_cart]
            allowed_discount_products = [product_pk for product_pk in discount_approved_products if product_pk in products_in_cart]

            # Fetch all products that belong to offer-approved categories
            approved_category_products = Product.objects.filter(category__pk__in=offer_approved_category)
            approved_category_product_pks = list(approved_category_products.values_list('pk', flat=True))

            approved_discount_category_products = Product.objects.filter(category__pk__in=discount_approved_category)
            approved_discount_category_product_pks = list(approved_discount_category_products.values_list('pk', flat=True))

            
            if offer.is_active: 
                offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()

                if offer_schedule:
                    # Check if there are matching OfferSchedule objects with specific criteria
                    checking_products_offer_type = OfferSchedule.objects.filter(
                        offer_type=offer_schedule.offer_type,
                        get_option=offer_schedule.get_option,
                        get_value=offer_schedule.get_value,
                        method=offer_schedule.method,
                        offer_active=True
                    ).first()

                    if checking_products_offer_type and checking_products_offer_type.offer_type == "BUY" and checking_products_offer_type.method == "FREE":
                        # Retrieve the buy and get values
                        buy = checking_products_offer_type.get_option
                        get = checking_products_offer_type.get_value

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

                        for item in user_cart:
                            free_quantity = 0
                            if item.product.pk in combined_product_pks:
                                free_quantity = int(item.quantity / buy) * get
                                total_free_quantity += free_quantity

                            total_quantity = int(item.quantity + free_quantity)
                            total_price = item.product.salePrice * item.quantity


                            if item.product.pk in matched_product_pks:
                                offer_products.append(item)
                            if item.product.pk in allowed_discount_products:
                                discount_allowed_products.append(item)

                            # Calculate subtotal and total sale price for each item
                            sub_total_sale_price += item.product.price * item.quantity
                            total_sale_price += item.product.salePrice * item.quantity


                        serializer = CartSerializers(cart_items, many=True)
                        total_discount_after_adjustment = sub_total_sale_price - total_sale_price

                        if total_sale_price <= 500:
                            shipping_fee = 60
                        else:
                            shipping_fee = 0

                        address = Address.objects.filter(pk=pk, user=user).first()
                        if not address:
                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                        coupon_code = request.data.get('coupon_code')
                        coupon = None
                        if coupon_code:
                            try:
                                coupon = Coupon.objects.get(code=coupon_code)
                            except Coupon.DoesNotExist:
                                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

                            if coupon.status != 'Active':
                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                        payment_method = request.data.get('payment_method')
                        if not payment_method:
                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                        if payment_method not in ['COD', 'razorpay']:
                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

                        try:
                            with transaction.atomic():
                                order = Order.objects.create(
                                    customer=user,
                                    address=address,
                                    status='pending',
                                    payment_method=payment_method,
                                )

                                for item in user_cart:
                                    free_quantity = 0
                                    if item.product.pk in combined_product_pks:
                                        free_quantity = int(item.quantity / buy) * get
                                        total_free_quantity += free_quantity

                                    total_quantity = int(item.quantity + free_quantity)
                                    total_price = item.product.salePrice * item.quantity


                                    OrderItem.objects.create(
                                        customer=user,
                                        order=order,
                                        product=item.product,
                                        quantity=item.quantity,
                                        free_quantity=free_quantity,
                                        price=item.product.salePrice,
                                        color=item.color,
                                        size=item.size
                                    )

                                    if item.product.type == "single":
                                        check_color = ProductColorStock.objects.filter(product=item.product, color=item.color)
                                        if check_color is None:
                                            return Response({"message": "Color not found"}, status=status.HTTP_400_BAD_REQUEST)
                                        for stock in check_color:
                                            if stock.stock >= item.quantity:
                                                stock.stock -= item.quantity
                                                stock.save()
                                    else:
                                        product_variants = ProductVariant.objects.filter(product=item.product, color=item.color)
                                        if not product_variants.exists():
                                            return Response({"message": f"No variants found for {item.product.name} - {item.color}"}, status=status.HTTP_404_NOT_FOUND)

                                        for variant in product_variants:
                                            size_stocks = ProductVarientSizeStock.objects.filter(product_variant=variant, size=item.size)
                                            for stock in size_stocks:
                                                if stock.stock >= item.quantity:
                                                    stock.stock -= item.quantity
                                                    stock.save()
                                                    break
                                                else:
                                                    return Response({"message": f"Insufficient stock for {item.product.name} - {item.color} - {item.size}"}, status=status.HTTP_400_BAD_REQUEST)

                                # Apply the coupon if present
                                if coupon:
                                    if coupon.coupon_type == 'Percentage':
                                        discount_amount = (coupon.discount / 100) * total_sale_price
                                        total_sale_price -= discount_amount
                                        order.coupon = coupon
                                    else:
                                        total_sale_price -= coupon.discount
                                        order.coupon = coupon

                                if payment_method == 'COD':
                                    cod_charge = Decimal('40.00')
                                    total_sale_price += cod_charge

                                order.total_amount = total_sale_price
                                order.save()

                                # If payment method is razorpay, create a razorpay order
                                if payment_method == 'razorpay':
                                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                                    razorpay_order = razorpay_client.order.create({
                                        'amount': int(order.total_amount * 100),
                                        'currency': 'INR',
                                        'payment_capture': 1
                                    })

                                    order.payment_id = razorpay_order['id']
                                    order.save()

                                cart_items.delete()
                                serializer = OrderSerializer(order)
                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
                        except Exception as e:
                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                total_cart_value = 0
                for data in cart_items:
                    total_product_value = data.quantity * data.product.salePrice
                    total_cart_value += total_product_value

                if matched_product_pks and allowed_discount_products is not None :
                    offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()
                    if offer_schedule:
                        checking_products_offer_type = OfferSchedule.objects.filter(
                            offer_type=offer_schedule.offer_type,
                            get_option=offer_schedule.get_option,
                            get_value=offer_schedule.get_value,
                            method=offer_schedule.method,
                            offer_active=True
                        ).first()

                        if checking_products_offer_type:
                            if checking_products_offer_type.offer_type == "BUY" and checking_products_offer_type.method == "FREE":
                                buy = checking_products_offer_type.get_option
                                get = checking_products_offer_type.get_value

                                combined_product_pks = set(matched_product_pks).union(set(allowed_discount_products))
                                user_cart = Cart.objects.filter(customer=user, product__in=combined_product_pks)

                                offer_products = []
                                discount_allowed_products = []

                                offer_products_data = Product.objects.filter(pk__in=offer_approved_products)
                                discount_allowed_products_data = Product.objects.filter(pk__in=discount_approved_products)

                                intersection_products = offer_products_data.filter(pk__in=discount_allowed_products_data.values('pk'))

                                if intersection_products.exists():

                                    for item in user_cart:
                                        if item.product in matched_product_pks:
                                            offer_products.append(item.product)
                                        if item.product in allowed_discount_products:
                                            discount_allowed_products.append(item.product)

                                    total_free_quantity = 0
                                    for item in user_cart:
                                        if item.product.pk in matched_product_pks:
                                            free_quantity = (item.quantity) * get
                                        else:
                                            free_quantity = 0
                                        total_quantity = item.quantity + free_quantity
                                        total_price = item.product.salePrice * item.quantity


                                        if item.product.pk in matched_product_pks:
                                            offer_products.append(item)
                                        if item.product.pk in allowed_discount_products:
                                            discount_allowed_products.append(item)

                                    total_sale_price = sum(i.product.salePrice * i.quantity for i in cart_items)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart_items)


                                    if discount_allowed_products:
                                        discount_allowed_products.sort(key=lambda i: i.product.salePrice)
                                        offer_products_in_cart = user_cart.filter(product__in=matched_product_pks)
                                        remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                        total_free_quantity = int(remaining_free_quantity / 2) * get


                                        total_cart_value = total_sale_price

                                        for item in discount_allowed_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0
                                            

                                        serializer = CartSerializers(cart_items, many=True)
                                        shipping_fee = 60 if total_cart_value <= 500 else 0
                                        total_discount_after_adjustment = sub_total_sale_price - total_cart_value


                                        address = Address.objects.filter(pk=pk, user=user).first()
                                        if not address:
                                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                        coupon_code = request.data.get('coupon_code')
                                        coupon = None
                                        if coupon_code:
                                            try:
                                                coupon = Coupon.objects.get(code=coupon_code)
                                            except Coupon.DoesNotExist:
                                                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

                                            if coupon.status != 'Active':
                                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                        payment_method = request.data.get('payment_method')
                                        if not payment_method:
                                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                        if payment_method not in ['COD', 'razorpay']:
                                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

                                        try:
                                            with transaction.atomic():
                                                order = Order.objects.create(
                                                    customer=user,
                                                    address=address,
                                                    status='pending',
                                                    payment_method=payment_method,

                                                )

                                                for item in cart_items:
                                                    if item.product.pk in approved_category_product_pks:
                                                        free_quantity = (item.quantity / buy) * get
                                                    else:
                                                        free_quantity = 0  # Ensure free quantity for non-offer products is zero



                                                    OrderItem.objects.create(
                                                        customer=user,
                                                        order=order,
                                                        product=item.product,
                                                        quantity=item.quantity,
                                                        free_quantity = 0,
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


                                                # Apply the coupon if present
                                                if coupon:
                                                    if coupon.coupon_type == 'Percentage':

                                                        discount_amount = (coupon.discount / 100) * total_cart_value
                                                        total_cart_value -= discount_amount
                                                        order.coupon = coupon
                                                    else :
                                                        total_cart_value -= coupon.discount
                                                        order.coupon = coupon


                                                
                                                if payment_method == 'COD':
                                                    cod_charge = Decimal('40.00')  # Example COD charge
                                                    total_cart_value += cod_charge

                                                order.total_amount = total_cart_value
                                                order.save()

                                                # If payment method is razorpay, create a razorpay order
                                                if payment_method == 'razorpay':
                                                    # Initialize Razorpay client with API credentials
                                                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                                                    
                                                    # Create Razorpay order
                                                    razorpay_order = razorpay_client.order.create({
                                                        'amount': int(order.total_amount * 100),  # Razorpay expects amount in paisa
                                                        'currency': 'INR',
                                                        'payment_capture': 1  # Auto capture payment
                                                    })

                                                    # Update order with Razorpay order ID
                                                    order.payment_id = razorpay_order['id']
                                                    order.save()
                                            


                                                cart_items.delete()

                                                serializer = OrderSerializer(order)
                                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
                                        except Exception as e:
                                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                                else :
                                    for item in user_cart:
                                        if item.product in matched_product_pks:
                                            offer_products.append(item.product)
                                        if item.product in allowed_discount_products:
                                            discount_allowed_products.append(item.product)

                                    total_free_quantity = 0
                                    for item in user_cart:
                                        if item.product.pk in matched_product_pks:
                                            free_quantity = (item.quantity) * get
                                        else:
                                            free_quantity = 0
                                        total_quantity = item.quantity + free_quantity
                                        total_price = item.product.salePrice * item.quantity

                                        if item.product.pk in matched_product_pks:
                                            offer_products.append(item)
                                        if item.product.pk in allowed_discount_products:
                                            discount_allowed_products.append(item)

                                    total_sale_price = sum(i.product.salePrice * i.quantity for i in cart_items)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart_items)

                                    if discount_allowed_products:
                                        discount_allowed_products.sort(key=lambda i: i.product.salePrice)
                                        offer_products_in_cart = user_cart.filter(product__in=matched_product_pks)
                                        remaining_free_quantity = sum(i.quantity for i in offer_products_in_cart)
                                        total_free_quantity = int(remaining_free_quantity) * get

                                        total_cart_value = total_sale_price
                                        for item in discount_allowed_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0

                                        serializer = CartSerializers(cart_items, many=True)
                                        shipping_fee = 60 if total_cart_value <= 500 else 0

                                        address = Address.objects.filter(pk=pk, user=user).first()
                                        if not address:
                                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                        coupon_code = request.data.get('coupon_code')
                                        coupon = None
                                        if coupon_code:
                                            try:
                                                coupon = Coupon.objects.get(code=coupon_code)
                                            except Coupon.DoesNotExist:
                                                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

                                            if coupon.status != 'Active':
                                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                        payment_method = request.data.get('payment_method')
                                        if not payment_method:
                                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                        if payment_method not in ['COD', 'razorpay']:
                                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

                                        try:
                                            with transaction.atomic():
                                                order = Order.objects.create(
                                                    customer=user,
                                                    address=address,
                                                    status='pending',
                                                    payment_method=payment_method,

                                                )

                                                for item in cart_items:
                                                    if item.product.pk in approved_category_product_pks:
                                                        free_quantity = (item.quantity / buy) * get
                                                    else:
                                                        free_quantity = 0  # Ensure free quantity for non-offer products is zero



                                                    OrderItem.objects.create(
                                                        customer=user,
                                                        order=order,
                                                        product=item.product,
                                                        quantity=item.quantity,
                                                        free_quantity = 0,
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


                                                # Apply the coupon if present
                                                if coupon:
                                                    if coupon.coupon_type == 'Percentage':

                                                        discount_amount = (coupon.discount / 100) * total_cart_value
                                                        total_cart_value -= discount_amount
                                                        order.coupon = coupon
                                                    else :
                                                        total_cart_value -= coupon.discount
                                                        order.coupon = coupon


                                                
                                                if payment_method == 'COD':
                                                    cod_charge = Decimal('40.00')  # Example COD charge
                                                    total_cart_value += cod_charge

                                                order.total_amount = total_cart_value
                                                order.save()

                                                # If payment method is razorpay, create a razorpay order
                                                if payment_method == 'razorpay':
                                                    # Initialize Razorpay client with API credentials
                                                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                                                    
                                                    # Create Razorpay order
                                                    razorpay_order = razorpay_client.order.create({
                                                        'amount': int(order.total_amount * 100),  # Razorpay expects amount in paisa
                                                        'currency': 'INR',
                                                        'payment_capture': 1  # Auto capture payment
                                                    })

                                                    # Update order with Razorpay order ID
                                                    order.payment_id = razorpay_order['id']
                                                    order.save()
                                            


                                                cart_items.delete()

                                                serializer = OrderSerializer(order)
                                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
                                        except Exception as e:
                                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        elif checking_products_offer_type.offer_type == "SPEND" and checking_products_offer_type.method == "% OFF":
                            return Response({"message":"SPEND"})
                        else:
                            return Response({"message":"No offer found"})
                    else:
                        return Response({"message":"No matching offer type found"})
                else:

                    offer_schedule = OfferSchedule.objects.filter(offer_active=True).first()
                    if offer_schedule:
                        checking_products_offer_type = OfferSchedule.objects.filter(
                            offer_type=offer_schedule.offer_type,
                            get_option=offer_schedule.get_option,
                            get_value=offer_schedule.get_value,
                            method=offer_schedule.method,
                            offer_active=True
                        ).first()

                        if checking_products_offer_type:
                            if checking_products_offer_type.offer_type == "BUY" and checking_products_offer_type.method == "FREE":
                                buy = checking_products_offer_type.get_option
                                get = checking_products_offer_type.get_value

                                # Combine product pks to fetch the cart items
                                combined_product_pks = set(approved_category_product_pks).union(set(approved_discount_category_product_pks))

                                user_cart = Cart.objects.filter(customer=user, product__in=combined_product_pks)

                                offer_category_products = []
                                discount_allowed_category_products = []

                                offer_category_products__data = Product.objects.filter(category__in=offer_approved_category)
                                discount_allowed_category_products__data = Product.objects.filter(category__in=discount_approved_category)

                                intersection_products = offer_category_products__data.filter(pk__in=discount_allowed_category_products__data.values('pk'))

                                if intersection_products.exists():
                                    for item in user_cart:
                                        if item.product.pk in approved_category_product_pks:
                                            offer_category_products.append(item)
                                        if item.product.pk in approved_discount_category_product_pks:
                                            discount_allowed_category_products.append(item)

                                    total_cart_value = sum(i.product.salePrice * i.quantity for i in cart_items)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart_items)

                                    total_offer_product_quantity = sum(i.quantity for i in offer_category_products)
                                    total_free_quantity = int((total_offer_product_quantity / 2) * get)

                                    if discount_allowed_category_products:
                                        discount_allowed_category_products.sort(key=lambda i: i.product.salePrice)

                                        for item in discount_allowed_category_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0


                                        serializer = CartSerializers(cart_items, many=True)
                                        total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                        shipping_fee = 60 if total_cart_value <= 500 else 0

                                        address = Address.objects.filter(pk=pk, user=user).first()
                                        if not address:
                                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                        coupon_code = request.data.get('coupon_code')
                                        coupon = None
                                        if coupon_code:
                                            try:
                                                coupon = Coupon.objects.get(code=coupon_code)
                                            except Coupon.DoesNotExist:
                                                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

                                            if coupon.status != 'Active':
                                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                        payment_method = request.data.get('payment_method')
                                        if not payment_method:
                                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                        if payment_method not in ['COD', 'razorpay']:
                                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

                                        try:
                                            with transaction.atomic():
                                                order = Order.objects.create(
                                                    customer=user,
                                                    address=address,
                                                    status='pending',
                                                    payment_method=payment_method,

                                                )

                                                for item in cart_items:
                                                    if item.product.pk in approved_category_product_pks:
                                                        free_quantity = (item.quantity / buy) * get
                                                    else:
                                                        free_quantity = 0  # Ensure free quantity for non-offer products is zero

                                                    total_quantity = item.quantity + free_quantity
                                                    total_price = item.product.salePrice * item.quantity


                                                    OrderItem.objects.create(
                                                        customer=user,
                                                        order=order,
                                                        product=item.product,
                                                        quantity=item.quantity,
                                                        free_quantity = 0,
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


                                                # Apply the coupon if present
                                                if coupon:
                                                    if coupon.coupon_type == 'Percentage':

                                                        discount_amount = (coupon.discount / 100) * total_cart_value
                                                        total_cart_value -= discount_amount
                                                        order.coupon = coupon
                                                    else :
                                                        total_cart_value -= coupon.discount
                                                        order.coupon = coupon


                                                
                                                if payment_method == 'COD':
                                                    cod_charge = Decimal('40.00')  # Example COD charge
                                                    total_cart_value += cod_charge

                                                order.total_amount = total_cart_value
                                                order.save()

                                                # If payment method is razorpay, create a razorpay order
                                                if payment_method == 'razorpay':
                                                    # Initialize Razorpay client with API credentials
                                                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                                                    
                                                    # Create Razorpay order
                                                    razorpay_order = razorpay_client.order.create({
                                                        'amount': int(order.total_amount * 100),  # Razorpay expects amount in paisa
                                                        'currency': 'INR',
                                                        'payment_capture': 1  # Auto capture payment
                                                    })

                                                    # Update order with Razorpay order ID
                                                    order.payment_id = razorpay_order['id']
                                                    order.save()
                                            


                                                cart_items.delete()

                                                serializer = OrderSerializer(order)
                                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
                                        except Exception as e:
                                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                                else :
                                    for item in user_cart:
                                        if item.product.pk in approved_category_product_pks:
                                            offer_category_products.append(item)
                                        if item.product.pk in approved_discount_category_product_pks:
                                            discount_allowed_category_products.append(item)

                                    total_cart_value = sum(i.product.salePrice * i.quantity for i in cart_items)
                                    sub_total_sale_price = sum(i.product.price * i.quantity for i in cart_items)

                                    total_offer_product_quantity = sum(i.quantity for i in offer_category_products)
                                    total_free_quantity = int((total_offer_product_quantity) * get)

                                    if discount_allowed_category_products:
                                        discount_allowed_category_products.sort(key=lambda i: i.product.salePrice)

                                        for item in discount_allowed_category_products:
                                            product = item.product
                                            product_price = product.salePrice
                                            product_quantity = item.quantity

                                            if total_free_quantity <= 0:
                                                break

                                            if total_free_quantity >= product_quantity:
                                                discount_amount = product_price * product_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity -= product_quantity
                                            else:
                                                discount_amount = product_price * total_free_quantity
                                                total_cart_value -= discount_amount
                                                total_free_quantity = 0

                                        serializer = CartSerializers(cart_items, many=True)
                                        total_discount_after_adjustment = sub_total_sale_price - total_cart_value
                                        shipping_fee = 60 if total_cart_value <= 500 else 0

                                        address = Address.objects.filter(pk=pk, user=user).first()
                                        if not address:
                                            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

                                        coupon_code = request.data.get('coupon_code')
                                        coupon = None
                                        if coupon_code:
                                            try:
                                                coupon = Coupon.objects.get(code=coupon_code)
                                            except Coupon.DoesNotExist:
                                                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

                                            if coupon.status != 'Active':
                                                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

                                        payment_method = request.data.get('payment_method')
                                        if not payment_method:
                                            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
                                        if payment_method not in ['COD', 'razorpay']:
                                            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

                                        try:
                                            with transaction.atomic():
                                                order = Order.objects.create(
                                                    customer=user,
                                                    address=address,
                                                    status='pending',
                                                    payment_method=payment_method,

                                                )

                                                for item in cart_items:
                                                    if item.product.pk in approved_category_product_pks:
                                                        free_quantity = (item.quantity / buy) * get
                                                    else:
                                                        free_quantity = 0  # Ensure free quantity for non-offer products is zero

                                                    total_quantity = item.quantity + free_quantity
                                                    total_price = item.product.salePrice * item.quantity


                                                    OrderItem.objects.create(
                                                        customer=user,
                                                        order=order,
                                                        product=item.product,
                                                        quantity=item.quantity,
                                                        free_quantity = 0,
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


                                                # Apply the coupon if present
                                                if coupon:
                                                    if coupon.coupon_type == 'Percentage':

                                                        discount_amount = (coupon.discount / 100) * total_cart_value
                                                        total_cart_value -= discount_amount
                                                        order.coupon = coupon
                                                    else :
                                                        total_cart_value -= coupon.discount
                                                        order.coupon = coupon


                                                
                                                if payment_method == 'COD':
                                                    cod_charge = Decimal('40.00')  # Example COD charge
                                                    total_cart_value += cod_charge

                                                order.total_amount = total_cart_value
                                                order.save()

                                                # If payment method is razorpay, create a razorpay order
                                                if payment_method == 'razorpay':
                                                    # Initialize Razorpay client with API credentials
                                                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                                                    
                                                    # Create Razorpay order
                                                    razorpay_order = razorpay_client.order.create({
                                                        'amount': int(order.total_amount * 100),  # Razorpay expects amount in paisa
                                                        'currency': 'INR',
                                                        'payment_capture': 1  # Auto capture payment
                                                    })

                                                    # Update order with Razorpay order ID
                                                    order.payment_id = razorpay_order['id']
                                                    order.save()
                                            


                                                cart_items.delete()

                                                serializer = OrderSerializer(order)
                                                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
                                        except Exception as e:
                                            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                        else:
                            return Response({"message":"No offer found"})
                    else:
                        return Response({"message":"No matching offer type found"})

        
        address = Address.objects.filter(pk=pk, user=user).first()
        if not address:
            return Response({"message": "Address not found"}, status=status.HTTP_404_NOT_FOUND)

        coupon_code = request.data.get('coupon_code')
        coupon = None
        if coupon_code:
            try:
                coupon = Coupon.objects.get(code=coupon_code)
            except Coupon.DoesNotExist:
                return Response({"message": "Invalid coupon code"}, status=status.HTTP_400_BAD_REQUEST)

            if coupon.status != 'Active':
                return Response({"message": "Invalid or inactive coupon"}, status=status.HTTP_400_BAD_REQUEST)

        payment_method = request.data.get('payment_method')
        if not payment_method:
            return Response({"message": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)
        if payment_method not in ['COD', 'razorpay']:
            return Response({"message": "Invalid payment method"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                order = Order.objects.create(
                    customer=user,
                    address=address,
                    status='pending',
                    payment_method=payment_method
                )

                total_amount = 0
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

                # Apply the coupon if present
                if coupon:
                    if coupon.coupon_type == 'percentage':

                        discount_amount = (coupon.discount / 100) * total_amount
                        total_amount -= discount_amount
                        order.coupon = coupon
                    else :
                        total_amount -= coupon.discount



                # Add COD charge if payment method is COD
                if payment_method == 'COD':
                    cod_charge = Decimal('50.00')  # Example COD charge
                    total_amount += cod_charge

                order.total_amount = total_amount
                order.save()

                # If payment method is razorpay, create a razorpay order
                if payment_method == 'razorpay':
                    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(total_amount * 100),  # Razorpay expects amount in paisa
                        'currency': 'INR',
                        'payment_capture': 1  # Auto capture payment
                    })
                    order.payment_id = razorpay_order['id']
                    order.save()

                cart_items.delete()

                serializer = OrderSerializer(order)
                return Response({"message": "Order success", "data": serializer.data}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



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
                serializer = ProductSerializer(offer_products, many=True)
                return Response({"data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No offer schedule found'}, status=status.HTTP_404_NOT_FOUND)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for discount sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FlashSaleProducts(APIView):
    def get(self, request):
        try:
            discount_sale = Product.objects.filter(offer_type="FLASH SALE").order_by('-pk')
            serializer = SubcatecoryBasedProductView(discount_sale, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Product.DoesNotExist:
            return Response({'error': 'No products found for flash sale'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

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


