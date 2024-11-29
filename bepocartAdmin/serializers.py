from rest_framework import serializers
from.models import *
from bepocartBackend.models import *
from django.contrib.auth.models import User
from django.db.models import Q
from bepocartBackend.serializers import *

class AdminSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    is_active = serializers.BooleanField(default=True)
    is_superuser = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ['username', 'password', 'password_confirm', 'id', 'email', 'is_active', 'is_superuser']
        extra_kwargs = {
            'password': {'write_only': True},
            'password_confirm': {'write_only': True},
        }

    def validate(self, data):
        """
        Check that the two password entries match.
        """
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')  # Remove the password confirmation field
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        user.is_active = validated_data.get('is_active', True)
        user.is_superuser = validated_data.get('is_superuser', False)
        user.save()
        return user


class AdminLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField()    
    class Meta :
        model = User
        fields = ['email','password']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"

class SubcategoryModelSerializer(serializers.ModelSerializer):
    class Meta :
        model = Subcategory
        fields = "__all__"


class SubcategorySerializer(serializers.ModelSerializer):
    categoryName = serializers.CharField(source ='category.name')
    class Meta :
        model = Subcategory
        fields =  ['id','name','image','category','categoryName','slug']



class SubCategoryUpdateSerializers(serializers.ModelSerializer):
    class Meta :
        model = Subcategory
        fields = "__all__"

class ProductSerializer(serializers.ModelSerializer):
    class Meta :
        model = Product
        fields = "__all__"


class ProductSerializerView(serializers.ModelSerializer):
    categoryName = serializers.CharField(source ='category.name')
    mainCategory = serializers.CharField(source ='category.category.slug')

    class Meta :
        model = Product
        fields = ['id','name','description','short_description','salePrice','category','image','categoryName','mainCategory','price','discount','type','slug']


class CarousalSerializers(serializers.ModelSerializer):
    class Meta :
        model = Carousal
        fields = "__all__"




class OfferBannerSerializers(serializers.ModelSerializer):
    class Meta :
        model = OfferBanner
        fields = "__all__"



class OfferProductSerializers(serializers.ModelSerializer):
    class Meta :
        model = Product
        fields = "__all__"



class CustomerAllProductSerializers(serializers.ModelSerializer):
    categoryName = serializers.CharField(source="category.name")
    mainCategory = serializers.CharField(source ='category.category.slug')
    offer = serializers.SerializerMethodField()
    class Meta :
        model = Product
        fields = ['id','name','short_description','description','price','salePrice','category','image','discount','categoryName','mainCategory','type','offer']

    def get_offer(sel,obj):
        product = obj.id
        category = obj.category

        try:
            # Filter for active offers associated with the specific product or its category all
            offer = OfferSchedule.objects.filter(
                Q(offer_active=True) &
                (Q(offer_products=product) | Q(offer_category=category))
            ).first()
            
            # Check if an offer exists and if its type is "BUY"
            if offer and offer.offer_type == "BUY":
                return f"BUY {offer.get_option} GET {offer.get_value} {offer.method}"
            
            elif  offer and offer.offer_type == "SPEND":
                discount_percentage = int(offer.discount_percentage) if offer.discount_percentage is not None else 0
                return f"{offer.offer_type}   {offer.amount}   {discount_percentage}   {offer.method}"
            # Default return value if no matching offer is found
            return None
        
        except Exception as e:
            return None





class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    
    
class AdminOrderSerializers(serializers.ModelSerializer):
    class Meta :
        model = Order
        fields = "__all__"


# class AdminOrderViewsSerializers(serializers.ModelSerializer):
#     customerImage = serializers.ImageField(source ='customer.image')
#     customerName  = serializers.CharField(source ='customer.username')
#     # name = serializers.CharField(source='coupon.code')
#     class Meta :
#         model = Order
#         fields = ['id','customer','total_amount','created_at','updated_at','status','address','customerImage','customerName','coupon']

class AdminOrderItemSerializers(serializers.ModelSerializer):
    class Meta :
        model = OrderItem
        fields = "__all__"

class AdminOrderViewsSerializers(serializers.ModelSerializer):
    customerImage = serializers.ImageField(source='customer.image')
    customerName = serializers.CharField(source='customer.first_name')
    couponName = serializers.SerializerMethodField() 
    couponType = serializers.SerializerMethodField() 
    address = serializers.CharField(source='address.address')
    phone = serializers.IntegerField(source="customer.phone")
    city = serializers.CharField(source="address.city")
    state = serializers.CharField(source="address.state")
    pincode = serializers.IntegerField(source="address.pincode")
    order_items = CustomerAllOrderSerializers(many=True, read_only=True)


    class Meta:
        model = Order
        fields = [
            'id', 'customer', 'total_amount', 'created_at','coupon' ,'order_id','phone','city','state','pincode',
            'updated_at', 'status', 'address', 'customerImage', 
            'customerName', 'couponName', 'couponType', 'payment_method', 'payment_id','razorpay_order_id','created_time','order_items'
        ]
    def get_couponName(self, obj):
        return obj.coupon.code if obj.coupon else None  # Return the coupon code or None

    def get_couponType(self, obj):
        return obj.coupon.coupon_type if obj.coupon else None 





# class ProductSizeSerializers(serializers.ModelSerializer):
#     class Meta :
#         model = Size
#         fields = "__all__"



class AdminCoupenSerializers(serializers.ModelSerializer):
    start_date = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')
    end_date = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')
    class Meta :
        model = Coupon
        fields = "__all__"



class AdminallCoupenSerializers(serializers.ModelSerializer):
    category  = serializers.CharField(source ='discount_category.name')
    class Meta :
        model = Coupon
        fields = ['id','code','coupon_type','discount','start_date','end_date','status','max_uses','used_count','discount_product','discount_category','category']



class BlogSerializers(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = "__all__"


class AdminCustomerViewSerilizers(serializers.ModelSerializer):
    class Meta :
        model = Customer
        fields ="__all__"


class OrderInvoiceBillSerializer(serializers.ModelSerializer):
    customerImage = serializers.ImageField(source='customer.image')
    customerName = serializers.CharField(source='customer.first_name')
    lastName = serializers.CharField(source='customer.last_name')
    address = serializers.CharField(source='address.address')
    email = serializers.CharField(source='address.email')
    phone = serializers.CharField(source='address.phone')
    pincode = serializers.CharField(source='address.pincode')
    city = serializers.CharField(source='address.city') 
    state = serializers.CharField(source='address.state')    
    couponName = serializers.SerializerMethodField() 
    couponType = serializers.SerializerMethodField()  
    coupon_value = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            'id', 'customer', 'total_amount', 'created_at','coupon' ,'order_id','free_quantity',
            'updated_at', 'status', 'address', 'customerImage', 
            'customerName', 'couponName', 'couponType', 'payment_method', 'payment_id','lastName','address','email','phone','pincode','city','state','coupon_value'
        ]

    def get_coupon_value(self, obj):
        return obj.coupon.discount if obj.coupon else None  # Return the coupon discount value or None


    def get_couponName(self, obj):
        return obj.coupon.code if obj.coupon else None  # Return the coupon code or None

    def get_couponType(self, obj):
        return obj.coupon.coupon_type if obj.coupon else None 




class CoinModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoinValue
        fields = "__all__"



class AdminCustomerCoinSerializer(serializers.ModelSerializer):
    firstName = serializers.CharField(source='user.first_name')
    lastName = serializers.CharField(source='user.last_name')

    class Meta:
        model = Coin
        fields = ['id','user','amount','timestamp','source','firstName','lastName']



class AdminProductReviewSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(source='user.image')
    product_image = serializers.ImageField(source='product.image')
    product_name = serializers.CharField(source='product.name')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')


    class Meta :
        model = Review
        fields = ['id','user','product','rating','review_text','status','created_at','image','product_image','first_name','last_name','product_name']




# class ProductVarientModelSerilizers(serializers.ModelSerializer):
#     color_name = serializers.CharField(source="color.color")
#     class Meta:
#         model = Productverient
#         fields = ["id","color","size","stock","color_name"]


# class ProductVarientColorAddin(serializers.ModelSerializer):
#     class Meta:
#         model = Productverient
#         fields = "__all__"



# class ColorAndSizeSerilizers(serializers.ModelSerializer):
#     class Meta:
#         model = Productverient
#         fields = "__all__"


class ProductImageVarientModelSerilizers(serializers.ModelSerializer):
    productImage = serializers.ImageField(source="product_variant.product.image")
    class Meta:
        model = ProductVarientSizeStock
        fields = ["id","product_variant","size","stock","productImage"]


class OfferProductModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = OfferSchedule
        fields = "__all__"
        
class BestSellerProductSerializer(serializers.ModelSerializer):
    total_sold = serializers.IntegerField(read_only=True)
    sale = serializers.SerializerMethodField()
    mainCategory = serializers.CharField(source ='category.category.slug')


    class Meta:
        model = Product
        fields = ['id', 'name', 'slug', 'salePrice', 'discount', 'image', 'price', 'total_sold', 'sale','mainCategory']

    def get_sale(self, obj):
        return "popular"