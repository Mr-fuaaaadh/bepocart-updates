from django.db import models
from django.utils import timezone
from bepocartBackend.models import Customer, Order, OrderItem, Coupon
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils.text import slugify



class OfferBanner(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to="offer_banner", max_length=100)

    class Meta :
        db_table = "Offer_Banner"


class Category(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to="category/",max_length=100, null=True)
    slug = models.SlugField(max_length=250,unique=True,null=True)

    
    def __str__(self):
        return self.name

    class Meta:
        db_table = 'category'






class Subcategory(models.Model):
    category = models.ForeignKey(Category, related_name='subcategories', on_delete= models.CASCADE)
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=250,unique=True,null=True)
    image = models.ImageField(max_length=100, upload_to="Subcategory/", null=True)
    
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'Subcategory'


class Carousal(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to="banner", max_length=100)
    slug = models.SlugField(unique=True, blank=True,null=True)
    alt_text = models.CharField(max_length=255, blank=True, null=True, help_text=("Alternative text for the image"))
    category = models.ForeignKey(Subcategory, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta :
        db_table="banner"
    


class Product(models.Model):
    SINGLE = 'single'
    VARIANT = 'variant'
    PRODUCT_TYPE_CHOICES = [
        (SINGLE, 'Single Product'),
        (VARIANT, 'Variant Product'),
    ]
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=250,unique=True,null=True)
    short_description = models.TextField(blank=True, null=True)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2,null=True)
    salePrice = models.DecimalField(max_digits=10, decimal_places=2,null=True)
    category = models.ForeignKey(Subcategory, on_delete=models.CASCADE, related_name='products')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to='products/', blank=True, null=True)
    discount = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)], default=0   )
    type = models.CharField(
        max_length=10,
        choices=PRODUCT_TYPE_CHOICES,
        default=SINGLE,
        null=True
    )

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'product'
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
        ]






class ProductColorStock(models.Model):
    
    product = models.ForeignKey(Product, related_name='color_stocks', on_delete=models.CASCADE)
    color = models.CharField(max_length=100)
    stock = models.PositiveIntegerField()
    image1 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image2 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image3 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image4 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image5 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)



    def __str__(self):
        return f"{self.product.name} - {self.color}"

    class Meta:
        db_table = "ProductColorStock"
        unique_together = ('product', 'color')

class ProductVariant(models.Model):
    product = models.ForeignKey(Product, related_name='variants', on_delete=models.CASCADE)
    color = models.CharField(max_length=100)
    image1 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image2 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image3 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image4 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)
    image5 = models.ImageField(upload_to="products/" ,max_length=200, blank=True)


    def __str__(self):
        return f"{self.product.name} - {self.color}"

    class Meta:
        db_table = "ProductVariant"


class ProductVarientSizeStock(models.Model):
    product_variant = models.ForeignKey(ProductVariant, related_name='size_stocks', on_delete=models.CASCADE)
    size = models.CharField(max_length=100)
    stock = models.PositiveIntegerField()


    def __str__(self):
        return f"{self.product_variant.product.name} - {self.product_variant.color} - {self.size}"

    class Meta :
        db_table = "Size"


class Wishlist(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    class Meta :
        db_table ="Whishlist"


class Cart(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    product =  models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    color = models.CharField(max_length=100,null=True)
    size = models.CharField(max_length=100,null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta :
        db_table = "Cart"


class Blog(models.Model):
    title = models.CharField(max_length=200)
    image = models.ImageField(max_length=100, upload_to="blog")
    content = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.CharField(default="Active",max_length=100)

    def publish(self):
        self.published_at = timezone.now()
        self.save()

    def __str__(self):
        return self.title
    
    class Meta :
        db_table = "Blog"




class Coin(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    amount = models.IntegerField(default=0)
    source = models.CharField(max_length=100) 
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.first_name} - {self.amount} coins from {self.source}"
    
from django.core.exceptions import ValidationError

class CoinValue(models.Model):
    coin = models.IntegerField()
    value = models.FloatField()
    login_value = models.IntegerField(default=10,null=True)
    first_payment_value = models.IntegerField(default=100,null=True)
    payment_value = models.FloatField(null=True) 
    referral_point = models.IntegerField(default=10,null=True)
    review_reward = models.IntegerField(default=10,null=True)
    birthday_reward = models.IntegerField(default=10,null=True)
    anniversary_reward = models.IntegerField(default=10,null=True)
    timestamp = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.coin} - {self.value}"

    def clean(self):
        if CoinValue.objects.exists() and not self.pk:
            raise ValidationError("Only one instance of CoinValue is allowed.")
        if not (0 <= self.payment_value <= 100):
            raise ValidationError("Payment value must be a percentage between 0 and 100.")
        super().clean()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)




class OfferSchedule(models.Model):
    # id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    offer_type = models.CharField(max_length=100, help_text="Select BUY or SPEND")
    amount = models.IntegerField(null=True, blank=True, help_text="Amount for BUY or SPEND")
    get_option = models.IntegerField(null=True, help_text="Option for GET")
    get_value = models.IntegerField(null=True, blank=True, help_text="Free quantity")
    method = models.CharField(max_length=100, help_text="Select FREE or % OFF")
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)], null=True, blank=True, help_text="Discount percentage if method is % OFF")
    offer_products = models.ManyToManyField(Product, related_name='offers', blank=True, help_text="Products eligible for this offer")
    exclude_products = models.ManyToManyField(Product, related_name='exclude_offers', blank=True, help_text="Products excluded from this offer")
    offer_category = models.ManyToManyField(Subcategory, related_name='offers', blank=True, help_text="Categories eligible for this offer")
    excluded_offer_category = models.ManyToManyField(Subcategory, related_name='exclude_offers', blank=True, help_text="Categories excluded from this offer")

    start_date = models.DateTimeField(help_text="Start date of the offer")
    end_date = models.DateTimeField(help_text="End date of the offer")
    offer_active = models.BooleanField(default=False,null=True)

    not_allowed_coupons = models.ManyToManyField(Coupon, blank=True, help_text="Coupons not allowed with this offer")
    messages = models.CharField(max_length=500, null=True, help_text="Additional messages for the offer")
    coupon_user_limit = models.IntegerField(null=True, blank=True, help_text="Maximum usage per user for coupons")
    coupon_use_order_limit = models.IntegerField(null=True, blank=True, help_text="Maximum usage per order for coupons")
    shipping_charge = models.IntegerField(default=0, help_text="Shipping charge applicable with the offer")

    is_active = models.BooleanField(default=True,help_text="Active status of the offer")
    discount_approved_products = models.ManyToManyField(Product, blank=True, related_name='approved_offers', help_text="Products approved for discount")
    discount_not_allowed_products = models.ManyToManyField(Product, blank=True, related_name='not_allowed_offers', help_text="Products not allowed for discount")
    discount_approved_category = models.ManyToManyField(Subcategory, blank=True, related_name='approved_offers', help_text="Categories approved for discount")
    discount_not_allowed_category = models.ManyToManyField(Subcategory, blank=True, related_name='not_allowed_offers', help_text="Categories not allowed for discount")

    def __str__(self):
        return f"Offer {self.pk}"

    class Meta :
        db_table = "Offer Schedule"





class Notification(models.Model):
    message = models.TextField()
    link = models.URLField(null=True, blank=True)  
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Notification for {self.message}"