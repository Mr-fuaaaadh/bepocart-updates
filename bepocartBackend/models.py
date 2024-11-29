from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from bepocartAdmin.models import *
from django.utils import timezone
import uuid
from django.core.validators import RegexValidator
from bepocartAdmin.models import *

current_time = timezone.now()

class Customer(models.Model):
    phone_regex = RegexValidator(
        regex=r'^\d+$',
        message="Phone number must contain only digits."
    )
    
    first_name = models.CharField(max_length=100, null=True, blank=False)
    last_name = models.CharField(max_length=100, null=True, blank=False)
    email = models.EmailField(max_length=100, unique=True,null=True, blank=True)
    phone = models.CharField(validators=[phone_regex], max_length=15, unique=True, null=True, blank=True)
    image = models.ImageField(max_length=100, upload_to='UserProfile', null=True)
    place = models.CharField(max_length=100, null=True, blank=False)
    zip_code = models.CharField(max_length=6, null=True, blank=False)
    password = models.CharField(max_length=100, null=True)

    def save(self, *args, **kwargs):
        # Clean the phone field: Remove non-numeric characters
        if self.phone:
            self.phone = ''.join(filter(str.isdigit, self.phone))
        
        # Hash the password if it's a new customer or password is being changed
        if not self.pk or self._state.adding or self.password != Customer.objects.get(pk=self.pk).password:
            self.password = make_password(self.password)
        
        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    class Meta:
        db_table = "customer"



class Address(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    address =  models.CharField(max_length=250)
    email = models.CharField(max_length=250)
    phone = models.CharField(max_length=10)
    pincode = models.IntegerField()
    city = models.CharField(max_length=250)
    state = models.CharField(max_length=250)


    class Meta :
        db_table = "Address"



class OTP(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)

    class Meta :
        db_table = "OTP"







class RecentlyViewedProduct(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    product = models.ForeignKey('bepocartAdmin.Product', on_delete=models.CASCADE)
    viewed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'product')
        ordering = ['-viewed_at']




class Coupon(models.Model):
    code = models.CharField(max_length=20, unique=True)
    coupon_type = models.CharField(max_length=20, default='Percentage')
    discount = models.DecimalField(max_digits=10, decimal_places=2) 
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    status = models.CharField(max_length=20, default='Active')  
    max_uses = models.IntegerField(default=1) 
    used_count = models.IntegerField(default=0)
    discount_product = models.ManyToManyField('bepocartAdmin.Product', blank=True)
    discount_category = models.ManyToManyField('bepocartAdmin.Subcategory', blank=True)

    def __str__(self):
        return self.code

    def is_valid(self):
        return (
            self.status == 'Active' and
            self.used_count < self.max_uses and
            self.start_date <= timezone.now().date() <= self.end_date
        )
    
    class Meta:
        db_table = "Coupon"

    def apply_coupon(self, order_total, products=None):
        if not self.is_valid():
            return order_total, False

        if self.discount_product.exists() and (not products or not any(p in self.discount_product.all() for p in products)):
            return order_total, False

        if self.discount_category.exists() and (not products or not any(p.category in self.discount_category.all() for p in products)):
            return order_total, False

        if self.coupon_type.lower() == 'percentage':
            discount_amount = (self.discount / 100) * order_total
        else:
            discount_amount = self.discount

        new_total = max(order_total - discount_amount, 0)
        self.used_count += 1  
        self.save()  
        return new_total, True
    
class Order(models.Model):
    order_id = models.CharField(max_length=50, null=True, unique=True, editable=False)
    customer = models.ForeignKey('Customer', on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    created_time = models.TimeField(auto_now_add = True,blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=50)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    shipping_charge = models.IntegerField(default=0,null=True)
    cod_charge = models.IntegerField(default=0,null=True)
    address = models.ForeignKey(Address, on_delete=models.CASCADE)
    coupon = models.ForeignKey('Coupon', on_delete=models.CASCADE, null=True)
    payment_method = models.CharField(max_length=50, null=True)
    payment_id = models.CharField(max_length=100, null=True)
    razorpay_order_id = models.CharField(max_length=500,  null=True)
    free_quantity = models.PositiveBigIntegerField(default=0, null=True)
    
    
    def generate_order_id(self):
        date_str = timezone.now().strftime('%Y%m%d')
        unique_id = uuid.uuid4().hex[:6].upper()  # Generate a random unique identifier
        return f'{date_str}-{unique_id}'

    def save(self, *args, **kwargs):
        if not self.order_id:
            self.order_id = self.generate_order_id()
        if self.created_time is None:
            self.created_time = timezone.now().time()  # Set the current time if not provided
        super(Order, self).save(*args, **kwargs)

    def __str__(self):
        return self.order_id
    

    class Meta :
        db_table = "Order"





class OrderItem(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE,null=True)
    order = models.ForeignKey(Order, related_name='order_items', on_delete=models.CASCADE)
    product = models.ForeignKey('bepocartAdmin.Product', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True,null=True,blank=False)
    color = models.CharField(max_length=20,null=True)
    size = models.CharField(max_length=100, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    offer_type =models.CharField(max_length=100, null=True, default="none")

    def total_price(self):
        return self.price * self.quantity
    

class Review(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    product = models.ForeignKey('bepocartAdmin.Product', on_delete=models.CASCADE)
    rating = models.IntegerField(choices=[(i, str(i)) for i in range(1, 6)])
    review_text = models.TextField()
    status = models.CharField(default="Processing", max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Review of {self.product.name} by {self.user.first_name}'
    

    class Meta :
        db_table = "Review"
