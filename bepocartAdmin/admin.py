from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(Customer)
admin.site.register(Product)
admin.site.register(ProductColorStock)
admin.site.register(Cart)
admin.site.register(Version)

