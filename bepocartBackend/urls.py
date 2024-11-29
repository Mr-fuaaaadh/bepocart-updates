from django.urls import path
from bepocartBackend.views import *


urlpatterns = [
    path('register/',CustomerRegistration.as_view(), name="customer-register"),
    path('google-login/', GoogleLoginAPIView.as_view(), name='google-login'),
    path('login/',CustomerLogin.as_view(), name="customer-login"),
    path('delete-account/',CustomerDeleteAccount.as_view(), name="customer-delete"),
    path('category/',CategoryView.as_view(), name="category"),
    path('subcategorys/',AllSubCategoryView.as_view(), name="AllSubCategoryView"),
    path('category/<int:pk>/',SubcategoryView.as_view(), name="subcategory"),
    path('products/',CustomerProductView.as_view(), name="product"),
    path('subcategory/<slug:slug>/',SubcategoryBasedProducts.as_view(), name="SubcategoryBasedProducts"),
    path('banners/',CustomerCarousalView.as_view(), name="CustomerCarousalView"),
    path('offer-banner/',CustomerOfferBannerView.as_view(), name="CustomerOfferBannerView"),


    path('categories/', CategoryListView.as_view(), name='category-list'),

    path('wishlist/',CustomerWishlist.as_view(), name="CustomerWishlist"),
    path('add-wishlist/<int:pk>/',CustomerAddProductInWishlist.as_view(), name="Customer-add-Wishlist"),
    path('wishlist-delete/<int:pk>/',CustomerProductDeleteInWishlist.as_view(), name="CustomerProductDeleteInWishlist"),



    path('cart/<int:pk>/',CustomerProductInCart.as_view(), name="CustomerProductInCart"),
    path('cart-products/',CustomerCartProducts.as_view(), name="CustomerCartProducts"),
    path('cart-delete/<int:pk>/',CartProductDelete.as_view(), name="CartProductDelete"),
    path('cart/increment/<int:pk>/', IncrementProductQuantity.as_view(), name='increment-quantity'),
    path('cart/decrement/<int:pk>/', DecrementProductQuantity.as_view(), name='decrement-quantity'),


    path('offer-banner/<int:pk>/products/', OfferBanerBasedProducts.as_view(), name='offer-banner-products'),
    path('product/<slug:slug>/',ProductBigView.as_view(), name="ProductBigView"),
    path('related-products/<slug:slug>/',RelatedProduct.as_view(), name="RelatedProduct"),
    path('category/<slug:slug>/products/',MianCategoryBasedProducts.as_view(), name="MianCategoryBasedProducts"),


    path('reset-password/', UserPasswordReset.as_view(), name='reset-password'),
    path('add-address/', UserAddressAdd.as_view(), name='add-address'),
    path('get-address/', UserAddressView.as_view(), name='get-address'),
    path('update-address/<int:pk>/', UserAddressUpdate.as_view(), name='update-address'),
    path('delete-address/<int:pk>/', UserAddressDelete.as_view(), name='delete-address'),
    path('profile/', UserProfileUpdate.as_view(), name='profile'),
    path('profile-view/', UserProfileView.as_view(), name='UserProfileView'),


    path('offer/', AllOfferpRODUCTS.as_view(), name='profile'),

    path('search-products/', UserSearchProductView.as_view(), name='search-products'),
    path('high-products/<int:pk>/', HighToLowProducts.as_view(), name='high-products'),
    path('low-products/<int:pk>/', LowToHighProducts.as_view(), name='low-products'),


    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),


    path('order/create/<int:pk>/', CreateOrder.as_view(), name='create_order'),
    path('verify-razorpay-payment/', VerifyRazorpayPaymentAPIView.as_view(), name='verify_razorpay_payment'),

    path('offers/', DiscountSaleProducts.as_view(), name='discount-sale'),
    path('best-sale/', BestSellerProductsAPIView.as_view(), name='flash-sale'),
    

    path('orders/', CustomerOrders.as_view(), name='CustomerOrders'),
    path('order-items/<int:pk>/', CustomerOrderItems.as_view(), name='CustomerOrderItems'),
    path('order-items/', CustomerAllOrderItems.as_view(), name='CustomerAllOrderItems'),
    path('product-review/<int:pk>/', CreateProductReview.as_view(), name='CreateProductReview'),
    path('review/<int:pk>/', CustomerProductReviewView.as_view(), name='CustomerProductReviewView'),


    path('recently-viewed/', RecentlyViewedProductsView.as_view(), name='recently-viewed-products'),
    path('recommended/', RecommendedProductsView.as_view(), name='recommended-products'),
    path('filtered-products/<int:pk>/', FilteredProductsView.as_view(), name='filtered-products'),

    path('profile-image/', UserProfileImageSetting.as_view(), name='UserProfileImageSetting'),
    
    path('cupons/', CoupensAll.as_view(), name='CoupensAll'),

    path('blog/',BlogView.as_view(),name="blog"),
    path('coin/',CustomerCoinView.as_view(),name="coin"),


    path('generate-otp/', SendOtpView.as_view(), name='generate-otp'),
    path('verification-otp/', VerifyOtpView.as_view(), name='verify-otp'),


    path('all-products-schema/', AllProductsSchemaAPIView.as_view(), name='all-products-schema'),
    path('product-schema/<slug:slug>/', ProductSchemaAPIView.as_view(), name='product-schema'),



]



















    
