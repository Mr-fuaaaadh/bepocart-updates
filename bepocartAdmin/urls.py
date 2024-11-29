from django.urls import path
from  bepocartAdmin.views import *

urlpatterns = [
    path("register/",AdminRegister.as_view()),
    path("login/",AdminLogin.as_view()),

    path('Bepocart-Banner/',CarousalAdd.as_view()),
    path('Bepocart-Banners/',CarousalView.as_view()),
    path('Bepocart-Banner-delete/<int:pk>/',CarousalDelete.as_view()),
    path('Bepocart-Banner-update/<int:pk>/',CarousalUpdate.as_view()),


    path('Bepocart-Offer-Banner/',OfferBannerAdd.as_view()),
    path('Bepocart-Offer-Banners/',OfferBannerView.as_view()),
    path('Bepocart-Offer-Banner-Delete/<int:pk>/',OfferBannerDelete.as_view()),
    path('Bepocart-Offer-Banner-Update/<int:pk>/',OfferBannerUpdate.as_view()),



    path('Bepocart-category/',CategoryAdd.as_view()),
    path('Bepocart-categories/',Categories.as_view()),
    path('Bepocart-category-delete/<int:pk>/',CategoryDelete.as_view()),
    path('Bepocart-category-update/<int:pk>/',CategoryUpdate.as_view()),


    path('Bepocart-subcategory/',SubcategoryAdd.as_view()),
    path('Bepocart-subcategories/',SubcategoryView.as_view()),
    path('Bepocart-subcategory-update/<int:pk>/',SubcategoryUpdate.as_view()),
    path('Bepocart-subcategory-delete/<int:pk>/',SubcategoryDelete.as_view()),


    path('Bepocart-product/',ProductAdd.as_view()),
    path('Bepocart-products/',ProductView.as_view()),
    path('Bepocart-product-update/<int:pk>/',ProductUpdate.as_view()),
    path('Bepocart-product-delete/<int:pk>/',ProductDelete.as_view()),


    path('Bepocart-Product-image-add/<int:pk>/',ProductImageCreateView.as_view()),
    path('Bepocart-Product-images/<int:pk>/',ProductBasdMultipleImageView.as_view()),
    path('Bepocart-Product-images-delete/<int:pk>/',ProductMultipleImageDelete.as_view()),
    path('Bepocart-Product-images-update/<int:pk>/',ProductMultipleImageUpdate.as_view()),



    path('Bepocart-offer/',AdminOfferCreating.as_view()),
    path('Bepocart-offer-delete/<int:pk>/',AdminSheduledOfferDeleting.as_view()),




    path('Bepocart-Orders/',AllOrders.as_view()),
    path('Bepocart-Order-status-update/<int:pk>/',OrderStatusUpdation.as_view()),
    path('Bepocart-Order-Item/<int:customer>/',AllOrderItems.as_view()),
    path('Bepocart-Order-Bill/<str:order_id>/',OrderInvoiceBillCreating.as_view()),
    path('Bepocart-saled-products/', TotalSaledProductsView.as_view(), name='total-saled-products'),


    path('Bepocart-product-varient/<int:pk>/',VarientProductAdding.as_view()),
    path('Bepocart-product-varient-view/<int:pk>/',VarientProductDataView.as_view()),
    path('Bepocart-product-varient-delete/<int:pk>/',VarientProductSizeDelete.as_view()),
    path('Bepocart-product-varient-update/<int:pk>/',VarientProductDataupdate.as_view()),



    path('Bepocart-promotion-coupen/',AdminCouponCreation.as_view()),
    path('Bepocart-promotion-coupen-views/',AdminCoupensView.as_view()),
    path('Bepocart-promotion-coupen-delete/<int:pk>/',AdminCouponDelete.as_view()),
    path('Bepocart-promotion-coupen-update/<int:pk>/',AdminCouponUpdate.as_view()),

    path('Bepocart-Blog/',AdminBlogCreate.as_view()),
    path('Bepocart-Blogs/',AdminBlogView.as_view()),
    path('Bepocart-Blog-update/<int:pk>/',AdminBlogUpdate.as_view()),
    path('Bepocart-Blog-delete/<int:pk>/',AdminBlogDelete.as_view()),


    path('Bepocart-customers/',AdminCustomerView.as_view()),
    path('Bepocart-customer-delete/<int:pk>/',CustomersDelete.as_view()),
    path('Bepocart-customer-update/<int:pk>/',CustomerUpdate.as_view()),

    path('export-orders/', ExportOrdersToExcel.as_view(), name='export_orders'),

    path('Bepocart-Bcoin/',AdminCoinCreating.as_view()),
    path('Bepocart-coins/',AdminCoinFetching.as_view()),
    path('Bepocart-coin-delete/<int:pk>/',AdminCoinDelete.as_view()),
    path('Bepocart-coin-update/<int:pk>/',AdminCoinUpdate.as_view()),


    path('Bepocart-user-coins/<int:pk>/',AdminCustomerCOinDAtaView.as_view()),

    path('Bepocart-Product-Review/',AdminViewAllProductReviw.as_view()),
    path('Bepocart-approve-review/<int:pk>/', UpdateReviewStatus.as_view(), name='approve-review'),



    
    path("offer-scheduling/",OfferScheduling.as_view()),
    path("offer/",AllOffers.as_view()),

    path('Bepocart-offer/<int:pk>/toggle-status/', toggle_offer_active.as_view(), name='toggle_offer_active'),





















    








]