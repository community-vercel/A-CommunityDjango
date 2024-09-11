from django.urls import path,include
from .views import CustomLoginView

from . import views
urlpatterns = [
    #auth
    path('registerUser',views.registerUser,name='registerUser'),
    path('login/', CustomLoginView.as_view(), name='custom_login'),
    path('update-category/', views.update_category, name='update_category'),
    path('password-reset/', views.forgotPassword, name='password_reset_email'),
    path('confirm-reset/', views.passwordConfirm, name='password_confirm'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),


#admin
    path('addAdmin', views.addAdmin, name = 'addAdmin'),
    path('add-category/', views.add_category, name='add_category'),
    path('get-categories/', views.get_categories, name='get_categories'),
    path('get-category/', views.get_category, name='get_category'),
    path('category-count/', views.category_count_view, name='category-count'),
    path('get-usercategory/', views.get_usercategory, name='usercategory'),
    path('update-businesses/', views.update_businesses, name='update-businesses'),

   #a busineess
    path('create-business/', views.create_business, name='create_business'),
    path('get-business/', views.get_all_businesses, name='get_all_businesses'),
    path('get-specifibusiness/', views.get_business_by_id, name='get_business_by_id'),
    path('get-userbusiness/', views.get_businesses_for_user, name='get_businesses_for_user'),
    path('archive-business/', views.archive_business, name='archive-business'),
    path('update-business-status/', views.update_business_status, name='update-business-status'),

#Reviews    
    
    path('create-review/', views.create_review, name='create-review'),
    path('get-reviews/', views.get_reviews, name='get_reviews_for_business'),
    path('update-reviews/', views.update_reviews, name='update_reviews'),



    #  path("google/", GoogleLoginView.as_view(), name = "google"),
    # path('api/auth/password/reset/confirm/<str:uidb64>/<str:token>', PasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    # path('api/auth/password/change/<str:uidb64>/<str:token>', PasswordChangeView.as_view(),name='password_change'),
 
]