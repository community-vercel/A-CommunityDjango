from django.urls import path,include
from .views import CustomLoginView

from . import views
urlpatterns = [
    path('registerUser',views.registerUser,name='registerUser'),
    path('addAdmin', views.addAdmin, name = 'addAdmin'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('login/', CustomLoginView.as_view(), name='custom_login'),
    path('add-category/', views.add_category, name='add_category'),
    path('get-categories/', views.get_categories, name='get_categories'),
    path('get-category/', views.get_category, name='get_category'),
    path('update-category/', views.update_category, name='update_category'),



    #  path("google/", GoogleLoginView.as_view(), name = "google"),
    # path('api/auth/password/reset/confirm/<str:uidb64>/<str:token>', PasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    # path('api/auth/password/change/<str:uidb64>/<str:token>', PasswordChangeView.as_view(),name='password_change'),
 
]