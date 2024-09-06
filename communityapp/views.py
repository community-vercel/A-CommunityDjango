from django.shortcuts import render
from rest_framework.permissions import AllowAny,IsAuthenticated
from communityapp.serializers import *
from rest_framework import generics, filters
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import viewsets
from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
from functools import wraps
import json

from django.core.files.storage import default_storage

from rest_framework.decorators import api_view , permission_classes
from django.forms.models import model_to_dict
from rest_framework.generics import GenericAPIView
import logging
from django.utils.encoding import force_bytes
from communityapp.codes import error_codes
logger = logging.getLogger(__name__)
from django.shortcuts import render, redirect
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model


from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


from django.template.loader import render_to_string

from django.contrib.sites.shortcuts import get_current_site
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.tokens import default_token_generator
from dj_rest_auth.views import LoginView

# from django.core.mail import send_mail
# from django.utils.crypto import get_random_string
# from django.urls import reverse

    # Allows access only to super admin users.

from rest_framework.permissions import BasePermission

    # Allows access only to super admin users.

class IsSuperAdmin(BasePermission):
    # Allows access only to super admin users.
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 1

def is_admin(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if request.user.id is None:
            status = {'ErrorCode': error_codes.ERROR, 'ErrorMsg': error_codes.LOGIN_REQ_MSG}
            logger.info("%s " %(str(status)))
       
            return JsonResponse(status)
        else:
            user = None
            try:
                user = User.objects.get(id=request.user.id, status=User.ACTIVE, role__in=[User.SUPER_ADMIN,User.ADMIN])
            except User.DoesNotExist:
                pass

            if user:
                return view(request, *args, **kwargs)
            else:
                status = {'ErrorCode': error_codes.ERROR, 'ErrorMsg': error_codes.RSTRCTD_CALL_MSG}
                logger.info("%s " %('userID = '+str(request.user.id)+' reponse : '+str(status)))
                return JsonResponse(status)          
    return wrapper



@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def registerUser(request):
    context = {}
    name = request.data.get('name')
    email = request.data.get('email')
    password = request.data.get('password')
    roles = request.data.get('roles',[])  # Get the list of roles

    logger.info("Request: %s" % (request.data))
    try:
        if User.objects.filter(email=email).exists():
            result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.EMAIL_ALREADY_EXIST}
            context.update(result)
        else:
            user = User.objects.create_user(username=email, email=email, password=password, name=name)
            user.is_active = False 
            # user.roles = ','.join(roles)  
            user.save()
            
            # Send confirmation email
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            # current_site = get_current_site(request)
            current_site="127.0.0.1:8000"
            print("current site ")
            print(current_site)
            mail_subject = 'Activate your account'
            message = f"""
            Hi {user.username},

            Thank you for registering. Please click the link below to activate your account:

            http://{current_site}/activate/{uid}/{token}/

            Best regards,
            The Team
            """
            print(message)
            send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            # message = render_to_string('html/acc_active_email.html', {
            #     'user': user,
            #     'domain': current_site.domain,
            #     'uid': uid,
            #     'token': token,
            # })
            # print("message+ $message")
            # print(message)
            # send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])

            result = {"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG}
            context.update(result)
    except Exception as e:
        result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.NOT_ADD_MSG}
        context.update(result)
        logger.error("Exception in registerUser: %s " % (str(e)))

    return JsonResponse(context, safe=False)


# Create your views here.
# @api_view(['GET', 'POST'])
# @permission_classes((AllowAny,))
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('http://localhost:3000/login')  # Redirect to login page after activation
    else:
        return render(request, 'activation_invalid.html')


class CustomLoginView(LoginView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = request.user

        # Add user data and session information to the response
        response_data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role':user.role,
            },
            'session_key': request.session.session_key,
            'token': response.data.get('key') 
        }

        return Response(response_data, status=status.HTTP_200_OK)
class CustomLoginView(LoginView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == status.HTTP_200_OK:
            logger.debug(f"Login response data: {response.data}")
            print(f"Login response data: {response.data}")
            # Assume response.data contains the tokens and related information
            access_token = response.data.get('access_token')
            refresh_token = response.data.get('refresh_token')
            expires_at = response.data.get('expires_at')
            expires_in = response.data.get('expires_in')
            token_type = response.data.get('token_type')

            # Store these tokens and information in the session
            request.session['access_token'] = access_token
            request.session['refresh_token'] = refresh_token
            request.session['expires_at'] = expires_at
            request.session['expires_in'] = expires_in
            request.session['token_type'] = token_type

            # Add user data and session information to the response
            user = request.user
            response_data = {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role':user.role,
                     'user_metadata': {
            "email":user.email,
            "email_verified": user.is_active,
            "full_name": user.name,
            "phone_verified": False,
            'role':user.role,
           
        }
                },
               'session':{
                 'session_key': request.session.session_key,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_at': expires_at,
                'expires_in': expires_in,
                'token_type': token_type
               },
               'user_meta':{
 
'id': user.id,
 'role': user.role, 
 'address':user.address

               }
            }

            return Response(response_data, status=status.HTTP_200_OK)

        return response
# Create your views here.
# @api_view(['GET', 'POST'])
# @permission_classes((AllowAny,))
# def registerUser(request):
#     context = {}
#     name=request.data['name']
#     email=request.data['email']
#     password=request.data['password']
#     # phone=request.data['phone']
#     # address=request.data['address']
#     logger.info("Request: %s" %(request.data))
#     try:
#         if(User.objects.filter(email=email).exists()):
#             result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.EMAIL_ALREADY_EXIST}
#             context.update(result)
#         else:
#             createuser = User.objects.create(username=email,email=email,password=make_password(password),
#             # ,phone=phone,address=address,name=name
#             )
#             result = {"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG}
#             context.update(result)
           
#     except Exception as e:
#         result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.NOT_ADD_MSG}
#         context.update(result)
#         logger.error("Exception in registerUser: %s " %(str(e)))
#             # traceback.print_exc()
#     # print(context)
#     return JsonResponse(context, safe=False)




# def registerUser(request):
#     context = {}
#     name = request.data['name']
#     email = request.data['email']
#     password = request.data['password']
#     logger.info("Request: %s" % (request.data))
#     try:
#         if User.objects.filter(email=email).exists():
#             result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.EMAIL_ALREADY_EXIST}
#             context.update(result)
#         else:
#             user = User.objects.create(
#                 username=email,
#                 email=email,
#                 password=make_password(password),
#                 is_active=False  # Set to False until email is confirmed
#             )
#             # Generate a unique token for email confirmation
#             token = get_random_string(length=32)
#             user.totp_key = token
#             user.save()

#             # Construct the email confirmation link
#             confirmation_url = request.build_absolute_uri(
#                 reverse('confirm_email') + f"?token={token}&email={email}"
#             )

#             # Send the email
#             send_mail(
#                 'Confirm your email address',
#                 f'Hi {name},\n\nPlease confirm your email address by clicking the following link:\n\n{confirmation_url}\n\nThank you!',
#                 'noreply@example.com',
#                 [email],
#                 fail_silently=False,
#             )

#             result = {"ErrorCode": error_codes.SUCCESS, "ErrorMsg": "Please check your email to confirm your registration."}
#             context.update(result)
           
#     except Exception as e:
#         result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.NOT_ADD_MSG}
#         context.update(result)
#         logger.error("Exception in registerUser: %s " % (str(e)))
#     return JsonResponse(context, safe=False)


# from django.shortcuts import render
# from django.http import HttpResponse
# from django.contrib.auth import get_user_model

# User = get_user_model()

# def confirm_email(request):
#     token = request.GET.get('token')
#     email = request.GET.get('email')
#     try:
#         user = User.objects.get(email=email, totp_key=token)
#         if user:
#             user.is_active = True  # Activate the user
#             user.totp_key = None  # Clear the token
#             user.save()
#             return HttpResponse("Your email has been confirmed. You can now log in.")
#     except User.DoesNotExist:
#         return HttpResponse("Invalid confirmation link or the email has already been confirmed.")

#     return HttpResponse("An error occurred during email confirmation.")


@api_view(['GET', 'POST'])
@permission_classes((IsAuthenticated,))
@is_admin
@csrf_exempt
def addAdmin(request):
        context = {}
        valueDict = request.data['valueDict']
        logger.info("Request %s" %(str(request.data)))
        try:
            if(User.objects.filter(email=valueDict['email']).exists()):
                result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.EMAIL_ALREADY_EXIST}
                context.update(result)
            else:
                obj = User()
                for (field, value) in (valueDict.items()):
                    if value:
                        if field=='password':
                            setattr(obj,field,make_password(value))
                        else:
                            setattr(obj, field,value)
                setattr(obj,'username',valueDict['email'])
                responseObject = obj.save()
                userSerialized = UserSerializer(responseObject).data
                result = {"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG, "Add Admin":userSerialized}
                context.update(result)
                logger.info("%s" %(str(userSerialized)))
        except Exception as e:
            result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.NOT_ADD_MSG}
            context.update(result)
            print("Exception in Add Admin View ", str(e))
            logger.error("Exception in addAdmin: %s " %(str(e)))
            # traceback.print_exc()
        return JsonResponse(context, safe=False)
@api_view(['GET', 'POST'])
# @permission_classes((IsAuthenticated,))

def add_category(request):
    name = request.POST.get('category')
    thumbnail_file = request.FILES.get('thumbnail')
    cover_file = request.FILES.get('cover')

    if not name:
        return JsonResponse({'error': 'Category name is required'}, status=400)
    
    if Category.objects.filter(name=name).exists():
        return JsonResponse({'error': 'Category already exists'}, status=400)
    
    # Handle file uploads
    thumbnail_url = ''
    cover_url = ''
    if thumbnail_file:
        thumbnail_url = default_storage.save(f'category-images/{thumbnail_file.name}', thumbnail_file)
    if cover_file:
        cover_url = default_storage.save(f'category-images/{cover_file.name}', cover_file)
    
    # Create a new Category
    category = Category.objects.create(
        name=name,
        thumbnail=thumbnail_url,
        cover=cover_url
    )

    return JsonResponse({'message': 'Added Successfully', 'category_id': category.id})

    name = request.POST.get('category')
    thumbnail_url = request.POST.get('thumbnail')
    cover_url = request.POST.get('cover')

    if not name:
        return JsonResponse({'error': 'Category name is required'}, status=400)
    
    if Category.objects.filter(name=name).exists():
        return JsonResponse({'error': 'Category already exists'}, status=400)
    
    # Create a new Category
    category = Category.objects.create(
        name=name,
        thumbnail=thumbnail_url,
        cover=cover_url
    )

    return JsonResponse({"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG})
    
@api_view(['GET', 'POST'])
def get_categories(request):
    categories = Category.objects.all().values('id', 'name', 'thumbnail', 'cover')
    return JsonResponse(list(categories), safe=False)
@api_view(['GET', 'POST'])
def get_category(request):

    category_id=request.data.get('category_id')
    print("data id")
    print(category_id)
    try:
        category = Category.objects.get(id=category_id)
        data = {
            'id': category.id,
            'name': category.name,
            'thumbnail': category.thumbnail,
            'cover': category.cover,
        }
        print("data")
        print(data)
        return JsonResponse({"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG,'data':data})
    except Category.DoesNotExist:
        return JsonResponse({"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG})
@api_view(['GET', 'POST'])
def update_category(request):
    category_id = request.data.get('category_id')
    
    try:
        category = Category.objects.get(id=category_id)
        
        # Handle name field update
        if 'name' in request.data:
            category.name = request.data['name']
        
        # Handle file uploads
        if 'thumbnail' in request.FILES:
            category.thumbnail =  default_storage.save(f'category-images/{request.FILES['thumbnail'].name}', request.FILES['thumbnail'])

        
        if 'cover' in request.FILES:
            category.cover = default_storage.save(f'category-images/{request.FILES['cover'].name}', request.FILES['cover'])

        
        # Save the updated category
        category.save()
        
        return JsonResponse({'message': 'Category updated successfully'})
    
    except Category.DoesNotExist:
        return JsonResponse({'error': 'Category not found'}, status=404)
    