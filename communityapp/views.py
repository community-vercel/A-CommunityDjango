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
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

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
from django.shortcuts import get_object_or_404


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
    roles = request.data.get('roles', [])  # Get the list of roles (strings)

    logger.info("Request: %s" % (request.data))
    try:
        if User.objects.filter(email=email).exists():
            result = {"ErrorCode": error_codes.ERROR, "ErrorMsg": error_codes.EMAIL_ALREADY_EXIST}
            context.update(result)
        else:
            user = User.objects.create_user(username=email, email=email, password=password, name=name)
            user.is_active = False 
            for role in roles:
                # Check if the role doesn't already exist in user.roles
                if role not in user.roles:
                    user.roles.append({"role": role, "status": "pending"})  # Assuming you add roles as dicts

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

@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def forgotPassword(request):
    email = request.data.get('email')
    user = User.objects.filter(email=email).first()
    
    if not user:
        return JsonResponse({'error': 'User not found'}, status=404)

    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_link = f'http://localhost:3000/update-password?uid={uid}&token={token}'

    send_mail(
        'Password Reset Request',
        f'Click the link to reset your password: {reset_link}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

    return JsonResponse({"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG}, status=200)

@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def passwordConfirm(request):
    # data = json.loads(request.body)
    token = request.data.get('token')
    new_password = request.data.get('newpassword')
    uidb64 = request.data.get('uid')

    if not token or not new_password or not uidb64:
        return JsonResponse({'error': 'Token, new password, and UID are required'}, status=400)

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        return JsonResponse({'error': 'Invalid UID'}, status=400)

    if not default_token_generator.check_token(user, token):
        return JsonResponse({'error': 'Invalid token'}, status=400)

    user.set_password(new_password)
    user.save()

    return JsonResponse({"ErrorCode": error_codes.SUCCESS, "ErrorMsg": error_codes.CREATE_MSG}, status=200)


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

# This decorator ensures only superadmins can access this function
@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def update_role_status(request):
    context = {}
    try:
        user_id=request.data.get('id')
        user = User.objects.get(pk=user_id)

        role_updates = request.data.get('roles', [])  # Get updated roles and statuses from request

        if not role_updates:
            return JsonResponse({"ErrorCode": "ERROR", "ErrorMsg": "No roles provided"}, status=400)

        # Update each role's status
        updated_roles = []
        for role_update in role_updates:
            for existing_role in user.roles:
                if existing_role['role'] == role_update['role']:
                    existing_role['status'] = role_update['status']
            updated_roles.append(existing_role)

        user.roles = updated_roles
        user.save()

        result = {"ErrorCode": "SUCCESS", "ErrorMsg": "Roles updated successfully"}
        context.update(result)
    except User.DoesNotExist:
        context.update({"ErrorCode": "ERROR", "ErrorMsg": "User not found"})
    except Exception as e:
        context.update({"ErrorCode": "ERROR", "ErrorMsg": str(e)})

    return JsonResponse(context, safe=False)


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



@csrf_exempt
def create_business(request):
    if request.method == 'POST':
        try:
            form_data = request.POST
            logo = request.FILES.get('logo')
            images = request.FILES.getlist('images')

            # Extract social media links
            socials = {
                "facebook": form_data.get('b_facebook'),
                "instagram": form_data.get('b_instagram'),
                "youtube": form_data.get('b_youtube'),
                "tiktok": form_data.get('b_tiktok'),
                "twitter": form_data.get('b_twitter'),
            }

            # Create the business object
            business = Business.objects.create(
                name=form_data.get('b_name'),
                description=form_data.get('b_description'),
                phone=form_data.get('b_phone'),
                email=form_data.get('b_email'),
                website=form_data.get('b_website'),
                operating_hours=form_data.get('b_operating_hours'),
                location=form_data.get('b_location'),
                city=form_data.get('b_city'),
                state=form_data.get('b_state'),
                zip=form_data.get('b_zip'),
                discount_code=form_data.get('b_discount_code'),
                discount_message=form_data.get('b_discount_message'),
                user_id=form_data.get('user_id'),
                socials=socials,
                language=form_data.get('b_language'),
                approved=form_data.get('approved') == '1',
            )

            
            categories = request.POST.getlist('categories')
            for category_id in categories:
                CategoryBusiness.objects.create(business=business, category_id=category_id)

            # Add tags
            tags = form_data.get('b_tags')
            if tags:
                TagBusiness.objects.create(business=business, tag=tags)

            # Upload and save logo
            if logo:
                logo_path = f'business/{business.id}/logo_{logo.name}'
                default_storage.save(logo_path, logo)
                business.logo = logo_path
                business.save()

            # Upload and save business images
            image_urls = []
            for img in images:
                image_path = f'business/{business.id}/images_{img.name}'
                default_storage.save(image_path, img)
                image_urls.append(image_path)
            business.images = ','.join(image_urls)
            business.save()

            return JsonResponse({
                "ErrorCode": 0,  # Success code
                "ErrorMsg": "Business created successfully.",
                "data": {
                    # "id": business.id,
                    "name": business.name,
                    # "logo": business.logo,
                    # "images": business.images,
                }
            })

        except Exception as e:
            return JsonResponse({
                "ErrorCode": 1,  # Error code
                "ErrorMsg": str(e),
            })

    return JsonResponse({"error": "Invalid request method"}, status=405)


@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def get_all_businesses(request):
   
    try:
        businesses = Business.objects.all().values(
            'id', 'name', 'description', 'phone', 'email', 'website', 
            'operating_hours', 'location', 'city', 'state', 'zip', 
            'discount_code', 'discount_message', 'user_id', 'socials', 
            'language', 'approved', 'logo', 'images'
        )
        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": list(businesses)
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        })
@api_view(['GET', 'POST'])
def get_business_by_id(request):
    print(request.data)
    print(request)

    business_id=request.data.get('id')
    
    if request.content_type != 'application/json':
                return JsonResponse({
                    "ErrorCode": 1,  # Error code
                    "ErrorMsg": "Unsupported Media Type. Please send JSON.",
                }, status=415)
    try:
        # Retrieve the business object by ID
        business = get_object_or_404(Business, id=business_id)
        
        # Retrieve related data
        categories = CategoryBusiness.objects.filter(business_id=business_id).values('category__id', 'category__name')
        # reviews = Review.objects.filter(business_id=business_id, status='1', isArchived=False).values()
        
        # Check business approval status
        user_id = request.data.get('user_id')  # You should get user_id from query parameters or authentication context
        user_role = request.data.get('user_role')  # Get the user's role
        
        if business.approved != "1" and user_id:
            if str(business.user_id) == user_id:
                approval_status = "not approved but owner"
            elif user_role == "1":
                approval_status = "system owner"
            else:
                approval_status = "not approved"
        else:
            approval_status = "approved"
        logo_url = business.logo.url if business.logo else None
        images_urls = business.images.split(',') if business.images else []

        # Construct the response
        response_data = {
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Business details retrieved successfully.",
            "data": {
                "id": business.id,
                "name": business.name,
                "description": business.description,
                "phone": business.phone,
                "email": business.email,
                "website": business.website,
                "operating_hours": business.operating_hours,
                "location": business.location,
                "city": business.city,
                "state": business.state,
                "zip": business.zip,
                "discount_code": business.discount_code,
                "discount_message": business.discount_message,
                "user_id": business.user_id,
                "socials": business.socials,
                "language": business.language,
                "approved": approval_status,
                "logo": logo_url,
                "images": images_urls,
                "categories": list(categories),
                # "reviews": list(reviews),
            }
        }

        return JsonResponse(response_data)

   

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 2,  # Error code
            "ErrorMsg": str(e),
        })

