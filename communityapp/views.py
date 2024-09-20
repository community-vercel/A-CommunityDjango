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
from django.http import HttpResponse

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
from django.shortcuts import get_list_or_404
from django.core.files.base import ContentFile
from django.db.models import Avg, Count

import os

from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


from django.template.loader import render_to_string
from django.db import transaction

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
def test_view(request):
    return HttpResponse("Test view working!")


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


# class CustomLoginView(LoginView):
#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)
#         user = request.user

#         # Add user data and session information to the response
#         response_data = {
#             'user': {
#                 'id': user.id,
#                 'username': user.username,
#                 'email': user.email,
#                 'role':user.role,
#             },
#             'session_key': request.session.session_key,
#             'token': response.data.get('key') 
#         }

class CustomLoginView(LoginView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            
            if response.status_code == status.HTTP_200_OK:
                user = request.user

                # Handle login data
                access_token = response.data.get('access_token')
                refresh_token = response.data.get('refresh_token')
                expires_at = response.data.get('expires_at')
                expires_in = response.data.get('expires_in')
                token_type = response.data.get('token_type')

                # Store tokens and information in session
                request.session['access_token'] = access_token
                request.session['refresh_token'] = refresh_token
                request.session['expires_at'] = expires_at
                request.session['expires_in'] = expires_in
                request.session['token_type'] = token_type

                # Prepare response data
                response_data = {
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'user_metadata': {
                            'email': user.email,
                            'email_verified': user.is_active,
                            'full_name': user.name,
                            'phone_verified': False,
                            'role': user.role,
                        },
                    },
                    'session': {
                        'session_key': request.session.session_key,
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'expires_at': expires_at,
                        'expires_in': expires_in,
                        'token_type': token_type,
                    },
                    'user_meta': {
                        'id': user.id,
                        'role': user.role,
                        'address': user.address,
                    }
                }

                # Add success message and code
                response_data.update({
                    'ErrorCode': 0,
                    'ErrorMsg': 'Login Successfully'
                })

                # Return success response
                return JsonResponse(response_data, status=status.HTTP_200_OK)

            # If login fails (e.g., wrong credentials)
            return JsonResponse({
                'ErrorCode': 1,
                'ErrorMsg': 'Invalid credentials or login failed.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        except ValueError as e:
            # Handle 400 errors (bad request)
            return JsonResponse({
                'ErrorCode': 1,
                'ErrorMsg': f'Bad Request: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Catch any other server-side errors
            return JsonResponse({
                'ErrorCode': 1,
                'ErrorMsg': f'Internal Server Error: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
    userid=request.POST.get('userid')
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
        cover=cover_url,
        user_id=userid
    )

    return JsonResponse({'message': 'Added Successfully', 'category_id': category.id})

    
    
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

@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))

def get_usercategory(request):
    try:
        user_id = request.data.get('user_id')
        
        if not user_id:
            return JsonResponse({
                "ErrorCode": 1,  # Error code
                "ErrorMsg": "user_id parameter is required.",
            })

        categories = Category.objects.filter(user_id=user_id)
        
        # Prepare the data to return
        categories_list = []
        for category in categories:
           
            categories_list.append({
            'id': category.id,
            'name': category.name,
            'thumbnail': category.thumbnail,
            'cover': category.cover,
            })
        
        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": categories_list
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        })

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
            n_tags = form_data.get('b_tags')
            if n_tags:
                tags = n_tags.split(",")  # Convert tags string back to list
            # Remove existing tags for this business
                TagBusiness.objects.filter(business=business).delete()
                # Add new tags
                for tag in tags:
                    TagBusiness.objects.create(business=business, tag=tag.strip())

            # if tags:
            #     TagBusiness.objects.create(business=business, tag=tags)

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
        businesses = Business.objects.filter(isArchived=False).values(
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
@permission_classes((AllowAny,))

def get_businesses_for_user(request):
    try:
        user_id = request.data.get('user_id')
        
        if not user_id:
            return JsonResponse({
                "ErrorCode": 1,  # Error code
                "ErrorMsg": "user_id parameter is required.",
            })

        # Fetch businesses for the specific user
        businesses = Business.objects.filter(user_id=user_id,isArchived=False)
        
        # Prepare the data to return
        business_list = []
        for business in businesses:
            logo_url = business.logo.url if business.logo else None
            images_urls = business.images.split(',') if business.images else []

            business_list.append({
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
                "language": business.language,
                "approved": business.approved,
                "logo": logo_url,
                "images": images_urls,
            })
        
        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": business_list
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
        reviews = Review.objects.filter(business_id=business_id, status='1',isArchived=False).values()
# Retrieve all tags associated with the given business ID
        tags = TagBusiness.objects.filter(business_id=business_id).values_list('tag', flat=True)
        print(tags)
        stats = Review.objects.filter(business_id=business_id, status=Review.APPROVED,isArchived=False).aggregate(
            avg_rating=Avg('rating'),
            total_count=Count('id')
        )

        # Combine average rating and total count into a single object
        statistics = {
            "avg_rating": stats['avg_rating'] if stats['avg_rating'] is not None else 0,
            "total_count": stats['total_count'] if stats['total_count'] is not None else 0
        }
        # Check business approval status
        user_id = request.data.get('user_id')  # You should get user_id from query parameters or authentication context
        user_role = request.data.get('user_role')  # Get the user's role
        
        # if business.approved != "1" and user_id:
        #     if str(business.user_id) == user_id:
        #         approval_status = "not approved but owner"
        #     elif user_role == "1":
        #         approval_status = "system owner"
        #     else:
        #         approval_status = "not approved"
        # else:
        #     approval_status = "approved"
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
                "approved": business.approved,
                "logo": logo_url,
                "images": images_urls,
                "categories": list(categories),
                "reviews": list(reviews),
                "statistics": statistics,
                "tags":list(tags),
            }
        }

        return JsonResponse(response_data)

   

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 2,  # Error code
            "ErrorMsg": str(e),
        })
@api_view(['GET', 'POST'])
def delete_businessimage(request):
    try:
        data = json.loads(request.body)
        image_url = data.get('image_url')
        business_id = data.get('business_id')

        if not image_url or not business_id:
            return JsonResponse({"ErrorCode": 1, "ErrorMsg": "Missing parameters."}, status=400)

        # Remove image from storage
        image_path = image_url.replace("/api/media/", "")
        if default_storage.exists(image_path):
            default_storage.delete(image_path)
        else:
            return JsonResponse({"ErrorCode": 1, "ErrorMsg": "Image not found in storage."}, status=404)

        # Update database
        business = Business.objects.get(id=business_id)
        current_images = business.images.split(",") if business.images else []
        updated_images = [img for img in current_images if img != image_url]
        business.images = ",".join(updated_images)
        business.save()

        return JsonResponse({"ErrorCode": 0, "ErrorMsg": "Image deleted successfully."})

    except Business.DoesNotExist:
        return JsonResponse({"ErrorCode": 1, "ErrorMsg": "Business not found."}, status=404)
    except Exception as e:
        return JsonResponse({"ErrorCode": 1, "ErrorMsg": str(e)}, status=500)

@api_view(['GET', 'POST'])
def update_businessdata(request):
    try:
        if request.method == 'POST':
            # Handle files
            logo = request.FILES.get('logo')
            images = request.FILES.getlist('images')

            # Handle business data
            business_data_json = request.POST.get('businessData')
            if not business_data_json:
                return JsonResponse({
                    "ErrorCode": 1,
                    "ErrorMsg": "Business data is missing."
                }, status=400)
            
            business_data = json.loads(business_data_json)
            business_id = business_data.get('id')
            if not business_id:
                return JsonResponse({
                    "ErrorCode": 1,
                    "ErrorMsg": "Business ID is missing."
                }, status=400)
            
            try:
                business_instance = Business.objects.get(id=business_id)
            except Business.DoesNotExist:
                return JsonResponse({
                    "ErrorCode": 1,
                    "ErrorMsg": "Business not found."
                }, status=404)
            
            # Handle logo
            if logo:
                logo_path = f'business/{business_instance.id}/logo_{logo.name}'
                default_storage.save(logo_path, ContentFile(logo.read()))
                business_instance.logo = logo_path
            
            # Handle images
            image_urls = []
            for img in images:
                image_path = f'business/{business_instance.id}/images_{img.name}'
                default_storage.save(image_path, ContentFile(img.read()))
                image_urls.append(image_path)
            
            business_instance.images = ','.join(image_urls)
            
            # Update business instance with other data
            business_instance.name = business_data.get('name', business_instance.name)
            business_instance.description = business_data.get('description', business_instance.description)
            business_instance.phone = business_data.get('phone', business_instance.phone)
            business_instance.email = business_data.get('email', business_instance.email)
            business_instance.website = business_data.get('website', business_instance.website)
            business_instance.operating_hours = business_data.get('operating_hours', business_instance.operating_hours)
            business_instance.location = business_data.get('location', business_instance.location)
            business_instance.city = business_data.get('city', business_instance.city)
            business_instance.state = business_data.get('state', business_instance.state)
            # business_instance.country = business_data.get('country', business_instance.country) # Uncomment if needed
            business_instance.zip = business_data.get('zip', business_instance.zip)
            business_instance.user_id = business_data.get('user_id', business_instance.user_id)
            business_instance.socials = business_data.get('socials', business_instance.socials)
            business_instance.discount_code = business_data.get('discount_code', business_instance.discount_code)
            business_instance.discount_message = business_data.get('discount_message', business_instance.discount_message)
            business_instance.language = business_data.get('language', business_instance.language)
            


# Handle tags
            # n_tags = business_data.get('tags', [])
            # if isinstance(n_tags, str):
            #     # Convert tags string back to list if it is a string
            #     tags = [tag.strip() for tag in n_tags.split(",") if tag.strip()]
            # elif isinstance(n_tags, list):
            #     # Use tags directly if it's already a list
            #     tags = [tag.strip() for tag in n_tags if tag.strip()]
            # else:
            #     # Default to an empty list if tags is neither a string nor a list
            #     tags = []

            # # Remove existing tags for this business
            # TagBusiness.objects.filter(business=business_instance).delete()

            # # Add new tags
            # for tag in tags:
            #     TagBusiness.objects.create(business=business_instance, tag=tag)

            # Handle tags and categories
            n_tags = business_data.get('tags', [])
            if n_tags:
                tags = n_tags.split(",")  # Convert tags string back to list
            # Remove existing tags for this business
                TagBusiness.objects.filter(business=business_instance).delete()
                # Add new tags
                for tag in tags:
                    TagBusiness.objects.create(business=business_instance, tag=tag.strip())

            
            
            
            categories = business_data.get('categories', [])
            if isinstance(categories, list):
                business_instance.categories = ','.join(map(str, categories))
            else:
                business_instance.categories = ''

            # Save the updated business instance
            business_instance.save()
            
            return JsonResponse({
                "ErrorCode": 0,
                "ErrorMsg": "Business updated successfully."
            })

        else:
            return JsonResponse({
                "ErrorCode": 1,
                "ErrorMsg": "Invalid request method."
            }, status=405)

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e)
        }, status=500)
@api_view(['GET', 'POST'])
def update_businesses(request):
    try:
        update_data = request.data
        
        for data in update_data:
            business_id = data.get('id')
            approved = data.get('approved')
            is_archived = data.get('isArchived')
            is_featured = data.get('isFeatured')
            
            try:
                business = Business.objects.get(id=business_id)
                
                if approved is not None:
                    business.approved = int(approved)
                if is_archived is not None:
                    business.isArchived = is_archived
                if is_featured is not None:
                    business.isFeatured = is_featured
                
                business.save()
            except Business.DoesNotExist:
                return JsonResponse({
                    "ErrorCode": 1,
                    "ErrorMsg": f"Business with ID {business_id} not found.",
                }, status=404)

        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Businesses updated successfully.",
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e),
        }, status=500)

@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def update_business_status(request):
    try:
        approved_status = request.data.get('approved')
        business_id=request.data.get('id')
        if approved_status is None:
            return JsonResponse({
                "ErrorCode": 1,  # Error code
                "ErrorMsg": "Missing 'approved' status.",
            }, status=400)

        # Fetch the business to update
        business = Business.objects.filter(id=business_id).first()
        
        if not business:
            return JsonResponse({
                "ErrorCode": 2,  # Error code
                "ErrorMsg": "Business not found.",
            }, status=404)

        # Update the business status
        business.approved = approved_status
        business.save()

        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Business status updated successfully.",
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)

@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))
def create_review(request):
    try:
        user_id = request.data.get('user_id')
        business_id = request.data.get('business_id')
        title = request.data.get('title')
        review = request.data.get('review')
        rating = request.data.get('rating')
        status = request.data.get('status', 0)  # Default to 0 if not provided
        images = request.data.get('images', []) 
       
        # List of image files
        email=request.data.get('email')
        # Create review
        review_instance = Review.objects.create(
            business_id=business_id,
            user_id=user_id,
            title=title,
            review=review,
            rating=rating,
            status=status,
            email=email
        )

        # Upload images
        if 'images' in request.FILES:
            image_files = request.FILES.getlist('images')
            image_urls = []
            for image in image_files:
                # image_name = f"{review_instance.id}/{image.name}"
                image_name = f'reviews/{review_instance.id}/images_{image.name}'

                image_path = default_storage.save(image_name, ContentFile(image.read()))
                image_url = default_storage.url(image_path)
                image_urls.append(image_url)
            

            # Update review with image URLs
            review_instance.review_files = ",".join(image_urls)
            review_instance.save()

        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Review added successfully.",
            "data": {
                "id": review_instance.id,
                "title": review_instance.title,
                "review": review_instance.review,
                "rating": review_instance.rating,
                "status": review_instance.status,
                "review_files": review_instance.review_files,
            }
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)
        
@api_view(['GET', 'POST'])
@permission_classes((AllowAny,))        
def get_reviews(request):
    try:
        # Retrieve all reviews including related business data
        reviews = Review.objects.filter(isArchived=False).select_related('business').values(
            'id', 'title','user__name','user__id','user__email', 'review','email', 'status','rating', 'review_files', 'created_at',
            'business__id',  
            'business__name'  
        )
        
        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Reviews retrieved successfully.",
            "data": list(reviews)
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)

@api_view(['GET', 'POST'])
def update_reviews(request):
    try:
        update_data = request.data
        
        # Process each review update request
        for review_data in update_data:
            review_id = review_data.get('id')
            status = review_data.get('status')
            is_archived = review_data.get('isArchived')

            # Retrieve the review and update its fields
            review = Review.objects.get(id=review_id)
            if status is not None:
                review.status = int(status)
            if is_archived is not None:
                review.isArchived = is_archived
            
            review.save()
        
        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Reviews updated successfully.",
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)



@api_view(['POST'])
def update_review_data(request):
    try:
        # Get the review data from the request
        review_data_json = request.POST.get('reviewData')
        if not review_data_json:
            return JsonResponse({
                "ErrorCode": 1,
                "ErrorMsg": "Review data is missing."
            }, status=400)
        
        # Parse the review data
        review_data = json.loads(review_data_json)
        review_id = review_data.get('id')
        title = review_data.get('title')
        review = review_data.get('review')
        rating = review_data.get('rating')
        review_files = review_data.get('review_files', '')  # Existing image URLs (comma-separated)

        # Retrieve the review instance
        review_instance = Review.objects.get(id=review_id)

        # Update review details (title, review, rating)
        if title is not None:
            review_instance.title = title
        if review is not None:
            review_instance.review = review
        if rating is not None:
            review_instance.rating = rating

        # Existing image URLs split into a list
        existing_images = review_files.split(",") if review_files else []

        # Handle the new image files from request.FILES (if any)
        image_files = request.FILES.getlist('images')
        new_image_urls = []

        for image in image_files:
            # Save the new image and get its URL
            image_name = f"reviews/{review_instance.id}/images_{image.name}"
            image_path = default_storage.save(image_name, ContentFile(image.read()))
            image_url = default_storage.url(image_path)
            new_image_urls.append(image_url)

        # Combine existing images and new images
        all_images = list(set(existing_images + new_image_urls))  # Use set to avoid duplicates
        review_instance.review_files = ",".join(all_images)  # Store as a comma-separated string

        # Save the updated review instance
        review_instance.save()

        # Return success response
        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Review updated successfully."
        })

    except Review.DoesNotExist:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": "Review not found."
        }, status=404)

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e)
        }, status=500)
@api_view(['GET', 'POST'])
def get_specific_review(request):
    
    review_id=request.data.get('id')
    try:
        # Fetch the review by ID
        review = Review.objects.select_related('business','user').get(id=review_id)

        # Prepare the data for response
        review_data = {
            "id": review.id,
            "title": review.title,
            "rating": review.rating,
            "review": review.review,
            "review_files":review.review_files,
            "status": review.status,
            "email":review.user.username,
            "business": {
                "id": review.business.id,
                "name": review.business.name
            }
        }

        return JsonResponse({
            "data": review_data,
            "status": "success"
        })

    except Review.DoesNotExist:
        return JsonResponse({
            "error": "Review not found",
            "status": "error"
        }, status=404)

    except Exception as e:
        return JsonResponse({
            "error": str(e),
            "status": "error"
        }, status=500)


@csrf_exempt
@transaction.atomic
def delete_review_image(request):
    if request.method == 'POST':
        try:
            review_id = request.POST.get('review_id')
            image_url = request.POST.get('image_url')
            
            if not review_id or not image_url:
                return JsonResponse({"error": "Invalid request data"}, status=400)

            # Extract the image file name from the URL
            image_name = image_url
            print(image_name)

            # Remove the image file from storage
            image_path = os.path.join(settings.MEDIA_ROOT, 'reviews', image_name)
            print(image_path)
            print(os.path)
            if os.path.exists(image_path):
                os.remove(image_path)

            # Update the review record
            review = Review.objects.get(id=review_id)
            print(review)
            current_images = review.review_files.split(",")
            print(current_images)

            updated_images = [img for img in current_images if img != image_name]
            print(updated_images)

            review.review_files = ",".join(updated_images)
            review.save()

            return JsonResponse({"message": "Image deleted successfully"})
        except Review.DoesNotExist:
            return JsonResponse({"error": "Review not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)


@api_view(['GET', 'POST'])
def archive_business(request):
    try:
        # Extract business ID from request data
        business_id = request.data.get('id')
        
        # Retrieve the business and update its isArchived status
        business = Business.objects.get(id=business_id)
        business.isArchived = True
        business.save()

        return JsonResponse({
            "ErrorCode": 0,  # Success code
            "ErrorMsg": "Business archived successfully.",
        })

    except Business.DoesNotExist:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": "Business not found.",
        }, status=404)
    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)



@api_view(['GET', 'POST'])
def get_businesses_by_category(request):
    category_id=request.data.get('id')
    try:
        from_value = int(request.data.get('from', 0))
        to_value = int(request.data.get('to', 10))

        category_businesses = CategoryBusiness.objects.filter(
            category_id=category_id,
            business__approved=True,
            business__isArchived=False
        ).select_related('category', 'business')[from_value:to_value]

        businesses_data = [
                {
                "category_name":cb.category.name,
                "cover":cb.category.cover,

                "business_id": cb.business.id,
                "business_name": cb.business.name,
                "business_approved": cb.business.approved,
                "business_isArchived": cb.business.isArchived,
                "description": cb.business.description,
                "phone": cb.business.phone,
                "email": cb.business.email,
                "website": cb.business.website,
                "operating_hours": cb.business.operating_hours,
                "location": cb.business.location,
                "city": cb.business.city,
                "state": cb.business.state,
                "zip": cb.business.zip,
                "discount_code": cb.business.discount_code,
                "discount_message": cb.business.discount_message,
                "logo": cb.business.logo.url,
                # "images": cb.business.images,
                "language": cb.business.language,
                "isFeatured": cb.business.isFeatured,
                # Add other business fields you need here
                } for cb in category_businesses
                ]

        if not businesses_data:
            return JsonResponse({
                "ErrorCode": 1,
                "ErrorMsg": "No businesses found for this category.",
            })

        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": businesses_data,
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e),
        }, status=500)

@api_view(['GET', 'POST'])
def fetch_more_businesses_by_category(request):
    try:
        # Get data from the request body
        category_id = request.data.get('id')
        from_value = int(request.data.get('from', 0))
        to_value = int(request.data.get('to', 10))

        # Ensure `from_value` and `to_value` are valid
        if from_value < 0 or to_value <= from_value:
            return JsonResponse({
                "ErrorCode": 1,
                "ErrorMsg": "Invalid pagination values.",
            })

        # Fetch businesses for the specified category that are approved and not archived
        category_businesses = CategoryBusiness.objects.filter(
            category_id=category_id,
            business__approved=True,
            business__isArchived=False
        ).select_related('business').order_by('business__id')[from_value:to_value]

        businesses_data = [
            {
            
            "business_id": cb.business.id,
            "business_name": cb.business.name,
            "business_approved": cb.business.approved,
            "business_isArchived": cb.business.isArchived,
            "description": cb.business.description,
            "phone": cb.business.phone,
            "email": cb.business.email,
            "website": cb.business.website,
            "operating_hours": cb.business.operating_hours,
            "location": cb.business.location,
            "city": cb.business.city,
            "state": cb.business.state,
            "zip": cb.business.zip,
            "discount_code": cb.business.discount_code,
            "discount_message": cb.business.discount_message,
            "logo": cb.business.logo.url,
            "language": cb.business.language,
            "isFeatured": cb.business.isFeatured,
            # Add other business fields you need here
            } for cb in category_businesses
            ]


        if not businesses_data:
            return JsonResponse({
                "ErrorCode": 1,
                "ErrorMsg": "No more businesses found.",
            })

        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": businesses_data,
        })

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e),
        }, status=500)
@api_view(['GET', 'POST'])
def get_business_rating_stats(request):
    try:
        # Get the business ID from the request body
        business_id = request.data.get('business_id_param')
        
        # Fetch the business
        business = Business.objects.get(id=business_id)
        
        # Fetch the average rating for this business
        stats = Review.objects.filter(business_id=business_id).aggregate(
                    avg_rating=Avg('rating'),
                    review_count=Count('id')
                )
        # Prepare the business details and stats
        business_data = {
            "id": business.id,
            "name": business.name,
            "description": business.description,
            "logo": business.logo.url if business.logo else None,
            "phone": business.phone,
            "website": business.website,
            "email": business.email,
            "isFeatured": business.isFeatured,  # Ensure this field exists in the model
            "discount_code": business.discount_code,  # Ensure this field exists in the model
            "stats": stats,
            "isFavorite": False,  # Logic to determine if the business is marked as favorite by the user
        }

        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Business details retrieved successfully.",
            "data": business_data
        })


        

    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,  # Error code
            "ErrorMsg": str(e),
        }, status=500)
@api_view(['GET', 'POST'])
def toggle_favorite(request):
    user_id = request.data.get('user_id')
    business_id = request.data.get('business_id')
    
    if not user_id or not business_id:
        return Response({'error': 'user_id and business_id are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = get_object_or_404(User, id=user_id)
        business = get_object_or_404(Business, id=business_id)
        
        favorite, created = Favorite.objects.get_or_create(user=user, business=business)
        
        if not created:
            # If the favorite already exists, delete it
            favorite.delete()
            return Response({'message': 'Favorite removed'}, status=status.HTTP_200_OK)
        else:
            # If the favorite did not exist, it has been created
            return Response({'message': 'Favorite added'}, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'POST']) 
def check_and_toggle_favorite(request):
    try:
        user_id = request.data.get('user_id')
        business_id = request.data.get('business_id')

        if not user_id or not business_id:
            return JsonResponse({'ErrorCode': 1, 'ErrorMsg': 'Invalid data.'}, status=400)

        # Check if the favorite exists
        favorite = Favorite.objects.filter(user_id=user_id, business_id=business_id).first()

        if favorite:
            # If favorite exists, delete it (unfavorite)
            is_favorite = True
        else:
            # If favorite does not exist, create it (favorite)
            is_favorite = False

        return JsonResponse({
            'ErrorCode': 0,
            'ErrorMsg': 'Favorite status toggled successfully.',
            'is_favorite': is_favorite
        })

    except Exception as e:
        return JsonResponse({'ErrorCode': 1, 'ErrorMsg': str(e)}, status=500)
    
@api_view(['GET', 'POST'])
def search_businesses(request):
    if request.method != 'POST':
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": "Invalid request method. Use POST."
        }, status=405)
    
    try:
        data = json.loads(request.body)
        category_id = data.get('category_id')
        selected_state = data.get('state')
        selected_city = data.get('city')
        selected_language = data.get('language')
        selected_rating = data.get('rating')
        discount = data.get('discount') == 'true'
        
        # Base queryset
        queryset = Business.objects.filter(
            approved=True,
            isArchived=False
        )
        
        if category_id:
            queryset = queryset.filter(
                categorybusiness__category_id=category_id
            )
        
        if discount:
            queryset = queryset.exclude(discount_code__isnull=True).exclude(discount_code='')
        
        if selected_language:
            queryset = queryset.filter(language=selected_language)
        
        if selected_state:
            queryset = queryset.filter(state=selected_state)
        
        if selected_city:
            queryset = queryset.filter(city=selected_city)
        
        if selected_rating:
            try:
                selected_rating = int(selected_rating)
            except ValueError:
                return JsonResponse({
                    "ErrorCode": 1,
                    "ErrorMsg": "Invalid rating value.",
                }, status=400)
            
            business_ids_with_rating = Review.objects.filter(
                rating__gte=selected_rating
            ).values_list('business_id', flat=True).distinct()
            
            if business_ids_with_rating:
                queryset = queryset.filter(id__in=business_ids_with_rating)
            else:
                return JsonResponse({
                    "ErrorCode": 0,
                    "ErrorMsg": "No businesses match the criteria.",
                    "data": []
                })
        
        businesses = queryset.values(
            'id', 'name', 'description', 'phone', 'email', 'website', 
            'operating_hours', 'location', 'city', 'state', 'zip', 
            'discount_code', 'discount_message', 'logo', 'images', 
            'language', 'isFeatured'
        )
        
        return JsonResponse({
            "ErrorCode": 0,
            "ErrorMsg": "Businesses retrieved successfully.",
            "data": list(businesses)
        })
    
    except Exception as e:
        return JsonResponse({
            "ErrorCode": 1,
            "ErrorMsg": str(e),
        }, status=500)
        
        
@api_view(['GET', 'POST'])
def get_all_users(request):
    try:
        users = User.objects.exclude(role=User.SUPER_ADMIN)
        
        # Transform the data
        transformed_data = [
            {
                'id': user.id,
                'role': user.role,
                # 'pre_approved': getattr(user, 'pre_approved', False),
                'name': user.name,
                'email': user.email,
            }
            for user in users
        ]

        return JsonResponse({
            'ErrorCode': 0,  # Success code
            'ErrorMsg': 'Users retrieved successfully.',
            'data': transformed_data
        }, status=200)

    except Exception as e:
        return JsonResponse({
            'ErrorCode': 1,  # Error code
            'ErrorMsg': str(e),
        }, status=500)
@api_view(['GET', 'POST'])
def fetch_favorites_for_user(request):
    user_id = request.GET.get('user_id')
    
    if not user_id:
        return JsonResponse({
            'ErrorCode': 1,  # Error code
            'ErrorMsg': 'User ID is required.',
        }, status=400)

    try:
        # Fetch the favorites and related business data
        favorites = Favorite.objects.filter(user_id=user_id,business__isArchived=False).select_related('business')
        favorites_data = [
            {
                'id': favorite.id,
                'user_id': favorite.user_id,
                'business': {
                    'business_id': favorite.business.id,
                    'business_name': favorite.business.name,
                    'description': favorite.business.description,
                    'phone': favorite.business.phone,
                    'email': favorite.business.email,
                    'website': favorite.business.website,
                    'operating_hours': favorite.business.operating_hours,
                    'location': favorite.business.location,
                    'city': favorite.business.city,
                    'state': favorite.business.state,
                    'zip': favorite.business.zip,
                    'discount_code': favorite.business.discount_code,
                    'discount_message': favorite.business.discount_message,
                    'language': favorite.business.language,
                    'approved': favorite.business.approved,
                    'logo': favorite.business.logo.url if favorite.business.logo else None,
                    'images': favorite.business.images.split(',') if favorite.business.images else [],
                    'isFavorite':True
                }
            }
            for favorite in favorites
        ]
        
        return JsonResponse({
            'ErrorCode': 0,  # Success code
            'ErrorMsg': 'Favorites retrieved successfully.',
            'data': favorites_data
        }, status=200)
        
    except Exception as e:
        return JsonResponse({
            'ErrorCode': 1,  # Error code
            'ErrorMsg': str(e),
        }, status=500)


@api_view(['GET', 'POST'])
def category_count_view(request):
    # Fetch all categories
    categories = get_list_or_404(Category)

    # Fetch counts for each category
    category_counts = CategoryBusiness.objects.filter(
      business__isArchived=False,business__approved=True
    ).values('category_id').annotate(count=models.Count('category_id'))

    # Convert category counts to a dictionary
    count_dict = {item['category_id']: item['count'] for item in category_counts}

    # Combine category data with business counts
    data = []
    for category in categories:
        data.append({
            'id': category.id,
            'name': category.name,
            'thumbnail': category.thumbnail,
            'cover': category.cover,
            'business_count': count_dict.get(category.id, 0)
        })

    return JsonResponse(data, safe=False)

@csrf_exempt
def add_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            # Create a new user
            user = User(
                extPosId=data.get('extPosId'),
                name=data.get('name'),
                password=data.get('password'),
                email=data.get('email'),
                username=data.get('email'),
                phone=data.get('phone'),
                gender=data.get('gender'),
                address=data.get('address'),
                role=data.get('role', User.CUSTOMER),  # Default to CUSTOMER if not provided
                status=data.get('status', User.INACTIVE),  # Default to ACTIVE if not provided
                is_first_login=data.get('is_first_login', True),
                is_active=data.get('active', True),
                is_staff=data.get('is_staff', False),
                is_superuser=data.get('is_superuser', False),
                roles=data.get('roles', [])
            )
            user.set_password(data.get('password'))  # Hash the password
            user.save()

            return JsonResponse({'ErrorCode': 0, 'ErrorMsg': 'User created successfully.'})

        except Exception as e:
            return JsonResponse({'ErrorCode': 1, 'ErrorMsg': str(e)})
    
    return JsonResponse({'ErrorCode': 1, 'ErrorMsg': 'Invalid request method.'})


@csrf_exempt
@api_view(['GET', 'POST'])
def update_user(request):
    
    user_id=request.data.get('id')
    user_id2=request.data.get('name')

    print(user_id2)
    if request.method == 'POST':
        try:
            user = User.objects.get(id=user_id)

            # Update user fields
            user.extPosId = request.data.get('extPosId', user.extPosId)
            user.name = request.data.get('name', user.name)
            user.email = request.data.get('email', user.email)
            user.username = request.data.get('username', user.email)
            user.phone = request.data.get('phone', user.phone)
            user.address = request.data.get('address', user.address)
            user.role = request.data.get('role', user.role)
            user.status = request.data.get('status', user.status)
            user.is_first_login =request.data.get('is_first_login', user.is_first_login)
            user.is_active = request.data.get('is_active', user.is_active)
            user.is_staff = request.data.get('is_staff', user.is_staff)
            user.is_superuser = request.data.get('is_superuser', user.is_superuser)
            user.roles = request.data.get('roles', user.roles)

            if 'password' in request.data:
                user.set_password(user.data.get('password'))  # Hash the password if it's being updated

            user.save()

            return JsonResponse({'ErrorCode': 0, 'ErrorMsg': 'User updated successfully.'})

        except User.DoesNotExist:
            return JsonResponse({'ErrorCode': 1, 'ErrorMsg': 'User not found.'})
        except Exception as e:
            return JsonResponse({'ErrorCode': 1, 'ErrorMsg': str(e)})

    return JsonResponse({'ErrorCode': 1, 'ErrorMsg': 'Invalid request method.'})


@api_view(['GET', 'POST'])
def FetchUserDetailsView(request):
    user_id=request.data.get('id')
    try:
        user = get_object_or_404(User, pk=user_id)
        data = {
            'id': user.id,
            "email": user.email,
            "fullname":user.name,
            "name":user.name,
            "phone": user.phone,
            "address": user.address,
            "role": user.role,
            "active": user.is_active,
            "roles":user.roles,
            
        }
        
        return JsonResponse({
            'ErrorCode': 0,  # Success code
            'ErrorMsg': 'User retrieved successfully.',
            'data': data
          
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
