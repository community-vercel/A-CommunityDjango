from django.db import models

from datetime import datetime
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, UserManager, AbstractUser
from django.db import IntegrityError

from django.contrib.auth.hashers import make_password

class User(AbstractBaseUser):

    ACTIVE    = 1
    PENDING   = 2
    INACTIVE  = 3
    DELETED   = 4
    status_choice = ((ACTIVE, "ACTIVE"), (PENDING, "PENDING"), (INACTIVE, "INACTIVE"), (DELETED, "DELETED"))

    MALE    = 1
    FEMALE  = 2
    OTHER   = 3
    gender_choice = ((MALE, "MALE"), (FEMALE, "FEMALE"), (OTHER, "OTHER"))

    SUPER_ADMIN  = 1
    ADMIN        = 2
    CUSTOMER      = 3
    role_choice = ((SUPER_ADMIN, "SUPER_ADMIN"), (ADMIN, "ADMIN"), (CUSTOMER, "CUSTOMER"))

    id               = models.BigAutoField(primary_key=True)
    extPosId         = models.IntegerField(null=True)
    name             = models.CharField(max_length=100, null=True)
    password         = models.CharField(max_length=255, null=True)
    email            = models.CharField(max_length=100, unique=True, null=True)
    username         = models.CharField(max_length=100, unique=True, null=True)
    phone            = models.CharField(max_length=100, null=True)
    mobile           = models.CharField(max_length=100, null=True)
    gender           = models.IntegerField(null=True, choices=gender_choice)
    profile_pic      = models.ImageField(upload_to='users_profile_pics/', default='users_profile_pics/default-user-icon.jpg', null=True)
    address          = models.CharField(max_length=250, null=True)
    membership       = models.IntegerField(null=True)
    points           = models.IntegerField(null=True)
    role             = models.IntegerField(null=False, choices=role_choice, default=CUSTOMER)
    status           = models.IntegerField(null=False, choices=status_choice, default=ACTIVE)
    totp_key         = models.CharField(max_length=128, null=True)
    is_first_login   = models.BooleanField(null=False, default=True) 
    is_active        = models.BooleanField(null=False, default=True) 
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    # roles = models.JSONField(default=list)


    # history = CustomHistoricalRecords()
    objects = UserManager()
    USERNAME_FIELD = 'username'
    class Meta:
        db_table = "auth_user"

    def __str__(self):
        return self.name
    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs) 
        return self
    
    def AddUser(mapping):
        obj = User()
        try:
            for (field, value) in (mapping.items()):
                if value:
                    if field=='password':
                        setattr(obj,field,make_password(value))
                    else:
                        setattr(obj, field,value)
            responseObject = obj.save()
            print('Models')
            print(responseObject)
        except IntegrityError:
            raise
        return responseObject

class Category(models.Model):
    name = models.CharField(max_length=255,unique=True)
    id   = models.BigAutoField(primary_key=True)
    thumbnail = models.URLField(blank=True, null=True)
    cover = models.URLField(blank=True, null=True)