from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.crypto import get_random_string

class MyUserManager(BaseUserManager):
    def create_user(self, email, contact, username, password=None, **extra_fields):
        """
        Creates and saves a User with the given email, contact, name, and password.
        """
        if not contact:
            raise ValueError('The Contact field must be set')
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, contact=contact, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, contact, username, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email, contact, name, and password.
        """
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, contact, username, password, **extra_fields)

class CustomUserIDField(models.CharField):
    def pre_save(self, model_instance, add):
        if add:
            return get_random_string(length=6, allowed_chars='0123456789')
        return super().pre_save(model_instance, add)

class User(AbstractUser):
    id = CustomUserIDField(primary_key=True, max_length=6, editable=False)
    full_name = models.CharField(max_length=150, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    contact = models.CharField(max_length=255, blank=True)
    device_token = models.CharField(max_length=255, blank=True)
    is_registered = models.BooleanField(default=False)
    verify = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    username = models.CharField(max_length=200)
    email = models.EmailField(verbose_name='Email', max_length=255, unique=True)
    origin = models.CharField(max_length=200, null=True, blank=True)
    uid = models.CharField(max_length=200, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)

    # New fields
    date_of_birth = models.DateField(null=True, blank=True)
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    ]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['contact', 'username']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
