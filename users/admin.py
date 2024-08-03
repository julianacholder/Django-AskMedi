from django.contrib import admin
from .models import CustomUser, VerificationToken, UserSummary

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'fullname', 'gender', 'age', 'is_verified', 'is_staff', 'is_superuser')
    search_fields = ('email', 'username', 'fullname')
    list_filter = ('is_verified', 'is_staff', 'is_superuser')

@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at')
    search_fields = ('user__email', 'token')

@admin.register(UserSummary)
class UserSummaryAdmin(admin.ModelAdmin):
    list_display = ("user_id","summary_content","diagnosis_content", "timestamp" )
