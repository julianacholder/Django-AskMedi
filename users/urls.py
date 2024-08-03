from django.urls import path
from .views import RegisterView, LoginView, LogoutView, VerifyEmailView, ChangePasswordView
from .views import RegisterView, LoginView, VerifyOTPView, ResendOTPView
from .views import CurrentUserView
from .views import StoreSummaryAndDiagnosisView, GetSummariesView
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('verify/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('store-summary/', StoreSummaryAndDiagnosisView.as_view(), name='store_summary_and_diagnosis'),
    path('user-summaries/<str:user_id>/', GetSummariesView.as_view(), name='get_summaries'),
    # path('test/', TestView.as_view(), name='test_view'),
]