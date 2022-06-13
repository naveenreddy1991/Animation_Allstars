from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (RegisterView, 
                    VerifyEmail, 
                    LoginView, 
                    PasswordTokenCheckApi,
                    RequestPasswordResetEmail, 
                    SetNewPasswordAPIView,
                    IdeasViewAPI,
                    CommentAPIView,
                    IdeaFeedbackAPIView)
from django.urls import path

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmail.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-rest-email/', RequestPasswordResetEmail.as_view(), name="request-rest-email"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckApi.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name="password-reset-complete"),
    # path('user-idea/', UserIdeaViewAPI.as_view(),  name="user-idea"),
    # path('geners/', GenersViewAPI.as_view(), name='geners'),
    # path('file-extension/', FileExtensionViewAPI.as_view(), name='file-extension'),
    path('ideas/',IdeasViewAPI.as_view(), name="ideas"),
    path('user-comment/', CommentAPIView.as_view(), name = 'user-comment'),
    path('ideafeedback/<int:pk>/', IdeaFeedbackAPIView.as_view(), name='ideafeedback')
    ] 