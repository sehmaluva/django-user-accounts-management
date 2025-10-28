# Django User Accounts (Backend API)

`django-user-accounts` is a Django application that provides a backend API for handling user accounts. It is designed to be integrated into larger projects that require user management functionality without the frontend components.

## Features

* **User Account Management API:**
  * User signup
  * Email confirmation
  * Login (username/email)
  * Logout
  * Password reset
  * Password change
  * Account settings update
  * Account deletion
* **JSON-based Responses:** All views return JSON responses, making it easy to consume with a frontend framework or mobile application.
* **Extensible:** Built with extensibility in mind using a hookset system.
* **Custom `User` model support.**

## Supported Django and Python versions

| Django / Python | 3.8 | 3.9 | 3.10 | 3.11 |
| --------------- | --- | --- | ---- | ---- |
| 3.2             |  *  |  *  |  *   |      |
| 4.2             |  *  |  *  |  *   |  *   |

## Requirements

* Django 3.2 or 4.2
* Python 3.8, 3.9, 3.10, 3.11
* django-appconf (included in `install_requires`)
* pytz (included in `install_requires`)

## Setup

1.  Add `account` to your `INSTALLED_APPS`:

    ```python
    INSTALLED_APPS = [
        # ...
        "account",
        # ...
    ]
    ```

2.  Run migrations:

    ```bash
    python manage.py migrate
    ```

## Usage

The application provides API endpoints for user account management. You will need to create a `urls.py` file in the `account` app to expose the views as API endpoints.

**Example `account/urls.py`:**

```python
from django.urls import path

from . import views

urlpatterns = [
    path("signup/", views.SignupView.as_view(), name="account_signup"),
    path("login/", views.LoginView.as_view(), name="account_login"),
    path("logout/", views.LogoutView.as_view(), name="account_logout"),
    path("confirm_email/<str:key>/", views.ConfirmEmailView.as_view(), name="account_confirm_email"),
    path("password/change/", views.ChangePasswordView.as_view(), name="account_password_change"),
    path("password/reset/", views.PasswordResetView.as_view(), name="account_password_reset"),
    path("password/reset/<str:uidb36>/<str:token>/", views.PasswordResetTokenView.as_view(), name="account_password_reset_token"),
    path("settings/", views.SettingsView.as_view(), name="account_settings"),
    path("delete/", views.DeleteView.as_view(), name="account_delete"),
]
```

Then, include these URLs in your project's root `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    # ...
    path("api/account/", include("account.urls")),
    # ...
]
```


