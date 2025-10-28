from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.http import base36_to_int, int_to_base36
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import View
from django.views.generic.edit import FormView

from account import signals
from account.conf import settings
from account.forms import (
    ChangePasswordForm,
    LoginUsernameForm,
    PasswordResetForm,
    PasswordResetTokenForm,
    SettingsForm,
    SignupForm,
)
from account.hooks import hookset
from account.models import (
    Account,
    AccountDeletion,
    EmailAddress,
    EmailConfirmation,
    PasswordHistory,
    SignupCode,
)
from account.utils import default_redirect, get_form_data, is_ajax


class JsonResponseMixin:
    def render_to_json_response(self, context, **response_kwargs):
        return JsonResponse(context, **response_kwargs)


class PasswordMixin:
    """
    Mixin handling common elements of password change.

    Required attributes in inheriting class:

      form_password_field - example: "password"
      fallback_url_setting - example: "ACCOUNT_PASSWORD_RESET_REDIRECT_URL"

    Required methods in inheriting class:

      get_user()
      change_password()
      after_change_password()
      get_redirect_field_name()

    """

    redirect_field_name = "next"
    messages = {
        "password_changed": {
            "level": messages.SUCCESS,
            "text": _("Password successfully changed."),
        }
    }

    def get_context_data(self, **kwargs):
        ctx = super(PasswordMixin, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update(
            {
                "redirect_field_name": redirect_field_name,
                "redirect_field_value": self.request.POST.get(
                    redirect_field_name,
                    self.request.GET.get(redirect_field_name, ""),
                ),
            }
        )
        return ctx

    def change_password(self, form):
        user = self.get_user()
        user.set_password(form.cleaned_data[self.form_password_field])
        user.save()
        return user

    def after_change_password(self):
        user = self.get_user()
        signals.password_changed.send(sender=self, user=user)
        if settings.ACCOUNT_NOTIFY_ON_PASSWORD_CHANGE:
            self.send_password_email(user)
        if self.messages.get("password_changed"):
            messages.add_message(
                self.request,
                self.messages["password_changed"]["level"],
                self.messages["password_changed"]["text"],
            )

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = getattr(settings, self.fallback_url_setting, None)
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def send_password_email(self, user):
        protocol = settings.ACCOUNT_DEFAULT_HTTP_PROTOCOL
        current_site = get_current_site(self.request)
        ctx = {
            "user": user,
            "protocol": protocol,
            "current_site": current_site,
        }
        hookset.send_password_change_email([user.email], ctx)

    def create_password_history(self, form, user):
        if settings.ACCOUNT_PASSWORD_USE_HISTORY:
            password = form.cleaned_data[self.form_password_field]
            PasswordHistory.objects.create(user=user, password=make_password(password))


class SignupView(JsonResponseMixin, PasswordMixin, FormView):
    form_class = SignupForm
    form_kwargs = {}
    form_password_field = "password"
    identifier_field = "username"

    def __init__(self, *args, **kwargs):
        self.created_user = None
        kwargs["signup_code"] = None
        super(SignupView, self).__init__(*args, **kwargs)

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self.request = request
        self.args = args
        self.kwargs = kwargs
        self.setup_signup_code()
        return super(SignupView, self).dispatch(request, *args, **kwargs)

    def setup_signup_code(self):
        code = self.get_code()
        if code:
            try:
                self.signup_code = SignupCode.check_code(code)
            except SignupCode.InvalidCode:
                self.signup_code = None
            self.signup_code_present = True
        else:
            self.signup_code = None
            self.signup_code_present = False

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect(
                default_redirect(self.request, settings.ACCOUNT_LOGIN_REDIRECT_URL)
            )
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            raise Http404()
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).post(*args, **kwargs)

    def get_initial(self):
        initial = super(SignupView, self).get_initial()
        if self.signup_code:
            initial["code"] = self.signup_code.code
            if self.signup_code.email:
                initial["email"] = self.signup_code.email
        return initial

    def get_template_names(self):
        if is_ajax(self.request):
            return [self.template_name_ajax]
        return [self.template_name]

    def get_form_kwargs(self):
        kwargs = super(SignupView, self).get_form_kwargs()
        kwargs.update(self.form_kwargs)
        return kwargs

    def form_invalid(self, form):
        return self.render_to_json_response({"errors": form.errors}, status=400)

    def form_valid(self, form):
        self.created_user = self.create_user(form, commit=False)
        # prevent User post_save signal from creating an Account instance
        # we want to handle that ourself.
        self.created_user._disable_account_creation = True
        self.created_user.save()
        self.use_signup_code(self.created_user)
        email_address = self.create_email_address(form)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            self.created_user.is_active = False
            self.created_user.save()
        self.create_account(form)
        self.create_password_history(form, self.created_user)
        self.after_signup(form)
        if settings.ACCOUNT_APPROVAL_REQUIRED:
            # Notify site admins about the user wanting activation
            self.created_user.is_active = False
            self.created_user.save()
            return self.account_approval_required_response()
        if settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL and not email_address.verified:
            self.send_email_confirmation(email_address)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            return self.email_confirmation_required_response()
        show_message = [
            settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL,
            self.messages.get("email_confirmation_sent"),
            not email_address.verified,
        ]
        if all(show_message):
            pass
        # attach form to self to maintain compatibility with login_user
        # API. this should only be relied on by d-u-a and it is not a stable
        # API for site developers.
        self.form = form  # skipcq: PYL-W0201
        self.login_user()
        return self.render_to_json_response({"success": True}, status=201)

    def create_user(self, form, commit=True, model=None, **kwargs):
        User = model
        if User is None:
            User = get_user_model()
        user = User(**kwargs)
        username = form.cleaned_data.get("username")
        if username is None:
            username = self.generate_username(form)
        user.username = username
        user.email = form.cleaned_data["email"].strip()
        password = form.cleaned_data.get("password")
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        if commit:
            user.save()
        return user

    def create_account(self, form):  # skipcq: PYL-W0613
        return Account.create(
            request=self.request, user=self.created_user, create_email=False
        )

    def generate_username(self, form):
        raise NotImplementedError(
            "Unable to generate username by default. "
            "Override SignupView.generate_username in a subclass."
        )

    def create_email_address(self, form, **kwargs):  # skipcq: PYL-W0613
        kwargs.setdefault("primary", True)
        kwargs.setdefault("verified", False)
        if self.signup_code:
            kwargs["verified"] = (
                self.created_user.email == self.signup_code.email
                if self.signup_code.email
                else False
            )
        return EmailAddress.objects.add_email(
            self.created_user, self.created_user.email, **kwargs
        )

    def use_signup_code(self, user):
        if self.signup_code:
            self.signup_code.use(user)

    def send_email_confirmation(self, email_address):
        email_address.send_confirmation(site=get_current_site(self.request))

    def after_signup(self, form):
        signals.user_signed_up.send(
            sender=SignupForm, user=self.created_user, form=form
        )

    def login_user(self):
        user = auth.authenticate(**self.user_credentials())
        if not user:
            raise ImproperlyConfigured(
                "Configured auth backends failed to authenticate on signup"
            )
        auth.login(self.request, user)
        self.request.session.set_expiry(0)

    def user_credentials(self):
        return hookset.get_user_credentials(self.form, self.identifier_field)

    def get_code(self):
        return self.request.POST.get("code", self.request.GET.get("code"))

    def is_open(self):
        if self.signup_code:
            return True

        if self.signup_code_present and self.messages.get("invalid_signup_code"):
            messages.add_message(
                self.request,
                self.messages["invalid_signup_code"]["level"],
                self.messages["invalid_signup_code"]["text"].format(
                    **{
                        "code": self.get_code(),
                    }
                ),
            )

        return settings.ACCOUNT_OPEN_SIGNUP

    def email_confirmation_required_response(self):
        if is_ajax(self.request):
            template_name = self.template_name_email_confirmation_sent_ajax
        else:
            template_name = self.template_name_email_confirmation_sent
        response_kwargs = {
            "request": self.request,
            "template": template_name,
            "context": {
                "email": self.created_user.email,
                "success_url": self.get_success_url(),
            },
        }
        return self.response_class(**response_kwargs)

    def closed(self):
        if is_ajax(self.request):
            template_name = self.template_name_signup_closed_ajax
        else:
            template_name = self.template_name_signup_closed
        response_kwargs = {
            "request": self.request,
            "template": template_name,
        }
        return self.response_class(**response_kwargs)

    def account_approval_required_response(self):
        if is_ajax(self.request):
            template_name = self.template_name_admin_approval_sent_ajax
        else:
            template_name = self.template_name_admin_approval_sent

        response_kwargs = {
            "request": self.request,
            "template": template_name,
            "context": {
                "email": self.created_user.email,
                "success_url": self.get_success_url(),
            },
        }
        return self.response_class(**response_kwargs)


class LoginView(JsonResponseMixin, FormView):
    form_class = LoginUsernameForm
    form_kwargs = {}

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super(LoginView, self).dispatch(*args, **kwargs)

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return self.render_to_json_response({"message": "Already logged in."})
        return self.render_to_json_response(
            {"error": "GET method not supported. Please use POST."}, status=405
        )

    def form_invalid(self, form):
        signals.user_login_attempt.send(
            sender=LoginView,
            username=get_form_data(form, form.identifier_field),
            result=form.is_valid(),
        )
        return self.render_to_json_response({"errors": form.errors}, status=400)

    def form_valid(self, form):
        self.login_user(form)
        self.after_login(form)
        return self.render_to_json_response({"success": True})

    @staticmethod
    def after_login(form):
        signals.user_logged_in.send(sender=LoginView, user=form.user, form=form)

    def login_user(self, form):
        auth.login(self.request, form.user)
        expiry = (
            settings.ACCOUNT_REMEMBER_ME_EXPIRY
            if form.cleaned_data.get("remember")
            else 0
        )
        self.request.session.set_expiry(expiry)


class LogoutView(JsonResponseMixin, View):

    redirect_field_name = "next"

    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super(LogoutView, self).dispatch(*args, **kwargs)

    def get(self, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return self.render_to_json_response({"error": "Not logged in."}, status=400)
        return self.render_to_json_response(
            {"error": "GET method not supported. Please use POST."}, status=405
        )

    def post(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            auth.logout(self.request)
        return self.render_to_json_response({"success": True})


class ConfirmEmailView(JsonResponseMixin, View):
    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        self.user = self.request.user
        confirmed = confirmation.confirm() is not None
        if confirmed:
            self.after_confirmation(confirmation)
            if settings.ACCOUNT_EMAIL_CONFIRMATION_AUTO_LOGIN:
                self.user = self.login_user(confirmation.email_address.user)
            return self.render_to_json_response({"success": True})
        else:
            return self.render_to_json_response(
                {"error": "Email confirmation has expired."}, status=400
            )

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        try:
            return queryset.get(key=self.kwargs["key"].lower())
        except EmailConfirmation.DoesNotExist:
            raise Http404()

    @staticmethod
    def get_queryset():
        qs = EmailConfirmation.objects.all()
        qs = qs.select_related("email_address__user")
        return qs

    def get_context_data(self, **kwargs):
        ctx = kwargs
        ctx["confirmation"] = self.object
        return ctx

    def get_redirect_url(self):
        if self.user.is_authenticated:
            if not settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL:
                return settings.ACCOUNT_LOGIN_REDIRECT_URL
            return settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL
        return settings.ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL

    @staticmethod
    def after_confirmation(confirmation):
        user = confirmation.email_address.user
        user.is_active = True
        user.save()

    def login_user(self, user):
        user.backend = "django.contrib.auth.backends.ModelBackend"
        auth.login(self.request, user)
        return user


class ChangePasswordView(JsonResponseMixin, PasswordMixin, FormView):
    form_class = ChangePasswordForm
    form_password_field = "password_new"

    def get(self, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return self.render_to_json_response(
                {"error": "Authentication required."}, status=401
            )
        return self.render_to_json_response(
            {"error": "GET method not supported. Please use POST."}, status=405
        )

    def post(self, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return HttpResponseForbidden()
        return super(ChangePasswordView, self).post(*args, **kwargs)

    def form_valid(self, form):
        self.change_password(form)
        self.create_password_history(form, self.request.user)
        self.after_change_password()
        return self.render_to_json_response({"success": True})

    def get_user(self):
        return self.request.user

    def get_form_kwargs(self):
        """Returns the keyword arguments for instantiating the form."""
        kwargs = {"user": self.request.user, "initial": self.get_initial()}
        if self.request.method in ["POST", "PUT"]:
            kwargs.update(
                {
                    "data": self.request.POST,
                    "files": self.request.FILES,
                }
            )
        return kwargs

    def change_password(self, form):
        user = super(ChangePasswordView, self).change_password(form)
        # required on Django >= 1.7 to keep the user authenticated
        if hasattr(auth, "update_session_auth_hash"):
            auth.update_session_auth_hash(self.request, user)


class PasswordResetView(JsonResponseMixin, FormView):
    form_class = PasswordResetForm
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super(PasswordResetView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        self.send_email(form.cleaned_data["email"])
        return self.render_to_json_response({"success": True})

    def send_email(self, email):
        User = get_user_model()
        protocol = settings.ACCOUNT_DEFAULT_HTTP_PROTOCOL
        current_site = get_current_site(self.request)
        email_qs = EmailAddress.objects.filter(email__iexact=email)
        for user in User.objects.filter(pk__in=email_qs.values("user")):
            uid = int_to_base36(user.id)
            token = self.make_token(user)
            path = reverse(
                settings.ACCOUNT_PASSWORD_RESET_TOKEN_URL,
                kwargs=dict(uidb36=uid, token=token),
            )
            password_reset_url = f"{protocol}://{current_site.domain}{path}"
            ctx = {
                "user": user,
                "current_site": current_site,
                "password_reset_url": password_reset_url,
            }
            hookset.send_password_reset_email([email], ctx)

    def make_token(self, user):
        return self.token_generator.make_token(user)


INTERNAL_RESET_URL_TOKEN = "set-password"
INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetTokenView(JsonResponseMixin, PasswordMixin, FormView):
    form_class = PasswordResetTokenForm
    token_generator = default_token_generator
    form_password_field = "password"

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        user = self.get_user()
        if user is not None:
            token = kwargs["token"]
            if token == INTERNAL_RESET_URL_TOKEN:
                session_token = self.request.session.get(
                    INTERNAL_RESET_SESSION_TOKEN, ""
                )
                if self.check_token(user, session_token):
                    return super(PasswordResetTokenView, self).dispatch(*args, **kwargs)
            else:
                if self.check_token(user, token):
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    return self.render_to_json_response({"success": True})
        return self.token_fail()

    def form_valid(self, form):
        self.change_password(form)
        self.create_password_history(form, self.get_user())
        self.after_change_password()
        return self.render_to_json_response({"success": True})

    def get_user(self):
        try:
            uid_int = base36_to_int(self.kwargs["uidb36"])
        except ValueError:
            raise Http404()
        return get_object_or_404(get_user_model(), id=uid_int)

    def check_token(self, user, token):
        return self.token_generator.check_token(user, token)

    def token_fail(self):
        return self.render_to_json_response({"error": "Invalid token."}, status=400)


class SettingsView(JsonResponseMixin, FormView):
    form_class = SettingsForm

    def get_form_class(self):
        self.primary_email_address = EmailAddress.objects.get_primary(self.request.user)
        return super(SettingsView, self).get_form_class()

    def get_initial(self):
        initial = super(SettingsView, self).get_initial()
        if self.primary_email_address:
            initial["email"] = self.primary_email_address.email
        initial["timezone"] = self.request.user.account.timezone
        initial["language"] = self.request.user.account.language
        return initial

    def form_valid(self, form):
        self.update_settings(form)
        return self.render_to_json_response({"success": True})

    def update_settings(self, form):
        self.update_email(form)
        self.update_account(form)

    def update_email(self, form, confirm=None):
        user = self.request.user
        if confirm is None:
            confirm = settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL
        email = form.cleaned_data["email"].strip()
        if not self.primary_email_address:
            user.email = email
            EmailAddress.objects.add_email(
                self.request.user, email, primary=True, confirm=confirm
            )
            user.save()
        else:
            if email != self.primary_email_address.email:
                self.primary_email_address.change(email, confirm=confirm)

    def update_account(self, form):
        fields = {}
        if "timezone" in form.cleaned_data:
            fields["timezone"] = form.cleaned_data["timezone"]
        if "language" in form.cleaned_data:
            fields["language"] = form.cleaned_data["language"]
        if fields:
            account = self.request.user.account
            for k, v in fields.items():
                setattr(account, k, v)
            account.save()


class DeleteView(JsonResponseMixin, View):
    def post(self, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return self.render_to_json_response(
                {"error": "Authentication required."}, status=401
            )
        AccountDeletion.mark(self.request.user)
        auth.logout(self.request)
        return self.render_to_json_response({"success": True})
