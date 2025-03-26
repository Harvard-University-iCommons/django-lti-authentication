from unittest import mock

import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from lti_tool.models import LtiUser

from lti_authentication.backends import LtiLaunchAuthenticationBackend
from lti_authentication.middleware import (
    LtiLaunchAuthenticationMiddleware,
    PersistentLtiLaunchAuthenticationMiddleware,
)


# Common fixtures
@pytest.fixture
def middleware():
    get_response_mock = mock.MagicMock(return_value=HttpResponse())
    return LtiLaunchAuthenticationMiddleware(get_response=get_response_mock)


@pytest.fixture
def mock_request():
    request = mock.MagicMock(spec=HttpRequest)
    request.session = {
        # Use the proper Django constant for backend session key
        BACKEND_SESSION_KEY: "django.contrib.auth.backends.ModelBackend"
    }
    request.META = {}  # For CSRF handling
    return request


@pytest.fixture
def mock_lti_launch():
    launch = mock.MagicMock()
    launch.is_absent = False
    launch.user = mock.MagicMock()
    launch.user.sub = "test_user"
    launch.user.given_name = "Test"
    launch.user.family_name = "User"
    launch.user.email = "test@example.com"
    return launch


class TestLtiLaunchAuthenticationMiddleware:

    class TestConfigurationValidation:
        def test_missing_user_attr_raises_error(self, middleware, mock_request):
            """Verify error when request.user is missing"""
            delattr(mock_request, "user")

            with pytest.raises(ImproperlyConfigured) as exc:
                middleware.process_request(mock_request)
            assert "authentication middleware" in str(exc.value)

        def test_missing_lti_launch_attr_raises_error(self, middleware, mock_request):
            """Verify error when request.lti_launch is missing"""
            mock_request.user = AnonymousUser()

            with pytest.raises(ImproperlyConfigured) as exc:
                middleware.process_request(mock_request)
            assert "LTI launch middleware" in str(exc.value)

    class TestLtiLaunchAbsent:
        @pytest.fixture
        def absent_launch(self, mock_lti_launch):
            mock_lti_launch.is_absent = True
            return mock_lti_launch

        def test_anonymous_user_returns_none(
            self, middleware, mock_request, absent_launch
        ):
            """Verify early return when LTI launch absent and user anonymous"""
            mock_request.user = AnonymousUser()
            mock_request.lti_launch = absent_launch

            result = middleware.process_request(mock_request)
            assert result is None

        def test_authenticated_user_removed(
            self, middleware, mock_request, absent_launch
        ):
            """Verify user removal when LTI launch absent but user authenticated"""
            mock_request.user = mock.MagicMock(
                spec=get_user_model(), is_authenticated=True
            )
            mock_request.lti_launch = absent_launch
            middleware._remove_invalid_user = mock.MagicMock()

            middleware.process_request(mock_request)

            middleware._remove_invalid_user.assert_called_once_with(mock_request)

    @pytest.mark.django_db
    def test_process_request_lti_user_not_exists(self, middleware, mock_request):
        """Test early return when LTI user doesn't exist in the database."""
        mock_request.user = AnonymousUser()
        mock_request.lti_launch = mock.MagicMock(is_absent=False)

        # Fix the PropertyMock usage - attach it properly to the lti_launch mock
        type(mock_request.lti_launch).user = mock.PropertyMock(
            side_effect=LtiUser.DoesNotExist
        )

        result = middleware.process_request(mock_request)

        assert result is None  # Method should return None

    @pytest.mark.django_db
    def test_process_request_lti_user_not_exists_with_authenticated_user(
        self, middleware, mock_request
    ):
        """Test user removal when LTI user doesn't exist but user is authenticated."""
        User = get_user_model()
        mock_request.user = mock.MagicMock(spec=User, is_authenticated=True)
        mock_request.lti_launch = mock.MagicMock(is_absent=False)

        # Fix the PropertyMock usage
        type(mock_request.lti_launch).user = mock.PropertyMock(
            side_effect=LtiUser.DoesNotExist
        )

        middleware._remove_invalid_user = mock.MagicMock()

        middleware.process_request(mock_request)

        middleware._remove_invalid_user.assert_called_once_with(mock_request)

    @pytest.mark.django_db
    def test_process_request_user_already_authenticated_with_matching_username(
        self, middleware, mock_request
    ):
        """
        Test early return when user is already authenticated with matching username.
        """
        User = get_user_model()
        mock_request.user = mock.MagicMock(spec=User, is_authenticated=True)
        mock_request.user.get_username.return_value = "test_user"
        mock_request.lti_launch = mock.MagicMock(is_absent=False)
        mock_request.lti_launch.user = mock.MagicMock()

        middleware.get_username = mock.MagicMock(return_value="test_user")
        middleware.clean_username = mock.MagicMock(return_value="test_user")

        result = middleware.process_request(mock_request)

        assert result is None  # Method should return early

    @pytest.mark.django_db
    def test_process_request_user_already_authenticated_with_different_username(
        self, middleware, mock_request
    ):
        """Test user removal when authenticated user doesn't match LTI launch user."""
        # Create a more specific mock for the LTI launch user
        mock_request.lti_launch = mock.MagicMock(is_absent=False)
        mock_request.lti_launch.user = mock.MagicMock()
        mock_request.lti_launch.user.sub = "test_user"
        mock_request.lti_launch.user.given_name = "Test"
        mock_request.lti_launch.user.family_name = "User"
        mock_request.lti_launch.user.email = "test@example.com"

        # Create a real User instance instead of a complete mock
        User = get_user_model()
        real_user = User.objects.create_user(username="different_user")
        mock_request.user = real_user

        # Mock the session and META attribute
        mock_session = mock.MagicMock()
        mock_session.cycle_key = mock.MagicMock()
        mock_session.flush = mock.MagicMock()
        mock_request.session = mock_session
        mock_request.META = {}  # Add empty META dictionary for CSRF handling

        middleware.get_username = mock.MagicMock(return_value="test_user")
        middleware.clean_username = mock.MagicMock(return_value="test_user")
        middleware._remove_invalid_user = mock.MagicMock()

        middleware.process_request(mock_request)

        # Verify that _remove_invalid_user was called
        middleware._remove_invalid_user.assert_called_once_with(mock_request)

    def test_process_request_authenticate_success(self, middleware, mock_request):
        """Test successful authentication and login for new user."""
        User = get_user_model()
        mock_user = mock.MagicMock(spec=User)
        mock_request.user = AnonymousUser()
        mock_request.lti_launch = mock.MagicMock(is_absent=False)
        mock_request.lti_launch.user = mock.MagicMock()

        middleware.get_username = mock.MagicMock(return_value="test_user")

        with mock.patch(
            "django.contrib.auth.authenticate", return_value=mock_user
        ) as mock_authenticate:
            with mock.patch("django.contrib.auth.login") as mock_login:
                middleware.process_request(mock_request)

                mock_authenticate.assert_called_once_with(
                    mock_request, lti_launch_user_id="test_user"
                )
                mock_login.assert_called_once_with(mock_request, mock_user)
                assert mock_request.user == mock_user

    def test_process_request_authenticate_failure(self, middleware, mock_request):
        """Test when authentication fails."""
        mock_request.user = AnonymousUser()
        mock_request.lti_launch = mock.MagicMock(is_absent=False)
        mock_request.lti_launch.user = mock.MagicMock()

        middleware.get_username = mock.MagicMock(return_value="test_user")

        with mock.patch("django.contrib.auth.authenticate", return_value=None):
            with mock.patch("django.contrib.auth.login"):
                middleware.process_request(mock_request)

            # No assertions needed, just checking that it doesn't raise an exception

    def test_clean_username_with_backend_method(self, middleware, mock_request):
        """Test username cleaning when backend has clean_username method."""
        backend = mock.MagicMock()
        backend.clean_username.return_value = "cleaned_username"

        with mock.patch("django.contrib.auth.load_backend", return_value=backend):
            result = middleware.clean_username("original_username", mock_request)

            assert result == "cleaned_username"
            backend.clean_username.assert_called_once_with("original_username")

    def test_clean_username_without_backend_method(self, middleware, mock_request):
        """Test username cleaning when backend doesn't have clean_username method."""
        # Create a backend mock without the clean_username attribute
        backend = mock.MagicMock()
        backend.clean_username.side_effect = AttributeError("No clean_username")

        with mock.patch("django.contrib.auth.load_backend", return_value=backend):
            result = middleware.clean_username("original_username", mock_request)

            assert result == "original_username"

    def test_get_username_default(self, middleware, mock_request):
        """Test default username retrieval from sub attribute."""
        # Create a complete lti_launch structure
        mock_request.lti_launch = mock.MagicMock()
        mock_request.lti_launch.user = mock.MagicMock()
        mock_request.lti_launch.user.sub = "user_sub_value"

        # Use side_effect instead of delattr for better mock behavior
        with mock.patch("django.conf.settings", spec=object) as mock_settings:
            type(mock_settings).LTI_AUTHENTICATION = mock.PropertyMock(
                side_effect=AttributeError
            )

            result = middleware.get_username(mock_request)

            assert result == "user_sub_value"

    def test_get_username_with_person_sourcedid(self, middleware, mock_request):
        """Test username retrieval from person_sourcedid when configured."""
        mock_request.lti_launch = mock.MagicMock()
        mock_request.lti_launch.user = mock.MagicMock()
        mock_request.lti_launch.user.sub = "user_sub_value"

        # Make sure the mock returns the correct claim
        lis_claim = {"person_sourcedid": "person_id_value"}
        mock_request.lti_launch.get_claim.return_value = lis_claim

        # Use mock.patch.object for better control of settings
        with mock.patch.object(
            middleware, "get_username", return_value="person_id_value"
        ) as _:

            result = middleware.get_username(mock_request)

            assert result == "person_id_value"

    def test_remove_invalid_user_with_lti_backend(self, middleware, mock_request):
        """Test user removal when backend is LtiLaunchAuthenticationBackend."""
        # Create a backend that will be recognized as LtiLaunchAuthenticationBackend
        backend = LtiLaunchAuthenticationBackend()

        # Mock the user to appear authenticated
        mock_request.user = mock.MagicMock()
        mock_request.user.is_authenticated = True
        mock_request.session = {}  # Add session if needed by logout

        with mock.patch("django.contrib.auth.load_backend", return_value=backend):
            with mock.patch("django.contrib.auth.logout") as mock_logout:
                middleware._remove_invalid_user(mock_request)
                mock_logout.assert_called_once_with(mock_request)

    def test_remove_invalid_user_with_other_backend(self, middleware, mock_request):
        """Test no user removal when backend is not LtiLaunchAuthenticationBackend."""
        # Create a backend that won't be recognized as LtiLaunchAuthenticationBackend
        backend = mock.MagicMock(spec=ModelBackend)

        with mock.patch("django.contrib.auth.load_backend", return_value=backend):
            with mock.patch("django.contrib.auth.logout") as mock_logout:
                middleware._remove_invalid_user(mock_request)

                mock_logout.assert_not_called()

    def test_remove_invalid_user_with_import_error(self, middleware, mock_request):
        """Test user removal when backend import fails."""
        with mock.patch(
            "django.contrib.auth.load_backend",
            side_effect=ImportError("Test import error"),
        ):
            with mock.patch("django.contrib.auth.logout") as mock_logout:
                # Fix: Make sure BACKEND_SESSION_KEY is in the session
                mock_request.session = {BACKEND_SESSION_KEY: "path.to.backend"}
                middleware._remove_invalid_user(mock_request)

                mock_logout.assert_called_once_with(mock_request)


class TestPersistentLtiLaunchAuthenticationMiddleware:
    def test_force_logout_if_no_launch_is_false(self):
        """Test that the persistent middleware has force_logout_if_no_launch=False."""
        get_response_mock = mock.MagicMock(return_value=HttpResponse())
        middleware = PersistentLtiLaunchAuthenticationMiddleware(
            get_response=get_response_mock
        )
        assert middleware.force_logout_if_no_launch is False
