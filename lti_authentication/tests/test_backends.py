from unittest import mock

import pytest
from django.contrib.auth import get_user_model

from ..backends import LtiLaunchAuthenticationBackend


@pytest.mark.django_db
class TestLtiLaunchAuthenticationBackendConfigureUser:

    @pytest.fixture
    def backend(self):
        return LtiLaunchAuthenticationBackend()

    @pytest.fixture
    def test_user(self):
        return get_user_model().objects.create_user(
            username="test_user",
            first_name="Old First",
            last_name="Old Last",
            email="old@example.com",
        )

    @pytest.fixture
    def mock_lti_request(self):
        """Creates a mock request with LTI launch data"""
        mock_request = mock.MagicMock()
        mock_request.lti_launch = mock.MagicMock()
        mock_request.lti_launch.user = mock.MagicMock()
        return mock_request

    def verify_user_fields(self, user, expected_first, expected_last, expected_email):
        """Helper method to verify user fields"""
        assert user.first_name == expected_first
        assert user.last_name == expected_last
        assert user.email == expected_email

    def test_configure_user_with_complete_lti_data(
        self, backend, test_user, mock_lti_request
    ):
        """Test configure_user with complete LTI launch data"""
        # Setup
        lti_user = mock_lti_request.lti_launch.user
        lti_user.given_name = "New First"
        lti_user.family_name = "New Last"
        lti_user.email = "new@example.com"

        # Execute
        updated_user = backend.configure_user(mock_lti_request, test_user)

        # Assert
        self.verify_user_fields(
            updated_user,
            expected_first="New First",
            expected_last="New Last",
            expected_email="new@example.com",
        )
        assert lti_user.auth_user == updated_user
        lti_user.save.assert_called_once()

    def test_configure_user_without_lti_launch(self, backend, test_user, caplog):
        """Test configure_user when no LTI launch data is present"""
        # Setup
        mock_request = mock.MagicMock()
        mock_request.lti_launch = None
        original_values = {
            "first": test_user.first_name,
            "last": test_user.last_name,
            "email": test_user.email,
        }

        # Execute
        updated_user = backend.configure_user(mock_request, test_user)

        # Assert
        self.verify_user_fields(
            updated_user,
            expected_first=original_values["first"],
            expected_last=original_values["last"],
            expected_email=original_values["email"],
        )
        assert (
            f"Unable to update user '{test_user}' without LTI launch data"
            in caplog.text
        )

    def test_configure_user_with_partial_lti_data(
        self, backend, test_user, mock_lti_request
    ):
        """Test configure_user with incomplete LTI launch data"""
        # Setup
        lti_user = mock_lti_request.lti_launch.user
        lti_user.given_name = "New First"
        lti_user.family_name = test_user.last_name
        lti_user.email = None

        # Execute
        updated_user = backend.configure_user(mock_lti_request, test_user)

        # Assert
        self.verify_user_fields(
            updated_user,
            expected_first="New First",
            expected_last=test_user.last_name,
            expected_email=test_user.email,
        )
        assert lti_user.auth_user == updated_user
        lti_user.save.assert_called_once()
