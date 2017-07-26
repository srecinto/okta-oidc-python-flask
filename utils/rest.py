import requests
import base64

from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning


class OktaUtil:
    # TODO: This should be configuration driven
    REST_HOST = None
    REST_TOKEN = None
    OKTA_SESSION_ID_KEY = "okta_session_id"
    OKTA_SESSION_TOKEN_KEY = "okta_session_id"
    DEVICE_TOKEN = None
    OKTA_HEADERS = {}
    OKTA_OAUTH_HEADERS = {}
    OIDC_CLIENT_ID = None
    OIDC_CLIENT_SECRET = None
    AUTH_SERVER_ID = None

    def __init__(self, headers, okta_config):
        # This is to supress the warnings for the older version
        requests.packages.urllib3.disable_warnings((InsecurePlatformWarning, SNIMissingWarning))

        self.REST_HOST = okta_config["org_host"]
        self.REST_TOKEN = okta_config["api_token"]
        self.OIDC_CLIENT_ID = okta_config["oidc_client_id"]
        self.OIDC_CLIENT_SECRET = okta_config["oidc_client_secret"]
        if "auth_server_id" in okta_config:
            self.AUTH_SERVER_ID = okta_config["auth_server_id"]
            print "HAS AUTH SERVER: {0}".format(self.AUTH_SERVER_ID)

        self.OKTA_HEADERS = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "SSWS {api_token}".format(api_token=self.REST_TOKEN),
            "User-Agent": headers["User-Agent"],
            "X-Forwarded-For": headers["X-Forwarded-For"],
            "X-Forwarded-Port": headers["X-Forwarded-Port"],
            "X-Forwarded-Proto": headers["X-Forwarded-Proto"]
        }

        self.OKTA_OAUTH_HEADERS = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic {encoded_auth}".format(
                encoded_auth=self.get_encoded_auth(
                    client_id=self.OIDC_CLIENT_ID,
                    client_secret=self.OIDC_CLIENT_SECRET))
        }

        print "OKTA_OAUTH_HEADERS: {0}".format(self.OKTA_OAUTH_HEADERS)

    def authenticate(self, username, password):
        print("authenticate()")
        url = "{host}/api/v1/authn".format(host=self.REST_HOST)

        body = {
            "username": username,
            "password": password,
            "options": {
                "multiOptionalFactorEnroll": True,
                "warnBeforePasswordExpired": True
            },
            "context": {
                "deviceToken": self.DEVICE_TOKEN
            }
        }

        return self.execute_post(url, body)

    def authenticate_via_activation_token(self, token):
        print("authenticate()")
        url = "{host}/api/v1/authn".format(host=self.REST_HOST)

        body = {
            "token": token
        }

        return self.execute_post(url, body)

    def revoke_token(self, token):
        print("revoke_token()")
        auth_server = ""
        if self.AUTH_SERVER_ID:
            auth_server = "/{0}".format(self.AUTH_SERVER_ID)

        url = "{host}/oauth2{auth_server}/v1/revoke?token={token}".format(
            host=self.REST_HOST,
            auth_server=auth_server,
            token=token)
        body = {}

        return self.execute_post(url, body)

    def list_factors(self, user_id):
        url = "{host}/api/v1/users/{user_id}/factors".format(host=self.REST_HOST, user_id=user_id)
        body = {}
        return self.execute_get(url, body)

    def get_factor(self, user_id, factor_id):
        url = "{host}/api/v1/users/{user_id}/factors/{factor_id}".format(host=self.REST_HOST, user_id=user_id, factor_id=factor_id)
        body = {}
        return self.execute_get(url, body)

    def push_factor_verification(self, user_id, factor_id):
        url = "{host}/api/v1/users/{user_id}/factors/{factor_id}/verify".format(host=self.REST_HOST, user_id=user_id, factor_id=factor_id)
        body = {}
        return self.execute_post(url, body)

    def factor_verification(self, verify_url, verification_Value):
        body = {"passCode": verification_Value}
        return self.execute_post(verify_url, body)

    def get_session_token(self, username, password):
        print("get_session_token()")
        url = "{host}/api/v1/authn".format(host=self.REST_HOST)

        body = {
            "username": username,
            "password": password
        }

        return self.execute_post(url, body)

    def validate_session(self, session_id):
        url = "{host}/api/v1/sessions/{session_id}".format(host=self.REST_HOST, session_id=session_id)
        body = {}
        return self.execute_get(url, body)

    def close_session(self, session_id):
        url = "{host}/api/v1/sessions/{session_id}".format(host=self.REST_HOST, session_id=session_id)
        body = {}
        return self.execute_delete(url, body)

    def create_session(self, session_token):
        url = "{host}/api/v1/sessions?additionalFields=cookieToken".format(host=self.REST_HOST)
        body = {
            "sessionToken": session_token
        }
        return self.execute_post(url, body)

    def introspect_oauth_token(self, oauth_token):
        print "introspect_oauth_token()"

        auth_server = ""

        if self.AUTH_SERVER_ID:
            auth_server = "/{0}".format(self.AUTH_SERVER_ID)

        url = "{host}/oauth2{auth_server}/v1/introspect?token={token}".format(
            host=self.REST_HOST,
            auth_server=auth_server,
            token=oauth_token)
        body = {}

        return self.execute_post(url, body, self.OKTA_OAUTH_HEADERS)

    def get_oauth_token(self, oauth_code, redirect_uri):
        print "get_oauth_token()"
        print "oauth_code: {0}".format(oauth_code)
        auth_server = ""

        if self.AUTH_SERVER_ID:
            auth_server = "/{0}".format(self.AUTH_SERVER_ID)

        url = (
            "{host}/oauth2{auth_server}/v1/token?"
            "grant_type=authorization_code&"
            "code={code}&"
            "redirect_uri={redirect_uri}"
        ).format(
            host=self.REST_HOST,
            auth_server=auth_server,
            code=oauth_code,
            redirect_uri=redirect_uri
        )

        body = {
            "authorization_code": oauth_code
        }

        return self.execute_post(url, body, self.OKTA_OAUTH_HEADERS)

    def get_user(self, user_id):
        url = "{host}/api/v1/users/{user_id}".format(host=self.REST_HOST, user_id=user_id)
        body = {}

        return self.execute_get(url, body)

    def get_user_groups(self, user_id):
        print "get_user_groups()"
        url = "{host}/api/v1/users/{user_id}/groups".format(host=self.REST_HOST, user_id=user_id)
        body = {}

        return self.execute_get(url, body)

    def list_all_groups(self):
        print "get_user_groups()"
        url = "{host}/api/v1/groups".format(host=self.REST_HOST)
        body = {}

        return self.execute_get(url, body)

    def get_curent_user(self, session_id):
        session_response = self.validate_session(session_id)
        url = "{host}/api/v1/users/{user_id}".format(host=self.REST_HOST, user_id=session_response["userId"])
        body = {}

        return self.execute_get(url, body)

    def find_users_by_criteria(self, member_id, last_name, zip_code):
        url = "{host}/api/v1/users?search=profile.lastName eq \"{last_name}\" and profile.membership_number eq \"{member_id}\"".format(
            host=self.REST_HOST,
            member_id=member_id,
            last_name=last_name)
        body = {}

        return self.execute_get(url, body)

    def create_user(self, user_data):
        print "create_user()"
        url = "{host}/api/v1/users?activate=false".format(host=self.REST_HOST)

        return self.execute_post(url, user_data)

    def forgot_password(self, user_login, relay_Url):
        print "forgot_password()"
        url = "{host}/api/v1/authn/recovery/password".format(host=self.REST_HOST)
        body = {
            "username": user_login,
            "factorType": "SMS",
            "relayState": relay_Url
        }

        return self.execute_post(url, body=body)

    def activate_user(self, user_id):
        print "activate_user()"
        url = "{host}/api/v1/users/{user_id}/lifecycle/activate/?sendEmail=false".format(host=self.REST_HOST, user_id=user_id)

        return self.execute_post(url, body={})

    def update_user_credentials(self, user_id, password):
        print "update_user_credentials()"
        url = "{host}/api/v1/users/{user_id}".format(host=self.REST_HOST, user_id=user_id)
        body = {
            "credentials": {
                "password": {"value": password}
            }
        }
        return self.execute_post(url, body=body)

    def update_user_mobile(self, user_id, phone):
        print "update_user()"
        url = "{host}/api/v1/users/{user_id}".format(host=self.REST_HOST, user_id=user_id)
        body = {
            "profile": {
                "mobilePhone": phone
            }
        }

        return self.execute_post(url, body)

    def update_user(self, user_id, first_name, last_name, email, phone, custom_account_links):
        print "update_user()"
        url = "{host}/api/v1/users/{user_id}".format(host=self.REST_HOST, user_id=user_id)
        body = {
            "profile": {
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "mobilePhone": phone,
                "custom_account_links": custom_account_links.strip().split(',')
            }
        }

        return self.execute_post(url, body)

    def deactivate_user(self, user_id):
        url = "{host}/api/v1/users/{user_id}/lifecycle/deactivate".format(host=self.REST_HOST, user_id=user_id)
        body = {}

        return self.execute_post(url, body)

    def create_sms_factor(self, user_id, phone_number):
        url = "{host}/api/v1/users/{user_id}/factors?updatePhone=true".format(host=self.REST_HOST, user_id=user_id)

        body = {
            "factorType": "sms",
            "provider": "OKTA",
            "profile": {
                "phoneNumber": phone_number
            }
        }

        return self.execute_post(url, body)

    def activate_sms_factor(self, url, pass_code=None):
        body = {}

        if pass_code:
            body["passCode"] = pass_code

        return self.execute_post(url, body)

    def extend_session(self, url):
        body = {}
        return self.execute_post(url, body)

    def list_users(self, limit):
        url = "{host}/api/v1/users?filter=status eq \"ACTIVE\"&limit={limit}".format(host=self.REST_HOST, limit=limit)
        body = {}
        return self.execute_get(url, body)

    def list_user_schema(self):
        url = "{host}/api/v1/meta/schemas/user/default".format(host=self.REST_HOST)
        body = {}
        return self.execute_get(url, body)

    def execute_post(self, url, body, headers=None):
        print url
        print body

        headers = self.reconcile_headers(headers)

        rest_response = requests.post(url, headers=headers, json=body)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    def execute_put(self, url, body, headers=None):
        print url
        print body

        headers = self.reconcile_headers(headers)

        rest_response = requests.put(url, headers=headers, json=body)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    def execute_delete(self, url, body, headers=None):
        print url
        print body

        headers = self.reconcile_headers(headers)

        rest_response = requests.delete(url, headers=headers, json=body)
        try:
            response_json = rest_response.json()
        except:
            response_json = {"status": "none"}

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    def execute_get(self, url, body, headers=None):
        print url
        print body

        headers = self.reconcile_headers(headers)

        rest_response = requests.get(url, headers=headers, json=body)
        response_json = rest_response.json()

        # print json.dumps(response_json, indent=4, sort_keys=True)
        return response_json

    def reconcile_headers(self, headers):

        if headers is None:
            headers = self.OKTA_HEADERS

        return headers

    def get_encoded_auth(self, client_id, client_secret):
        print "get_encoded_auth()"
        auth_raw = "{client_id}:{client_secret}".format(
            client_id=client_id,
            client_secret=client_secret
        )

        print "auth_raw: {0}".format(auth_raw)
        encoded_auth = base64.b64encode(auth_raw)
        print "encoded_auth: {0}".format(encoded_auth)

        return encoded_auth

    def create_oidc_auth_code_url(self, session_token, client_id, redirect_uri):
        print "create_oidc_auth_code_url"
        print "session_token: {0}".format(session_token)
        session_option = ""
        auth_server = ""

        if (session_token):
            session_option = "&sessionToken={session_token}".format(session_token=session_token)

        if self.AUTH_SERVER_ID:
            auth_server = "/{0}".format(self.AUTH_SERVER_ID)

        url = (
            "{host}/oauth2{auth_server}/v1/authorize?"
            "response_type=code&"
            "client_id={clint_id}&"
            "redirect_uri={redirect_uri}&"
            "state=af0ifjsldkj&"
            "nonce=n-0S6_WzA2Mj&"
            "response_mode=form_post&"
            "prompt=none&"
            "scope=openid"
            "{session_option}"
        ).format(
            host=self.REST_HOST,
            auth_server=auth_server,
            clint_id=client_id,
            redirect_uri=redirect_uri,
            session_option=session_option
        )
        return url
