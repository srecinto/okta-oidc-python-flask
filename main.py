import os
import config
import requests
import json
import base64

from flask import Flask, request, send_from_directory, redirect, make_response, session, render_template

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session


"""
UTILS ###################################################################################################################
"""


def get_encoded_auth():
    print "get_encoded_auth()"
    auth_raw = "{client_id}:{client_secret}".format(
        client_id=config.okta_config["oidc_client_id"],
        client_secret=config.okta_config["oidc_client_secret"]
    )

    print "auth_raw: {0}".format(auth_raw)
    encoded_auth = base64.b64encode(auth_raw)
    print "encoded_auth: {0}".format(encoded_auth)

    return encoded_auth


def execute_post(url, body, headers):
    print "execute_post()"
    print "url: {0}".format(url)
    print "body: {0}".format(body)
    print "headers: {0}".format(headers)

    rest_response = requests.post(url, headers=headers, json=body)
    response_json = rest_response.json()

    print "json: {0}".format(json.dumps(response_json, indent=4, sort_keys=True))
    return response_json


def create_oidc_auth_code_url(session_token):
    print "create_oidc_auth_code_url"
    print "session_token: {0}".format(session_token)
    session_option = ""

    if (session_token):
        session_option = "&sessionToken={session_token}".format(session_token=session_token)

    url = (
        "{host}/oauth2/v1/authorize?"
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
        host=config.okta_config["org_host"],
        clint_id=config.okta_config["oidc_client_id"],
        redirect_uri=config.okta_config["redirect_uri"],
        session_option=session_option
    )
    return url


def get_oauth_token(oauth_code):
    print "get_oauth_token()"
    print "oauth_code: {0}".format(oauth_code)
    url = (
        "{host}/oauth2/v1/token?"
        "grant_type=authorization_code&"
        "code={code}&"
        "redirect_uri={redirect_uri}"
    ).format(
        host=config.okta_config["org_host"],
        code=oauth_code,
        redirect_uri=config.okta_config["redirect_uri"]
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic {encoded_auth}".format(encoded_auth=get_encoded_auth())
    }

    body = {
        "authorization_code": oauth_code
    }

    oauth_token_response_json = execute_post(url, body, headers)

    return oauth_token_response_json["access_token"]


def get_session_token(username, password):
    print("get_session_token()")
    url = "{host}/api/v1/authn".format(host=config.okta_config["org_host"])

    header = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": request.headers["User-Agent"],
        "X-Forwarded-For": request.headers["X-Forwarded-For"],
        "X-Forwarded-Port": request.headers["X-Forwarded-Port"],
        "X-Forwarded-Proto": request.headers["X-Forwarded-Proto"]
    }

    body = {
        "username": username,
        "password": password
    }

    authn_reponse_json = execute_post(url, body, header)
    print "authn_reponse_json: {0}".format(authn_reponse_json)

    if("errorSummary" in authn_reponse_json):
        raise ValueError(authn_reponse_json["errorSummary"])

    return authn_reponse_json["sessionToken"]


def handle_login(form_data):
    print "handle_login()"

    # Authenticate via Okta API to get Session Token
    user = form_data["username"]
    password = form_data["password"]
    session_token = None
    try:
        session_token = get_session_token(username=user, password=password)
    except ValueError as err:
        print(err.args)

    print "session_token: {0}".format(session_token)

    # Use Session Token to generatet OIDC Auth Code URL
    if(session_token):
        oidc_auth_code_url = create_oidc_auth_code_url(session_token)
        print "url: {0}".format(oidc_auth_code_url)
        # redirect to User Auth Code URL to Get OIDC Code
        return redirect(oidc_auth_code_url)

    else:
        return serve_static_html("index.html")


"""
ROUTES ##################################################################################################################
"""


@app.route("/", methods=["GET"])
def root():
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), "index.html")


@app.route('/<path:filename>')
def serve_static_html(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route("/login", methods=["POST"])
def login():
    print "login()"
    print request.form

    return handle_login(request.form)


@app.route("/oidc", methods=["POST"])
def oidc():
    print "oidc()"
    print request.form

    if("error" in request.form):
        oauth_token = "NO_TOKEN"
    else:
        oidc_code = request.form["code"]
        print "oidc_code: {0}".format(oidc_code)
        oauth_token = get_oauth_token(oidc_code)

    response = make_response(redirect("{0}/".format(config.okta_config["app_host"])))
    response.set_cookie('token', oauth_token)
    return response


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    print "okta_config: {0}".format(config.okta_config)
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
