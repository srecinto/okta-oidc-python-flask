import os
import config

from flask import Flask, request, send_from_directory, redirect, make_response, render_template
from utils.rest import OktaUtil

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session


"""
UTILS ###################################################################################################################
"""


def get_oauth_token(oauth_code):
    print "get_oauth_token()"
    okta_util = OktaUtil(request.headers, config.okta)

    oauth_token_response_json = okta_util.get_oauth_token(oauth_code, config.okta["redirect_uri"])
    print "oauth_token_response_json: {0}".format(oauth_token_response_json)

    return oauth_token_response_json["access_token"]


def get_session_token(username, password):
    print "get_session_token()"
    okta_util = OktaUtil(request.headers, config.okta)
    session_token = None

    authn_reponse_json = okta_util.get_session_token(username, password)
    if "sessionToken" in authn_reponse_json:
        session_token = authn_reponse_json["sessionToken"]

    return session_token


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
        okta_util = OktaUtil(request.headers, config.okta)
        oidc_auth_code_url = okta_util.create_oidc_auth_code_url(
            session_token,
            config.okta["oidc_client_id"],
            config.okta["redirect_uri"])

        print "url: {0}".format(oidc_auth_code_url)
        # redirect to User Auth Code URL to Get OIDC Code
        return redirect(oidc_auth_code_url)

    else:
        return make_response(redirect("/"))


def handle_logout():
    print "handle_logout()"
    redirect_url = "{host}/login/signout?fromURI={redirect_path}".format(
        host = config.okta["org_host"],
        redirect_path = config.okta["app_host"]
    )

    print "redirect_url: {0}".format(redirect_url)

    response = make_response(redirect(redirect_url))
    response.set_cookie('token', "")

    return response


def get_current_user_token():
    print "get_current_user_token()"
    user_results_json = None
    okta_util = OktaUtil(request.headers, config.okta)

    if("token" in request.cookies):
        introspection_results_json = okta_util.introspect_oauth_token(request.cookies.get("token"))

        if("active" in introspection_results_json):
            if(introspection_results_json["active"]):
                print "Has active token"
                user_results_json = {
                    "active": introspection_results_json["active"],
                    "username": introspection_results_json["username"],
                    "uid": introspection_results_json["uid"]
                }
            else:
                print "Has inactive token"
        else:
            print "has inactive token error"
            check_okta_session_url = okta_util.create_oidc_auth_code_url(None, config.okta["oidc_client_id"], config.okta["redirect_uri"])
            user_results_json = {
                "active": False,
                "redirect_url": check_okta_session_url
            }
    else:
        print "has no token"
        check_okta_session_url = okta_util.create_oidc_auth_code_url(None, config.okta["oidc_client_id"], config.okta["redirect_uri"])
        user_results_json = {
            "active": False,
            "redirect_url": check_okta_session_url
        }

    if(not user_results_json):
        print "has no token default"
        user_results_json = {
            "active": False
        }

    return user_results_json


def get_current_user(user_token_data):
    print "get_current_user()"
    current_user = None

    if "uid" in user_token_data:
        user_id = user_token_data["uid"]
        print "Looking up user by id: {0}".format(user_id)
        okta_util = OktaUtil(request.headers, config.okta)
        current_user = okta_util.get_user(user_id)

    return current_user


"""
ROUTES ##################################################################################################################
"""


@app.route('/<path:filename>')
def serve_static_html(filename):
    print "serve_static_html('{0}')".format(filename)
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route("/", methods=["GET"])
def root():
    print "root()"

    user = None
    current_token_info = get_current_user_token()
    print "current_token_info: {0}".format(current_token_info)
    if current_token_info["active"]:
        user = get_current_user(current_token_info)
        print "user: {0}".format(user)
    elif "redirect_url" in current_token_info:
        return redirect(current_token_info["redirect_url"])

    response = make_response(render_template("index.html", current_token_info=current_token_info, user=user))
    if "token" in request.cookies:
        if request.cookies["token"] == "NO_TOKEN":
            response.set_cookie('token', "")

    return response


@app.route("/login", methods=["POST"])
def login():
    print "login()"
    print request.form

    return handle_login(request.form)


@app.route("/logout", methods=["GET"])
def logout():
    print "logout()"

    return handle_logout()


@app.route("/oidc", methods=["POST"])
def oidc():
    print "oidc()"
    print request.form

    redirect_url = ""

    if("error" in request.form):
        oauth_token = "NO_TOKEN"
        redirect_url = config.okta["app_host"]
    else:
        oidc_code = request.form["code"]
        print "oidc_code: {0}".format(oidc_code)
        oauth_token = get_oauth_token(oidc_code)
        redirect_url = config.okta["post_oidc_redirect"]

    response = make_response(redirect(redirect_url))
    response.set_cookie('token', oauth_token)
    return response


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    print "okta_config: {0}".format(config.okta)
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
