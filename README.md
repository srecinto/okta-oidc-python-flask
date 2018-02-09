# Okta OIDC Example with Python and Flask

This project was built using Python 2.7

This is a simple application on using Okta's OIDC endpoints to access web properties

## Requirements
* Python 2.7
* Okta domain
* Okta API Token

## Dependencies
PIP may have to be run as root:

`sudo pip install ...`
 
You can run all the dependencies via the requirements.txt
`pip install -r requirements.txt`

Or run them individually

**linter - flake8**

`pip install flake8`

**Web Framework - flask**

`pip install flask`

**HTTP Framework - Update requests**

Needed to install an update to fix a compatability issue

`pip install requests --upgrade`

## How to Run

Edit config.py with your settings. 

NOTE: You may need to configure your listening ports when serving the site

`python main.py`
