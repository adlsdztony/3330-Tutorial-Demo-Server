import azure.functions as func
import logging
import os
import requests
from requests_oauthlib import OAuth1Session

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


@app.route(route="twitter/oauth", methods=["GET"])
def twitter_oauth(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Starting Twitter OAuth process.')

    # Retrieve the Twitter API key, secret, and callback URI from environment variables
    TWITTER_API_KEY = os.environ['TWITTER_API_KEY']
    TWITTER_API_SECRET = os.environ['TWITTER_API_SECRET']
    TWITTER_CALLBACK_URI = os.environ['TWITTER_CALLBACK_URI']

    # Create an OAuth1 session with the Twitter API
    twitter = OAuth1Session(TWITTER_API_KEY, client_secret=TWITTER_API_SECRET, callback_uri=TWITTER_CALLBACK_URI)

    # Fetch the request token
    try:
        fetch_response = twitter.fetch_request_token('https://api.x.com/oauth/request_token')
    except ValueError as e:
        logging.error(f'Error fetching request token: {e}')
        return func.HttpResponse('Authentication failed.', status_code=500)

    # Extract the request token, secret, and callback confirmed flag
    oauth_token = fetch_response.get('oauth_token')
    oauth_token_secret = fetch_response.get('oauth_token_secret')
    oauth_callback_confirmed = fetch_response.get('oauth_callback_confirmed')

    # If any of the required parameters are missing, return an error
    if not oauth_token or not oauth_token_secret or not oauth_callback_confirmed:
        return func.HttpResponse('Invalid request token.', status_code=500)

    # Get the authorization URL
    authorization_url = twitter.authorization_url('https://api.x.com/oauth/authorize')

    # Redirect the user to the authorization URL
    return func.HttpResponse(
        status_code=302,
        headers={'Location': authorization_url}
    )

@app.route(route="twitter/callback", methods=["GET"])
def twitter_callback(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Handling Twitter OAuth callback.')

    # Retrieve the Twitter API key and secret from environment variables
    TWITTER_API_KEY = os.environ['TWITTER_API_KEY']
    TWITTER_API_SECRET = os.environ['TWITTER_API_SECRET']

    # Extract the oauth_token and oauth_verifier from the query parameters
    oauth_token = req.params.get('oauth_token')
    oauth_verifier = req.params.get('oauth_verifier')

    if not oauth_token or not oauth_verifier:
        return func.HttpResponse('Invalid callback parameters.', status_code=400)

    # Retrieve the stored resource owner secret based on the oauth_token
    resource_owner_secret = 'retrieve_from_storage'

    # Create an OAuth1 session with the Twitter API
    twitter = OAuth1Session(
        TWITTER_API_KEY,
        client_secret=TWITTER_API_SECRET,
        resource_owner_key=oauth_token,
        resource_owner_secret=resource_owner_secret,
        verifier=oauth_verifier
    )

    # Fetch the access token
    try:
        oauth_tokens = twitter.fetch_access_token('https://api.twitter.com/oauth/access_token')
    except ValueError as e:
        logging.error(f'Error fetching access token: {e}')
        return func.HttpResponse('Authentication failed.', status_code=500)

    # Extract the access token and secret
    access_token = oauth_tokens.get('oauth_token')
    access_token_secret = oauth_tokens.get('oauth_token_secret')

    # Use the access tokens as needed (e.g., create a session for the user)

    return func.HttpResponse(
        status_code=302,
        headers={'Location': f'demo://auth?platform=X&access_token={access_token}&access_token_secret={access_token_secret}'}
        )


@app.route(route="twitter/post", methods=["POST", "GET"])
def twitter_post(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Posting to Twitter.')

    # Retrieve the Twitter API key and secret from environment variables
    TWITTER_API_KEY = os.environ['TWITTER_API_KEY']
    TWITTER_API_SECRET = os.environ['TWITTER_API_SECRET']

    # Extract the access token, access token secret, and message from the request parameters
    access_token = req.params.get('access_token')
    access_token_secret = req.params.get('access_token_secret')
    message = req.params.get('message')

    logging.info(f'Access token: {access_token}')
    logging.info(f'Access token secret: {access_token_secret}')
    logging.info(f'Message: {message}')

    # If any of the required parameters are missing, return an error
    if not access_token or not access_token_secret or not message:
        return func.HttpResponse('Invalid request parameters.', status_code=400)
    
    # For testing purposes, return a fake tweet posted message
    if access_token == 'fake' and access_token_secret == 'fake':
        return func.HttpResponse('Fake tweet posted.', status_code = 200)

    # Create an OAuth1 session with the Twitter API
    twitter = OAuth1Session(
        TWITTER_API_KEY,
        client_secret=TWITTER_API_SECRET,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret
    )

    # Post the tweet
    response = twitter.post("https://api.twitter.com/2/tweets", json={"text": message})

    if response.status_code != 201:
        return func.HttpResponse(f'Error posting tweet: {response.text}', status_code = 500)

    return func.HttpResponse(f'Tweet posted: {response.text}', status_code=200)