import base64, hashlib, hmac
import logging, json, time
from botocore.exceptions import ClientError
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

logger = logging.getLogger(__name__)

class CognitoIdentityProviderWrapper:
    """Encapsulates Amazon Cognito actions"""

    def __init__(self, cognito_idp_client, user_pool_id, client_id, client_secret=None):
        """
        :param cognito_idp_client: A Boto3 Amazon Cognito Identity Provider client.
        :param user_pool_id: The ID of an existing Amazon Cognito user pool.
        :param client_id: The ID of a client application registered with the user pool.
        :param client_secret: The client secret, if the client has a secret.
        """
        self.cognito_idp_client = cognito_idp_client
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret


    def _secret_hash(self, user_name):
        """
        Calculates a secret hash from a user name and a client secret.

        :param user_name: The user name to use when calculating the hash.
        :return: The secret hash.
        """
        key = self.client_secret.encode()
        msg = bytes(user_name + self.client_id, "utf-8")
        secret_hash = base64.b64encode(
            hmac.new(key, msg, digestmod=hashlib.sha256).digest()
        ).decode()
        logger.info("Made secret hash for %s: %s.", user_name, secret_hash)
        return secret_hash
    

    def start_sign_in(self, user_name, password):
        """
        Starts the sign-in process for a user by using administrator credentials.
        This method of signing in is appropriate for code running on a secure server.

        If the user pool is configured to require MFA and this is the first sign-in
        for the user, Amazon Cognito returns a challenge response to set up an
        MFA application. When this occurs, this function gets an MFA secret from
        Amazon Cognito and returns it to the caller.

        :param user_name: The name of the user to sign in.
        :param password: The user's password.
        :return: The result of the sign-in attempt. When sign-in is successful, this
                 returns an access token that can be used to get AWS credentials. Otherwise,
                 Amazon Cognito returns a challenge to set up an MFA application,
                 or a challenge to enter an MFA code from a registered MFA application.
        """
        try:
            kwargs = {
                "UserPoolId": self.user_pool_id,
                "ClientId": self.client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {"USERNAME": user_name, "PASSWORD": password},
            }
            if self.client_secret is not None:
                kwargs["AuthParameters"]["SECRET_HASH"] = self._secret_hash(user_name)
            try:
                response = self.cognito_idp_client.admin_initiate_auth(**kwargs)
            except ClientError as err:
                return {"code":err.response['Error']['Code'],"message":err.response['Error']['Message']}
            challenge_name = response.get("ChallengeName", None)
            if challenge_name == "MFA_SETUP":
                if (
                    "SOFTWARE_TOKEN_MFA"
                    in response["ChallengeParameters"]["MFAS_CAN_SETUP"]
                ):
                    response.update(self.get_mfa_secret(response["Session"]))
                else:
                    raise RuntimeError(
                        "The user pool requires MFA setup, but the user pool is not "
                        "configured for TOTP MFA. This example requires TOTP MFA."
                    )
        except ClientError as err:
            logger.error(
                "Couldn't start sign in for %s. Here's why: %s: %s",
                user_name,
                err.response["Error"]["Code"],
                err.response["Error"]["Message"],
            )
            raise
        else:
            response.pop("ResponseMetadata", None)
            return response

class DecodeVerifyJWT:
        
        def __init__(self, user_pool_id, client_id, region_name):
            keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region_name, user_pool_id)
            # instead of re-downloading the public keys every time
            # we download them only on cold start
            # https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
            with urllib.request.urlopen(keys_url) as f:
                response = f.read()
            self.keys = json.loads(response.decode('utf-8'))['keys']
            self.client_id = client_id

        def lambda_handler(self, event):
            token = event['token']
            if token == 'fake':
                return {"message":"Unauthorized","errors":["Provided token does not have a valid format"]}
            # get the kid from the headers prior to verification
            headers = jwt.get_unverified_headers(token)
            kid = headers['kid']
            # search for the kid in the downloaded public keys
            key_index = -1
            for i in range(len(self.keys)):
                if kid == self.keys[i]['kid']:
                    key_index = i
                    break
            if key_index == -1:
                print('Public key not found in jwks.json')
                return {"message":"Public key not found in jwks.json"}
            # construct the public key
            public_key = jwk.construct(self.keys[key_index])
            # get the last two sections of the token,
            # message and signature (encoded in base64)
            message, encoded_signature = str(token).rsplit('.', 1)
            # decode the signature
            decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
            # verify the signature
            if not public_key.verify(message.encode("utf8"), decoded_signature):
                print('Signature verification failed')
                return {"message": "Signature verification failed"}
            print('Signature successfully verified')
            # since we passed the verification, we can now safely
            # use the unverified claims
            claims = jwt.get_unverified_claims(token)
            # additionally we can verify the token expiration
            if time.time() > claims['exp']:
                print('Token is expired')
                return False
            # and the Audience  (use claims['client_id'] if verifying an access token)
            if claims['client_id'] != self.client_id:
                print('Token was not issued for this audience')
                return {"message":"Token was not issued for this audience"}
            # now we can use the claims
            print(claims)
            return claims
