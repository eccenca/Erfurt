<?php
/**
 * This file is part of the {@link http://aksw.org/Projects/Erfurt Erfurt} project.
 *
 * @copyright Copyright (c) 2014, {@link http://aksw.org AKSW}
 * @license http://opensource.org/licenses/gpl-license.php GNU General Public License (GPL)
 */

require_once 'Zend/Auth/Adapter/Interface.php';

/**
 * This class provides functionality to authenticate users based on OAuth2.
 * Attention: This OAuth2 client only implements {@link http://tools.ietf.org/html/rfc6749#section-4.3 Resource Owner Password Credentials Grant}
 * 
 * @package   Erfurt_Auth_Adapter
 * @author    Christian Würker <christian.wuerker@ceusmedia.de>
 * @copyright Copyright (c) 2014 {@link http://aksw.org aksw}
 * @license   http://opensource.org/licenses/gpl-license.php GNU General Public License (GPL)
 */
class Erfurt_Auth_Adapter_OAuth implements Zend_Auth_Adapter_Interface
{
    private $_username = null;
    private $_password = null;
    private $_get;
    private $_redirectUri;
	private $_uris;
	private $_config = null;

    /**
     * Constructor
     */
    public function __construct($username = null, $password = null, $get = null, $redirectUri = null) 
    {
        // store given user credentials
        $this->_username = $username;
        $this->_password = $password;
        $this->_get         = $get;
        $this->_redirectUri = $redirectUri;
    }

    /**
     * Returns the anonymous user details.
     *
     * @return array
     */
    private function _getAnonymousUser()
    {
        $uris = $this->_getUris();
        $user = array(
            'username'  => 'Anonymous',
            'uri'       => $uris['user_anonymous'],
            'dbuser'    => false,
            'email'     => '',
            'anonymous' => true
        );

        require_once 'Erfurt/Auth/Identity.php';
        $identityObject = new Erfurt_Auth_Identity($user);

        return $identityObject;
    }

    private function _getConfig()
    {
        if (null === $this->_config) {
            $this->_config = Erfurt_App::getInstance()->getConfig();
        }

        return $this->_config;
    }

    private function _getUris()
    {
        if (null === $this->_uris) {
            $config = $this->_getConfig();

            $this->_uris = array(
                'user_class'      => $config->ac->user->class,
                'user_username'   => $config->ac->user->name,
                'user_password'   => $config->ac->user->pass,
                'user_mail'       => $config->ac->user->mail,
                'user_superadmin' => $config->ac->user->superAdmin,
                'user_anonymous'  => $config->ac->user->anonymousUser,
                'action_deny'     => $config->ac->action->deny,
                'action_login'    => $config->ac->action->login
            );
        }

        return $this->_uris;
    }


    // ------------------------------------------------------------------------
    // --- Public methods -----------------------------------------------------
    // ------------------------------------------------------------------------

    /**
     * This method requests an access token from the configured OAuth provider.
     * Using OAuth grant type "Resource Owner Password Credentials" it sends given user
     * credentials, authenticated by client credentials.
     * 
     * It uses Zend HTTP client with proxy support (extended by Erfurt_App).
     * 
     * Errors are handles by type:
     * - FAILURE_CREDENTIAL_INVALID: configuration insufficient or client credentials are invalid
     * - FAILURE_IDENTITY_NOT_FOUND: user credentials are invalid
     * - FAILURE: every other error
     *
     * @return Zend_Auth_Result
     */
    public function authenticate()
    {
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;

        if( $config->grantType === "code" )
            return $this->authenticateAuthorizationCode();
        else if( $config->grantType === "password" )
            return $this->authenticatePassword();
    }

    static public function refreshToken()
    {
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;
        $refreshToken = $app->getAuth()->getIdentity()->getOAuthRefreshToken();
        if (!$refreshToken) {
            $msg  = 'Unauthorized: token outdated and no refresh token available.';
            throw new Exception($msg, Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID);
        }

        if (!strlen(trim($providerUrl = $config->providerUrl))) {
            $msg = 'OAuth config error: No OAuth provider configured';
            throw new Exception($msg);
        }
        if (!strlen(trim($clientId = $config->clientId))) {
            $msg = 'OAuth config error: No OAuth client ID configured';
            throw new Exception($msg);
        }
        if (!strlen(trim($clientSecret = $config->clientSecret))) {
            $msg = 'OAuth config error: No OAuth client secret configured';
            throw new Exception($msg);
        }

        $postData	= array(
            'grant_type'	=> 'refresh_token',
            'refresh_token'	=> $refreshToken,
        );

        $client = $app->getHttpClient($providerUrl.'/oauth/token');
        $client->setAuth($clientId, $clientSecret, Zend_Http_Client::AUTH_BASIC);
//        $client->setHeaders('Authorization', 'bearer '.$accessToken);
        $client->setRawData(http_build_query($postData));
        $response = $client->request(Zend_Http_Client::POST);
        $data = json_decode($response->getBody());
//print_r($app->getAuth()->getIdentity());
//die;
        $app->getAuth()->getIdentity()->setOAuthAccessToken( $data->access_token );
    }

    static public function sparql( $query ){
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;
        $path   = "/proxy/" . $config->proxyId . '/sparql';
        return self::readResource( $path, array( 'query' => $query ) );
    }

    static public function readResource( $path, $postData = NULL )
    {
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;#
        $identity    = $app->getAuth()->getIdentity();
        if (!$identity){
//            throw new RuntimeException('Not authenticated');
            return null;
        }
        $accessToken = $identity->getOAuthAccessToken();

        if (!strlen(trim($providerUrl = $config->providerUrl))) {
            $msg = 'OAuth config error: No OAuth provider configured';
            throw new Exception($msg);
        }
        if (!strlen(trim($clientId = $config->clientId))) {
            $msg = 'OAuth config error: No OAuth client ID configured';
            throw new Exception($msg);
        }
        if (!strlen(trim($clientSecret = $config->clientSecret))) {
            $msg = 'OAuth config error: No OAuth client secret configured';
            throw new Exception($msg);
        }

        $client = $app->getHttpClient($providerUrl.$path);
//        $client->setAuth($clientId, $clientSecret, Zend_Http_Client::AUTH_BASIC);
        $client->setHeaders('Authorization', 'bearer '.$accessToken);
        $method = Zend_Http_Client::GET;
        if ($postData) {
            $method = Zend_Http_Client::POST;
            $client->setRawData(http_build_query($postData));
        }
        $response = $client->request($method);
        $data = json_decode($response->getBody());

        // handle errors
        if (!empty($data->error)) {
            if($data->error == "invalid_token"){
                self::refreshToken();
                return self::readResource( $path );
            }

            // error: client credentials are invalid
            if ($data->error === "Unauthorized") {
                $msg  = 'Unauthorized: OAuth client credentials invalid.';
                throw new Exception($msg, Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID);
            }

            // error: user credentials are invalid
            if ($data->error === "") {
                $msg  = 'Bad credentials: OAuth authentication failed.';
                throw new Exceptino($msg, Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND);
            }

            // error: others - be more verbose by adding error description
            $msg    = 'OAuth error: ' . $data->error;
            if (!empty($data->error_description)) {
                $msg .= " (" . utf8_encode($data->error_description) . ")";
            }
            throw new Exception($msg, Zend_Auth_Result::FAILURE);
        }
        return $data;
    }

    // ------------------------------------------------------------------------
    // --- Protected methods --------------------------------------------------
    // ------------------------------------------------------------------------

    protected function authenticateAuthorizationCode()
    {
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;

        if (!strlen(trim($providerUrl = $config->providerUrl))) {
            $msg = 'OAuth config error: No OAuth provider configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }
        if (!strlen(trim($clientId = $config->clientId))) {
            $msg = 'OAuth config error: No OAuth client ID configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }
        if (!strlen(trim($clientSecret = $config->clientSecret))) {
            $msg = 'OAuth config error: No OAuth client secret configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }
        if (empty($this->_get['code'])) {
            return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $this->_getAnonymousUser());
        }

        $postData = array(
            'grant_type'  => "authorization_code",
            'code'        => $this->_get['code'],
            'redirect_uri'=> $this->_redirectUri,
        );

        $client = $app->getHttpClient($providerUrl.'/oauth/token');
        $client->setAuth($clientId, $clientSecret, Zend_Http_Client::AUTH_BASIC);
        $client->setRawData(http_build_query($postData));
        $response = $client->request(Zend_Http_Client::POST);
        $data = json_decode($response->getBody());

        // handle errors
        if (!empty($data->error)) {

            // error: client credentials are invalid
            if ($data->error === "Unauthorized") {
                $msg    = 'OAuth client credentials invalid.';
                $result = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
                return new Zend_Auth_Result($result, null, array($msg));
            }

            // error: user credentials are invalid
            if ($data->error === "Bad credentials") {
                $msg    = 'OAuth authentication failed.';
                $result = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
                return new Zend_Auth_Result($result, null, array($msg));
            }

            // error: others - be more verbose by adding error description
            $msg    = 'OAuth error: ' . $data->error;
            if (!empty($data->error_description)) {
                $msg .= " (" . utf8_encode($data->error_description) . ")";
            }
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, null, array($msg));
        }

        //  handle success
        if (!empty($data->access_token)) {
            $identity = array(
                'username'       => $this->_username,
                'uri'            => '' . $this->_username,											//  @todo make an URI!
                'dbuser'         => (($this->_username === 'SuperAdmin') ? true : false), 
                'anonymous'      => false,
                'is_oauth_user'  => true,
                'access_token'   => $data->access_token,
                'refresh_token'  => $data->refresh_token,
                'expires'        => time() + $data->expires_in
            );
            $identityObject = new Erfurt_Auth_Identity($identity);
            $msg = 'OAuth authentication successful.';
            $result = Zend_Auth_Result::SUCCESS;
            return new Zend_Auth_Result($result, $identityObject, array($msg));
        }
    }

    protected function authenticatePassword()
    {
        $app = Erfurt_App::getInstance();
        $config = $app->getConfig()->auth->oauth;

        // check OAuth provider and client configuration
        $result = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
        if (!strlen(trim($providerUrl = $config->providerUrl))) {
            $msg = 'OAuth config error: No OAuth provider configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }
        if (!strlen(trim($clientId = $config->clientId))) {
            $msg = 'OAuth config error: No OAuth client ID configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }
        if (!strlen(trim($clientSecret = $config->clientSecret))) {
            $msg = 'OAuth config error: No OAuth client secret configured';
            return new Zend_Auth_Result($result, null, array($msg));
        }

        // prepare POST data for request
        $postData = array(
            'grant_type' => "password",
            'username' => $this->_username,
            'password' => $this->_password,
        );

        // setup HTTP client (with proxy support) with client credentials for basic authentication
        $client = $app->getHttpClient($providerUrl.'/oauth/token');
        $client->setAuth($clientId, $clientSecret, Zend_Http_Client::AUTH_BASIC);
        $client->setRawData(http_build_query($postData));
        $response = $client->request(Zend_Http_Client::POST);
        $data = json_decode($response->getBody());

        // handle errors
        if (!empty($data->error)) {

            // error: client credentials are invalid
            if ($data->error === "Unauthorized") {
                $msg    = 'OAuth client credentials invalid.';
                $result = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
                return new Zend_Auth_Result($result, null, array($msg));
            }

            // error: user credentials are invalid
            if ($data->error === "Bad credentials") {
                $msg    = 'OAuth authentication failed.';
                $result = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
                return new Zend_Auth_Result($result, null, array($msg));
            }

            // error: others - be more verbose by adding error description
            $msg    = 'OAuth error: ' . $data->error;
            if (!empty($data->error_description)) {
                $msg .= " (" . utf8_encode($data->error_description) . ")";
            }
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, null, array($msg));
        }

        //  handle success
        if (!empty($data->access_token)) {
            $identity = array(
                'username'       => $this->_username,
                'uri'            => '' . $this->_username,
                'dbuser'         => (($this->_username === 'SuperAdmin') ? true : false), 
                'anonymous'      => false,
                'is_oauth_user'  => true,
                'access_token'   => $data->access_token,
            );
            $identityObject = new Erfurt_Auth_Identity($identity);
            $msg = 'OAuth authentication successful.';
            $result = Zend_Auth_Result::SUCCESS;
            return new Zend_Auth_Result($result, $identityObject, array($msg));
        }
    }
}
