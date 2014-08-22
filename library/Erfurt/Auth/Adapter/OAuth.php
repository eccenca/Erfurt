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

    /**
     * Constructor
     */
    public function __construct($username = null, $password = null) 
    {        
        // store given user credentials
        $this->_username = $username;
        $this->_password = $password;
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
        $client = $app->getHttpClient($providerUrl);
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
            $msg    = 'OAuth error: ' . $data->error . utf8_encode( $desc );
            if (!empty($data->error_description)) {
                $msg = "(" . $data->error_description . ")";
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

    // ------------------------------------------------------------------------
    // --- Protected methods --------------------------------------------------
    // ------------------------------------------------------------------------

}
