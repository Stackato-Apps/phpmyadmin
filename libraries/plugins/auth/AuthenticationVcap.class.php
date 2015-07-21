<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * VCAP Authentication plugin for phpMyAdmin
 *
 * @package    PhpMyAdmin-Authentication
 * @subpackage Config
 */
if (! defined('PHPMYADMIN')) {
    exit;
}

/* Get the authentication interface */
require_once 'libraries/plugins/AuthenticationPlugin.class.php';

/**
 * Handles the vcap authentication method
 *
 * @package PhpMyAdmin-Authentication
 */
class AuthenticationVcap extends AuthenticationPlugin
{
    /**
     * Displays authentication form
     *
     * @return boolean always true
     */
    public function auth()
    {
        /* Perform logout to custom URL */
        if (!empty($_REQUEST['old_usr']) && !empty($GLOBALS['cfg']['Server']['LogoutURL'])) {
            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
            exit;
        }
        $pma_password = PMA_getenv('PMA_PASSWORD');
        if (!empty($pma_password) && $GLOBALS['cfg']['bound_services'] != false) {
            if (empty($GLOBALS['cfg']['Server']['auth_http_realm'])) {
                if (empty($GLOBALS['cfg']['Server']['verbose'])) {
                    $server_message = $GLOBALS['cfg']['Server']['host'];
                } else {
                    $server_message = $GLOBALS['cfg']['Server']['verbose'];
                }
                $realm_message = 'phpMyAdmin ' . $server_message;
            } else {
                $realm_message = $GLOBALS['cfg']['Server']['auth_http_realm'];
            }
            // remove non US-ASCII to respect RFC2616
            $realm_message = preg_replace('/[^\x20-\x7e]/i', '', $realm_message);
            header('WWW-Authenticate: Basic realm="' . $realm_message . '"');
            header('HTTP/1.0 401 Unauthorized');
            if (php_sapi_name() !== 'cgi-fcgi') {
                header('status: 401 Unauthorized');
            }
        }

        $vcap_application = json_decode(PMA_getenv('VCAP_APPLICATION'));

        // Defines the charset to be used
        header('Content-Type: text/html; charset=utf-8');
        /* HTML header */
        $page_title = __('Access denied');
        ?>
        <style type="text/css">
            code {
                background-color: #EEE; padding: 2px; font-weight: bold;
            }
            a.app-console {
                text-decoration: underline;
                color: blue;
            }
        </style>
    </head>
    <body>
        <?php
            if (file_exists(CUSTOM_HEADER_FILE)) {
                include CUSTOM_HEADER_FILE;
            }
            ?>

    <br /><br />
    <center>
        <img src="./themes/pmahomme/img/logo_right.png" id="imLogo" name="imLogo" alt="phpMyAdmin" border="0">
        <h1><?php echo sprintf(__('Welcome to %s'), ' phpMyAdmin'); ?></h1>
    </center>
    <br />
    <div style="padding:18px">
        <?php

        if ($GLOBALS['cfg']['bound_services'] == false) {
            PMA_Message::error(__('One or more MySQL services must be bound.'))->display();
            ?>

    <p>You must have a MySQL service bound to this app.</p>

    <p>Bind a service using: <code>stackato bind-service &lt;servicename&gt; &lt;app-name&gt;</code></p>
    <br />
    <br />
            <?php
        }

        if (empty($pma_password)) {
            PMA_Message::error(__('PMA_PASSWORD environment variable is not set.'))->display();
            ?>

    <p>You must set the PMA_PASSWORD environment variable.</p>

    <p>Set the PMA_PASSWORD environment variable in the Management Console or use the <code>stackato env-add</code> command.</p>
    <code>stackato env-add &lt;app-name&gt; PMA_PASSWORD='&lt;password&gt;'</code>
    <?php
        } else if ($GLOBALS['cfg']['bound_services'] == true) {
            PMA_Message::error(__('Wrong username/password. Access denied.'))->display();
        }
    ?>
    </div>
    <?php
        if (file_exists(CUSTOM_FOOTER_FILE)) {
            include CUSTOM_FOOTER_FILE;
        }
        ?>

    </body>
    </html>
        <?php
        exit();
    }

    /**
    * Gets advanced authentication settings
    *
    * @global string the username if register_globals is on
    * @global string the password if register_globals is on
    * @global array the array of server variables if register_globals is
    * off
    * @global array the array of environment variables if register_globals
    * is off
    * @global string the username for the ? server
    * @global string the password for the ? server
    * @global string the username for the WebSite Professional server
    * @global string the password for the WebSite Professional server
    * @global string the username of the user who logs out
    *
    * @return boolean whether we get authentication settings or not
    *
    * @access public
    */
    public function authCheck()
    {
        global $PHP_AUTH_USER, $PHP_AUTH_PW;
        global $old_usr;

        // Grabs the $PHP_AUTH_USER variable whatever are the values of the
        // 'register_globals' and the 'variables_order' directives
        if (empty($PHP_AUTH_USER)) {
            if (PMA_getenv('PHP_AUTH_USER')) {
                $PHP_AUTH_USER = PMA_getenv('PHP_AUTH_USER');
            } elseif (PMA_getenv('REMOTE_USER')) {
                // CGI, might be encoded, see below
                $PHP_AUTH_USER = PMA_getenv('REMOTE_USER');
            } elseif (PMA_getenv('REDIRECT_REMOTE_USER')) {
                // CGI, might be encoded, see below
                $PHP_AUTH_USER = PMA_getenv('REDIRECT_REMOTE_USER');
            } elseif (PMA_getenv('AUTH_USER')) {
                // WebSite Professional
                $PHP_AUTH_USER = PMA_getenv('AUTH_USER');
            } elseif (PMA_getenv('HTTP_AUTHORIZATION')) {
                // IIS, might be encoded, see below
                $PHP_AUTH_USER = PMA_getenv('HTTP_AUTHORIZATION');
            } elseif (PMA_getenv('Authorization')) {
                // FastCGI, might be encoded, see below
                $PHP_AUTH_USER = PMA_getenv('Authorization');
            }
        }
        // Grabs the $PHP_AUTH_PW variable whatever are the values of the
        // 'register_globals' and the 'variables_order' directives
        if (empty($PHP_AUTH_PW)) {
            if (PMA_getenv('PHP_AUTH_PW')) {
                $PHP_AUTH_PW = PMA_getenv('PHP_AUTH_PW');
            } elseif (PMA_getenv('REMOTE_PASSWORD')) {
                // Apache/CGI
                $PHP_AUTH_PW = PMA_getenv('REMOTE_PASSWORD');
            } elseif (PMA_getenv('AUTH_PASSWORD')) {
                // WebSite Professional
                $PHP_AUTH_PW = PMA_getenv('AUTH_PASSWORD');
            }
        }

        // Decode possibly encoded information (used by IIS/CGI/FastCGI)
        // (do not use explode() because a user might have a colon in his password
        if (strcmp(substr($PHP_AUTH_USER, 0, 6), 'Basic ') == 0) {
            $usr_pass = base64_decode(substr($PHP_AUTH_USER, 6));
            if (! empty($usr_pass)) {
                $colon = strpos($usr_pass, ':');
                if ($colon) {
                    $PHP_AUTH_USER = substr($usr_pass, 0, $colon);
                    $PHP_AUTH_PW = substr($usr_pass, $colon + 1);
                }
                unset($colon);
            }
            unset($usr_pass);
        }

        // User logged out -> ensure the new username is not the same
        if (!empty($old_usr)
            && (isset($PHP_AUTH_USER) && $old_usr == $PHP_AUTH_USER)) {
            $PHP_AUTH_USER = '';
            // -> delete user's choices that were stored in session
            session_destroy();
        }

        // Must have a bound service
        if ($GLOBALS['cfg']['bound_services'] == false) {
            return false;
        }

        // Must submit a username and password
        if (!isset($PHP_AUTH_USER) || empty($PHP_AUTH_PW)) {
            return false;
        }

        $pma_username = PMA_getenv('PMA_USERNAME');
        $vcap_application = json_decode(PMA_getenv('VCAP_APPLICATION'));
        if (!empty($pma_username)) {
          if ($PHP_AUTH_USER !== $pma_username) {
            return false;
          }
        } else if (!in_array($PHP_AUTH_USER, $vcap_application->users)) {
          return false;
        }

        $pma_password = PMA_getenv('PMA_PASSWORD');
        if ($PHP_AUTH_PW != $pma_password) {
            return false;
        }

        return true;
    }

    /**
    * Set the user and password after last checkings if required
    *
    * @global array the valid servers settings
    * @global integer the id of the current server
    * @global array the current server settings
    * @global string the current username
    * @global string the current password
    *
    * @return boolean always true
    *
    * @access public
    */
    public function authSetUser()
    {
        // Avoid showing the password in phpinfo()'s output
        unset($GLOBALS['PHP_AUTH_PW']);
        unset($_SERVER['PHP_AUTH_PW']);

        return true;
    }

    /**
    * User is not allowed to login to MySQL -> authentication failed
    *
    * @return boolean always true (no return indeed)
    *
    * @access public
    */
    public function authFails()
    {
        $error = PMA_DBI_getError();
        if ($error && $GLOBALS['errno'] != 1045) {
            PMA_fatalError($error);
        } else {
            PMA_auth();
            return true;
        }
    }
}
?>

