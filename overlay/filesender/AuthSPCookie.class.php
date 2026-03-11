<?php

/**
 * Custom authentication class for FileSender
 * Trusts the REMOTE_USER header set by an upstream proxy/server
 *
 * Place this file in: classes/auth/AuthRemoteUser.class.php
 */

if (!defined('FILESENDER_BASE')) {
    die('Missing environment');
}

/**
 * Remote User (Header-based) Authentication
 *
 * This authenticator trusts the REMOTE_USER server variable
 * which is typically set by Apache mod_auth_*, nginx auth_request,
 * or other reverse proxy authentication mechanisms.
 */
class AuthSPCookie {
    /**
     * The authenticated user's attributes
     */
    private static $attributes = null;

    /**
     * Check if user is authenticated via REMOTE_USER
     *
     * @return bool
     */
    public static function isAuthenticated() {
        Logger::warn("Check if user is authenticated, printing all headers:");
        return self::getRemoteUser() !== null;
    }

    /**
     * Get the REMOTE_USER value from server variables
     *
     * @return string|null
     */
    private static function getRemoteUser() {
        Logger::warn("Getting remote user from headers:");

        // Check multiple possible header locations
        $remoteUser = null;

        foreach (getallheaders() as $name => $value) {
            Logger::warn("$name: $value\n");

            if ($name == "Remoteuser"){
                $remoteUser = $value;
                Logger::warn("Remote user set to $remoteUser");
            }
        }

        // Standard REMOTE_USER (set by Apache/nginx)
        if (!empty($_SERVER['Remoteuser'])) {
            $remoteUser = $_SERVER['Remoteuser'];
        }
        // Redirect version (some configurations)
        elseif (!empty($_SERVER['REDIRECT_REMOTE_USER'])) {
            $remoteUser = $_SERVER['REDIRECT_REMOTE_USER'];
        }
        // HTTP header version (when passed through proxy)
        elseif (!empty($_SERVER['HTTP_REMOTE_USER'])) {
            $remoteUser = $_SERVER['HTTP_REMOTE_USER'];
        }

        // Sanitize the username
        if ($remoteUser !== null) {
            $remoteUser = trim($remoteUser);
            if (empty($remoteUser)) {
                Logger::warn("Remote user is empty, returning null");
                return null;
            }
        }

        Logger::warn("Remote user is $remoteUser ");
        return $remoteUser;
    }

    /**
     * Get user attributes
     *
     * @return array
     */
    public static function attributes() {
        if (self::$attributes !== null) {
            return self::$attributes;
        }

        $remoteUser = self::getRemoteUser();

        if ($remoteUser === null) {
            return array();
        }

        // We generate a uid from the byte array of the username - needs a proper mapping/implementation
        $uid = 0;
        $byte_array = unpack('C*', $remoteUser);
        foreach ($byte_array as $value) {
            $uid += $value;
        }

        // Build attributes array
        self::$attributes = array(
            'uid' => $uid,
            'email' => array(self::deriveEmail($remoteUser)),
            'name' => array(self::deriveName($remoteUser)),
        );

        // Add additional attributes from headers if available
        if (!empty($_SERVER['HTTP_REMOTE_USER_EMAIL'])) {
            self::$attributes['email'] = array($_SERVER['HTTP_REMOTE_USER_EMAIL']);
        }

        if (!empty($_SERVER['HTTP_REMOTE_USER_NAME'])) {
            self::$attributes['name'] = array($_SERVER['HTTP_REMOTE_USER_NAME']);
        }

        return self::$attributes;
    }

    /**
     * Derive email from username
     *
     * @param string $username
     * @return string
     */
    private static function deriveEmail($username) {
        // If username is already an email, return it
        if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
            return $username;
        }

        // Otherwise, try to construct email from config
        $defaultDomain = Config::get('auth_remote_user_default_domain');
        if ($defaultDomain) {
            return $username . '@' . $defaultDomain;
        }

        // Fallback: return username as-is
        return $username;
    }

    /**
     * Derive display name from username
     *
     * @param string $username
     * @return string
     */
    private static function deriveName($username) {
        // Remove domain part if email
        if (strpos($username, '@') !== false) {
            $username = substr($username, 0, strpos($username, '@'));
        }

        // Convert underscores/dots to spaces and capitalize
        $name = str_replace(array('_', '.'), ' ', $username);
        return ucwords($name);
    }

    /**
     * Trigger authentication (redirect or display login)
     * For header-based auth, we just return - the upstream handles login
     */
    public static function trigger() {
        // If not authenticated, return 401
        if (!self::isAuthenticated()) {
            header('HTTP/1.1 401 Unauthorized');
            die('Authentication required. Please ensure you are accessing this through the authenticated proxy.');
        }
    }

    /**
     * Logout the user
     */
    public static function logout() {
        // Clear any session data
        self::$attributes = null;

        // Get logout URL from config if set
        $logoutUrl = Config::get('auth_remote_user_logout_url');
        if ($logoutUrl) {
            header('Location: ' . $logoutUrl);
            exit;
        }
    }

    /**
     * Generate the logon URL.
     *
     * @param $target
     *
     * @retrun string
     */
    public static function logonURL($target = null)
    {
        if (!$target) {
            $landing_page = Config::get('landing_page');
            if (!$landing_page) {
                $landing_page = 'upload';
            }
            $target = Utilities::http_build_query(array('s' => $landing_page));
        }

        return Config::get('site_url').'#logon-'.urlencode($target);
    }

    /**
     * Generate the logoff URL.
     *
     * @param $target
     *
     * @retrun string
     */
    public static function logoffURL($target = null)
    {
        if (!$target) {
            $target = Config::get('site_logouturl');
        }

        return Config::get('site_url').'#logoff-'.urlencode($target);
    }
}
