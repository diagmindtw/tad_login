<?php
use XoopsModules\Tadtools\Utility;
use XoopsModules\Tad_login\Tools;

require_once dirname(dirname(__DIR__)) . '/mainfile.php';

if (!class_exists('XoopsModules\Tad_login\Tools')) {
    require XOOPS_ROOT_PATH . '/modules/tad_login/preloads/autoloader.php';
}

// Verify state to prevent CSRF attacks
if (!isset($_GET['state']) || !isset($_SESSION['auth0_state']) || $_GET['state'] !== $_SESSION['auth0_state']) {
    die('Invalid state parameter');
}

// Clear state
unset($_SESSION['auth0_state']);

if (!isset($_GET['code'])) {
    die('No authorization code received');
}

$code = $_GET['code'];

// Get Auth0 configuration
$domain = $xoopsModuleConfig['auth0_domain'];
$clientId = $xoopsModuleConfig['auth0_client_id'];
$clientSecret = $xoopsModuleConfig['auth0_client_secret'];
$redirectUri = XOOPS_URL . '/modules/tad_login/auth0_callback.php';

// Exchange code for access token
$tokenUrl = "https://{$domain}/oauth/token";
$tokenData = [
    'grant_type' => 'authorization_code',
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
    'code' => $code,
    'redirect_uri' => $redirectUri,
];

$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tokenData));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    die('Failed to exchange code for token');
}

$tokenResponse = json_decode($response, true);
if (!isset($tokenResponse['access_token'])) {
    die('No access token received');
}

$accessToken = $tokenResponse['access_token'];

// Get user info
$userInfoUrl = "https://{$domain}/userinfo";
$ch = curl_init($userInfoUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer {$accessToken}",
]);

$userInfoResponse = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    die('Failed to get user info');
}

$userInfo = json_decode($userInfoResponse, true);

// Process user login
if (isset($userInfo['email']) && !empty($userInfo['email'])) {
    $myts = \MyTextSanitizer::getInstance();
    
    // Create username from email
    list($id, $domain) = explode('@', $userInfo['email']);
    $uname = $id . '_auth0';
    
    // Get user information
    $name = isset($userInfo['name']) ? $myts->addSlashes($userInfo['name']) : $myts->addSlashes($userInfo['nickname'] ?? $userInfo['email']);
    $email = $userInfo['email'];
    $bio = $url = $from = $sig = $occ = $msnm = $user_avatar = $aim = $yim = '';
    
    // Optional: Use picture if available
    // if (isset($userInfo['picture'])) {
    //     $user_avatar = $userInfo['picture'];
    // }
    
    Tools::login_xoops($uname, $name, $email, '', '', $url, $from, $sig, $occ, $bio, $aim, $yim, $msnm, $user_avatar);
} else {
    die('No email address found in Auth0 user profile');
}
