<?php
use XoopsModules\Tadtools\Utility;
use XoopsModules\Tad_login\Tools;

require_once dirname(dirname(__DIR__)) . '/mainfile.php';

if (!class_exists('XoopsModules\Tad_login\Tools')) {
    require XOOPS_ROOT_PATH . '/modules/tad_login/preloads/autoloader.php';
}

// Verify state to prevent CSRF attacks
if (!isset($_GET['state'])) {
    die('Missing state parameter');
}
if (!isset($_SESSION['auth0_state'])) {
    die('Missing state in session - please try logging in again');
}
if ($_GET['state'] !== $_SESSION['auth0_state']) {
    die('State parameter mismatch - possible CSRF attack');
}

// Clear state
unset($_SESSION['auth0_state']);

if (!isset($_GET['code'])) {
    die('No authorization code received');
}

$code = $_GET['code'];

// Get Auth0 configuration
$TadLoginModuleConfig = Utility::getXoopsModuleConfig('tad_login');
$domain = $TadLoginModuleConfig['auth0_domain'];
$clientId = $TadLoginModuleConfig['auth0_client_id'];
$clientSecret = $TadLoginModuleConfig['auth0_client_secret'];
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
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    die('Failed to exchange code for token. HTTP Status: ' . $httpCode . '. Response: ' . htmlspecialchars($response));
}

$tokenResponse = json_decode($response, true);
if (!isset($tokenResponse['access_token'])) {
    die('No access token received. Response: ' . htmlspecialchars($response));
}

$accessToken = $tokenResponse['access_token'];

// Get user info
$userInfoUrl = "https://{$domain}/userinfo";
$ch = curl_init($userInfoUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer {$accessToken}",
]);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

$userInfoResponse = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    die('Failed to get user info. HTTP Status: ' . $httpCode . '. Response: ' . htmlspecialchars($userInfoResponse));
}

$userInfo = json_decode($userInfoResponse, true);

// Process user login
if (isset($userInfo['email']) && !empty($userInfo['email'])) {
    $myts = \MyTextSanitizer::getInstance();
    
    // Create username from email (discard domain portion)
    list($id, ) = explode('@', $userInfo['email']);
    $uname = $id . '_auth0';
    
    // Get user information - try name, fallback to nickname, then email
    $name = $myts->addSlashes($userInfo['name'] ?? $userInfo['nickname'] ?? $userInfo['email']);
    $email = $userInfo['email'];
    $bio = $url = $from = $sig = $occ = $msnm = $user_avatar = $aim = $yim = '';
    
    // Optional: Use picture if available
    // if (isset($userInfo['picture'])) {
    //     $user_avatar = $userInfo['picture'];
    // }
    
    Tools::login_xoops($uname, $name, $email, '', '', $url, $from, $sig, $occ, $bio, $aim, $yim, $msnm, $user_avatar);
} else {
    die('No email address found in Auth0 user profile. Please ensure your Auth0 application requests the email scope and that your email is verified in your Auth0 profile.');
}
