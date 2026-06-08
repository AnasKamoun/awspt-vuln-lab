<?php
// INTENTIONALLY VULNERABLE TEST LAB — DO NOT DEPLOY. Validates SAST taint tracking.
// All inputs are untrusted ($_GET/$_POST/$_SERVER/$_COOKIE/php://input/getenv/$argv).

// --- Hardcoded FAKE secrets (realistic shapes) ---
$DB_HOST = "127.0.0.1";
$DB_USER = "root";
$DB_PASS = "P@ssw0rd_root_2024!";                                  // CWE-798: hardcoded credentials
$AWS_ACCESS_KEY_ID = "AKIAJ4XEXAMPLE7QFAKEZ";                      // CWE-798: hardcoded AWS key
$AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // CWE-798: hardcoded AWS secret
$STRIPE_KEY = "sk_live_51Mq8kFAKEexampleSecretKeyAbCdEf0123456789"; // CWE-798: hardcoded API token

function db_connect() {
    global $DB_HOST, $DB_USER, $DB_PASS;
    return mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, "appdb");
}

// CWE-89: SQL injection — request param concatenated into query
function sqli_lookup() {
    $conn = db_connect();
    $id = $_GET["id"];
    $sql = "SELECT username, email FROM users WHERE id = " . $id;
    $res = mysqli_query($conn, $sql);
    while ($row = mysqli_fetch_assoc($res)) {
        echo $row["username"];
    }
}

// CWE-78: OS command injection via system()
function cmd_system() {
    $cmd = $_GET["cmd"];
    system("ping -c 1 " . $cmd);
}

// CWE-78: OS command injection via exec()
function cmd_exec() {
    $host = $_POST["host"];
    exec("nslookup " . $host, $out);
    print_r($out);
}

// CWE-78: OS command injection via shell_exec()
function cmd_shell_exec() {
    $file = $_GET["file"];
    $data = shell_exec("cat /var/log/" . $file);
    echo $data;
}

// CWE-78: OS command injection via passthru()
function cmd_passthru() {
    $target = $_REQUEST["target"];
    passthru("traceroute " . $target);
}

// CWE-98: Local/Remote File Inclusion — include() of attacker-controlled path
function lfi_include() {
    $page = $_GET["page"];
    include($page . ".php");
}

// CWE-98: RFI via require() — remote URL controllable
function rfi_require() {
    $module = $_GET["module"];
    require("/app/modules/" . $module);
}

// CWE-502: PHP object injection via unserialize() of POST data
function deserialize_payload() {
    $data = $_POST["data"];
    $obj = unserialize($data);
    var_dump($obj);
}

// CWE-95: Code injection via eval() of request body
function eval_code() {
    $code = $_POST["code"];
    eval($code);
}

// CWE-95: Code injection via preg_replace /e modifier
function preg_replace_e() {
    $pattern = $_GET["pat"];
    $subject = $_GET["subj"];
    echo preg_replace("/" . $pattern . "/e", "strtoupper('\\1')", $subject);
}

// CWE-94: assert() executes string expression from input
function assert_eval() {
    $expr = $_GET["expr"];
    assert($expr);
}

// CWE-918: SSRF — fetch attacker-supplied URL server-side
function ssrf_fetch() {
    $url = $_GET["url"];
    $body = file_get_contents($url);
    echo $body;
}

// CWE-918: SSRF via cURL on user URL
function ssrf_curl() {
    $u = $_POST["endpoint"];
    $ch = curl_init($u);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
}

// CWE-79: Reflected XSS — request param echoed unescaped
function xss_reflect() {
    $name = $_GET["x"];
    echo "<div>Hello, " . $name . "</div>";
}

// CWE-79: Stored/DOM XSS sink from header
function xss_header() {
    $ref = $_SERVER["HTTP_REFERER"];
    echo "<a href='" . $ref . "'>back</a>";
}

// CWE-22: Path traversal — read file by user-supplied name
function path_traversal_read() {
    $f = $_GET["doc"];
    readfile("/srv/docs/" . $f);
}

// CWE-434: Unrestricted file upload — extension/content unchecked
function file_upload() {
    $dest = "/var/www/uploads/" . $_FILES["f"]["name"];
    move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
}

// CWE-916/CWE-327: weak password hashing with md5
function weak_password_hash() {
    $pw = $_POST["password"];
    $hash = md5($pw);
    return $hash;
}

// CWE-601: Open redirect — Location set from input
function open_redirect() {
    $next = $_GET["next"];
    header("Location: " . $next);
}

// CWE-90: LDAP injection — filter built from input
function ldap_query() {
    $ds = ldap_connect("ldap://127.0.0.1");
    $user = $_GET["user"];
    ldap_search($ds, "dc=corp,dc=local", "(uid=" . $user . ")");
}

// CWE-643: XPath injection
function xpath_query($doc) {
    $u = $_GET["u"];
    return $doc->xpath("//user[name='" . $u . "']");
}

// CWE-611: XXE — external entities enabled while parsing user XML
function xxe_parse() {
    $xml = file_get_contents("php://input");
    $d = new DOMDocument();
    $d->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
    echo $d->textContent;
}

// CWE-77: command injection from CLI argv / env
function cli_command() {
    $arg = isset($argv[1]) ? $argv[1] : getenv("USER_INPUT");
    popen("backup.sh " . $arg, "r");
}

// CWE-89: second-order SQLi from cookie value
function sqli_cookie() {
    $conn = db_connect();
    $role = $_COOKIE["role"];
    mysqli_query($conn, "SELECT * FROM perms WHERE role='" . $role . "'");
}

// CWE-1004/CWE-614: insecure cookie set from input (no flags)
function set_session_cookie() {
    $sid = $_GET["sid"];
    setcookie("SESSIONID", $sid);
}

// Simple front-controller dispatch so every sink is reachable.
$action = isset($_GET["action"]) ? $_GET["action"] : "";
switch ($action) {
    case "sqli": sqli_lookup(); break;
    case "sys": cmd_system(); break;
    case "exec": cmd_exec(); break;
    case "sh": cmd_shell_exec(); break;
    case "pt": cmd_passthru(); break;
    case "lfi": lfi_include(); break;
    case "rfi": rfi_require(); break;
    case "unser": deserialize_payload(); break;
    case "eval": eval_code(); break;
    case "prege": preg_replace_e(); break;
    case "assert": assert_eval(); break;
    case "ssrf": ssrf_fetch(); break;
    case "curl": ssrf_curl(); break;
    case "xss": xss_reflect(); break;
    case "xssh": xss_header(); break;
    case "trav": path_traversal_read(); break;
    case "upload": file_upload(); break;
    case "redir": open_redirect(); break;
    case "ldap": ldap_query(); break;
    case "xxe": xxe_parse(); break;
    case "cookie": set_session_cookie(); break;
    default: echo "lab ready";
}
