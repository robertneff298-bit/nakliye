<?php
/**
 * Ziyaretçi bilgilerini ve proxy IP'lerini kaydetme endpoint'i
 * POST isteği alır ve JSON formatında bir log dosyasına kaydeder
 */

// CORS ve veri alma
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

// POST isteği kontrolü
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Only POST allowed']);
    exit;
}

// İstemci IP'leri (proxy dahil)
function getClientIPs() {
    $ips = [];
    
    // Doğrudan IP
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $ips['remote_addr'] = $_SERVER['REMOTE_ADDR'];
    }
    
    // X-Forwarded-For (reverse proxy, CDN)
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
        $ips['x_forwarded_for'] = $forwarded;
    }
    
    // Cloudflare
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ips['cloudflare_ip'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    
    // X-Real-IP (Nginx)
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ips['x_real_ip'] = $_SERVER['HTTP_X_REAL_IP'];
    }
    
    // Client-IP
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ips['client_ip'] = $_SERVER['HTTP_CLIENT_IP'];
    }
    
    return $ips;
}

// JSON verisini oku
$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!$data) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

// Sunucu tarafından toplanan bilgiler
$serverData = [
    'timestamp' => date('Y-m-d H:i:s'),
    'client_ips' => getClientIPs(),
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
    'referer' => $_SERVER['HTTP_REFERER'] ?? 'none',
    'method' => $_SERVER['REQUEST_METHOD'],
    'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'http_headers' => array_filter([
        'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
        'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? null,
        'connection' => $_SERVER['HTTP_CONNECTION'] ?? null,
        'x_forwarded_proto' => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null,
        'x_forwarded_port' => $_SERVER['HTTP_X_FORWARDED_PORT'] ?? null,
    ], fn($v) => $v !== null)
];

// Client ve server verisini birleştir
$logEntry = array_merge(['client_data' => $data], $serverData);

// Log dosyasının yolu
$logDir = __DIR__ . '/../logs';
if (!is_dir($logDir)) {
    mkdir($logDir, 0755, true);
}

$logFile = $logDir . '/visitor_log_' . date('Y-m-d') . '.json';

// Append to log (JSONL format)
$logContent = json_encode($logEntry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
file_put_contents($logFile, $logContent, FILE_APPEND | LOCK_EX);

// CSV export için de bir backup
$csvFile = $logDir . '/visitor_log_' . date('Y-m-d') . '.csv';
$csvLine = implode(',', [
    '"' . date('Y-m-d H:i:s') . '"',
    '"' . ($logEntry['client_ips']['remote_addr'] ?? 'N/A') . '"',
    '"' . implode(';', (array)($logEntry['client_ips']['x_forwarded_for'] ?? [])) . '"',
    '"' . ($logEntry['user_agent'] ?? 'N/A') . '"',
    '"' . ($logEntry['referer'] ?? 'N/A') . '"',
    '"' . ($data['pageURL'] ?? 'N/A') . '"',
    '"' . ($data['clientIP'] ?? 'N/A') . '"'
]) . PHP_EOL;

if (!file_exists($csvFile)) {
    $csvHeader = '"Timestamp","Server_IP","X-Forwarded-For","User-Agent","Referer","Page_URL","Client_IP"' . PHP_EOL;
    file_put_contents($csvFile, $csvHeader, FILE_APPEND);
}
file_put_contents($csvFile, $csvLine, FILE_APPEND);

// Başarı yanıtı
http_response_code(200);
echo json_encode([
    'success' => true,
    'message' => 'Visitor logged',
    'timestamp' => $logEntry['timestamp']
]);
?>
