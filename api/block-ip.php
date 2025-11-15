<?php
/**
 * Engellenen IP'leri kaydetme ve .htaccess / Nginx config üretme
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Only POST allowed']);
    exit;
}

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!isset($data['ip'])) {
    http_response_code(400);
    echo json_encode(['error' => 'IP required']);
    exit;
}

$ip = $data['ip'];
$blockInfo = $data['blockInfo'] ?? [];

// Engelleme dosyasının yolu
$blockDir = __DIR__ . '/../blocked-ips';
if (!is_dir($blockDir)) {
    mkdir($blockDir, 0755, true);
}

$blockedIPsFile = $blockDir . '/blocked_ips.json';

// Mevcut engelleri oku
$blocked = [];
if (file_exists($blockedIPsFile)) {
    $blocked = json_decode(file_get_contents($blockedIPsFile), true) ?? [];
}

// Yeni IP'yi ekle
if (!isset($blocked[$ip])) {
    $blocked[$ip] = array_merge($blockInfo, [
        'blockedAt' => date('Y-m-d H:i:s'),
        'expiresAt' => date('Y-m-d H:i:s', strtotime('+1 hour')) // 1 saat sonra kaldırılır
    ]);
    
    // Dosyaya kaydet
    file_put_contents($blockedIPsFile, json_encode($blocked, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    
    // .htaccess veya Nginx config oluştur
    generateBlockingRules($blocked);
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => "IP $ip engellendi",
        'blockedAt' => $blocked[$ip]['blockedAt'],
        'expiresAt' => $blocked[$ip]['expiresAt']
    ]);
} else {
    http_response_code(200);
    echo json_encode([
        'success' => false,
        'message' => "IP $ip zaten engelli",
        'blockedAt' => $blocked[$ip]['blockedAt']
    ]);
}

/**
 * .htaccess kuralları oluştur (Apache)
 */
function generateBlockingRules($blocked) {
    $blockDir = __DIR__ . '/../blocked-ips';
    
    // .htaccess dosyası
    $htaccessContent = "# Auto-generated blocking rules\n";
    $htaccessContent .= "# DO NOT EDIT MANUALLY\n";
    $htaccessContent .= "# Son güncelleme: " . date('Y-m-d H:i:s') . "\n\n";
    $htaccessContent .= "Order Allow,Deny\n";
    $htaccessContent .= "Allow from all\n\n";
    
    foreach (array_keys($blocked) as $ip) {
        // Geçerli IP formatı kontrolü
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $htaccessContent .= "Deny from $ip\n";
        }
    }
    
    file_put_contents($blockDir . '/.htaccess', $htaccessContent);
    
    // Nginx blocklist (kullanıcı tarafından elle include edilecek)
    $nginxContent = "# Auto-generated Nginx blocking rules\n";
    $nginxContent .= "# Include this in your server block:\n";
    $nginxContent .= "# include /path/to/blocked-ips/nginx-blocklist.conf;\n\n";
    
    foreach (array_keys($blocked) as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $nginxContent .= "deny $ip;\n";
        }
    }
    
    file_put_contents($blockDir . '/nginx-blocklist.conf', $nginxContent);
    
    // UFW blocklist (Linux firewall)
    $ufwContent = "#!/bin/bash\n";
    $ufwContent .= "# Auto-generated UFW blocking script\n";
    $ufwContent .= "# Run: sudo bash blocked-ips/ufw-blocklist.sh\n\n";
    
    foreach (array_keys($blocked) as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $ufwContent .= "sudo ufw deny from $ip\n";
        }
    }
    
    file_put_contents($blockDir . '/ufw-blocklist.sh', $ufwContent);
    chmod($blockDir . '/ufw-blocklist.sh', 0755);
}

?>
