<?php
/**
 * きらきら千葉版 簡易クーポンAPI (PHP 7.4以上)
 * 携帯番号入力のみ。SMS・PIN・外部サービスを使わず、サーバーのJSONで使用履歴を保持します。
 * 注意: 番号の所有者確認や「係員であること」の認証は行いません。
 */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: SAMEORIGIN');

function reply(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function reject(int $code, string $message): void {
    reply($code, ['ok'=>false, 'message'=>$message]);
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') reject(405, 'POSTでアクセスしてください。');
$origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
$host = (string)($_SERVER['HTTP_HOST'] ?? '');
if ($origin !== '') {
    $originHost = parse_url($origin, PHP_URL_HOST);
    $requestHost = parse_url('http://' . $host, PHP_URL_HOST);
    if (!is_string($originHost) || !is_string($requestHost) || strcasecmp($originHost, $requestHost) !== 0) {
        reject(403, 'このサイトから操作してください。');
    }
}
if (isset($_SERVER['HTTP_SEC_FETCH_SITE']) && !in_array($_SERVER['HTTP_SEC_FETCH_SITE'], ['same-origin','none'], true)) {
    reject(403, 'このサイトから操作してください。');
}
$body = file_get_contents('php://input');
if (!is_string($body) || strlen($body) > 4096) reject(400, '送信内容を確認してください。');
$json = json_decode($body, true);
if (!is_array($json)) reject(400, '送信内容を確認してください。');
$action = (string)($json['action'] ?? '');
if (!in_array($action, ['register', 'status', 'redeem'], true)) reject(400, '不正な操作です。');
$config = require __DIR__ . '/coupon_config.php';
if (!is_array($config) || strlen((string)($config['phone_hash_key'] ?? '')) < 48) reject(503, 'サーバー設定に問題があります。');
$key = (string)$config['phone_hash_key'];
$directory = __DIR__ . '/coupon_private';
if (!is_dir($directory)) reject(503, 'データ保存先がありません。');
$dbfile = $directory . '/coupons.json';
if (!is_file($dbfile)) reject(503, 'データファイルがありません。設置手順をご確認ください。');

/** JSONデータは排他ロックを保持したまま読み・変更・書きします。 */
function lockedData(string $filename, callable $modify) {
    $handle = @fopen($filename, 'c+');
    if ($handle === false) reject(503, 'クーポンデータを開けません。');
    if (!flock($handle, LOCK_EX)) { fclose($handle); reject(503, '処理が混み合っています。'); }
    rewind($handle);
    $contents = stream_get_contents($handle);
    $data = $contents === '' ? null : json_decode($contents, true);
    if (!is_array($data) || !isset($data['coupons'], $data['register_limiter']) ||
        !is_array($data['coupons']) || !is_array($data['register_limiter'])) {
        flock($handle, LOCK_UN); fclose($handle);
        reject(503, '保存データの形式に問題があります。管理者にお問い合わせください。');
    }
    $changed = false;
    $result = $modify($data, $changed);
    if ($changed) {
        $encoded = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($encoded === false) { flock($handle, LOCK_UN); fclose($handle); reject(503, '保存処理に失敗しました。'); }
        rewind($handle);
        // Existing file is shortened only while the exclusive lock is held.
        if (ftruncate($handle, 0) === false || fwrite($handle, $encoded) !== strlen($encoded) || fflush($handle) === false) {
            flock($handle, LOCK_UN); fclose($handle); reject(503, 'クーポンの保存に失敗しました。');
        }
    }
    flock($handle, LOCK_UN);
    fclose($handle);
    return $result;
}
function normalizePhone(string $raw): string {
    // Hyphens and whitespace are allowed for convenience; other characters are not.
    $stripped = preg_replace('/[\s\-ー－]/u', '', $raw);
    if (!is_string($stripped) || !preg_match('/^0[789]0[0-9]{8}$/D', $stripped)) {
        reject(400, '070・080・090から始まる11桁の携帯番号を入力してください。');
    }
    return $stripped;
}
function findByToken(array $data, string $token): ?array {
    if (!preg_match('/^[a-f0-9]{64}$/D', $token)) return null;
    $hash = hash('sha256', $token);
    foreach ($data['coupons'] as $id => $record) {
        if (isset($record['token_hash']) && is_string($record['token_hash']) && hash_equals($record['token_hash'], $hash)) {
            return ['id' => (string)$id, 'record'=>$record];
        }
    }
    return null;
}
function publicState(array $record): array {
    return [
        'ok' => true,
        'status' => !empty($record['used_at']) ? 'used' : 'unused',
        'people' => (int)($record['people'] ?? 1),
        'phone_last4' => (string)($record['last4'] ?? ''),
        'used_at' => (string)($record['used_at'] ?? ''),
    ];
}
$tz = new DateTimeZone('Asia/Tokyo');
$now = new DateTimeImmutable('now', $tz);
$today = $now->format('Y-m-d');

if ($action === 'register') {
    $number = normalizePhone((string)($json['phone'] ?? ''));
    $people = filter_var($json['people'] ?? null, FILTER_VALIDATE_INT);
    if ($people === false || $people < 1 || $people > 5) reject(400, '無料対象のお子さまの人数を1～5名で選んでください。');
    if (($json['consent'] ?? null) !== true) reject(400, '電話番号の取り扱いに同意してください。');
    $phoneHash = hash_hmac('sha256', 'phone/' . $number, $key);
    $ipHash = hash_hmac('sha256', 'ip/' . (string)($_SERVER['REMOTE_ADDR'] ?? ''), $key);
    $timestamp = time();
    $token = bin2hex(random_bytes(32));
    $max = max(1, min(200, (int)($config['registration_limit_per_ip_hour'] ?? 30)));
    $result = lockedData($dbfile, static function (&$data, &$changed) use ($phoneHash, $number, $ipHash, $timestamp, $max, $token, $people, $now) {
        // 重複番号を登録させない。SMS認証なしなので別端末への再発行は認めない。
        if (isset($data['coupons'][$phoneHash])) {
            return !empty($data['coupons'][$phoneHash]['used_at']) ? 'already_used' : 'already_registered';
        }
        $items = array_values(array_filter($data['register_limiter'][$ipHash] ?? [], static function ($t) use ($timestamp) {
            return is_numeric($t) && (int)$t > $timestamp - 3600;
        }));
        if (count($items) >= $max) return 'rate_limited';
        $items[] = $timestamp;
        $data['register_limiter'][$ipHash] = $items;
        // Old rate-limit entries are removed to prevent unbounded growth.
        foreach ($data['register_limiter'] as $id => $events) {
            if ($id === $ipHash) continue;
            $events = array_values(array_filter($events, static function ($t) use ($timestamp) {return is_numeric($t) && (int)$t > $timestamp - 3600;}));
            if ($events) $data['register_limiter'][$id] = $events;
            else unset($data['register_limiter'][$id]);
        }
        $entry = [
            'token_hash' => hash('sha256', $token),
            'last4' => substr($number, -4),
            'people' => $people,
            'registered_at' => $now->format('Y/m/d H:i:s'),
            'used_at' => '',
        ];
        $data['coupons'][$phoneHash] = $entry;
        $changed = true;
        return $entry;
    });
    if ($result === 'already_used') reject(409, 'この携帯番号のクーポンはすでに使用済みです。再発行できません。');
    if ($result === 'already_registered') reject(409, 'この携帯番号は登録済みです。最初に登録したスマートフォンの同じブラウザで表示してください。');
    if ($result === 'rate_limited') reject(429, 'この回線からの登録が集中しています。時間をおいてお試しください。');
    reply(200, array_merge(publicState($result), ['token'=>$token]));
}
$token = (string)($json['token'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/D', $token)) reject(401, 'この端末にクーポン情報がありません。');
if ($action === 'status') {
    $found = lockedData($dbfile, static function (&$data, &$changed) use ($token) {return findByToken($data, $token);});
    if ($found === null) reject(404, 'クーポン情報が見つかりません。');
    reply(200, publicState($found['record']));
}
if ($action === 'redeem') {
    $open = (string)($config['coupon_open_date'] ?? '2026-12-26');
    $close = (string)($config['coupon_close_date'] ?? '');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $open) || ($close !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $close))) {
        reject(503, 'クーポン期間の設定を確認してください。');
    }
    if ($today < $open) reject(403, 'クーポンの利用開始は2026年12月26日からです。');
    if ($close !== '' && $today > $close) reject(403, 'クーポンの利用期間は終了しました。');
    $result = lockedData($dbfile, static function (&$data, &$changed) use ($token, $now) {
        $found = findByToken($data, $token);
        if ($found === null) return 'missing';
        $id = $found['id'];
        if (!empty($data['coupons'][$id]['used_at'])) return 'already_used';
        $data['coupons'][$id]['used_at'] = $now->format('Y/m/d H:i:s');
        $changed = true;
        return $data['coupons'][$id];
    });
    if ($result === 'missing') reject(404, 'クーポンが存在しません。');
    if ($result === 'already_used') reject(409, 'このクーポンはすでに使用済みです。再利用できません。');
    reply(200, publicState($result));
}
reject(400, '不正な操作です。');
