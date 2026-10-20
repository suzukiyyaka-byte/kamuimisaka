<?php
/**
 * カムイみさか・きらきら千葉版 簡易クーポン設定
 * 追加の外部認証サービス／係員PINは不要です。
 * phone_hash_key は公開後は変更しないでください（変更すると既存番号の重複照合ができません）。
 * このファイルはPHPとして実行できるサーバーに設置してください。
 */
return [
    'phone_hash_key' => 'a9aa430534d429a31ed9425fefca487e4f005b2df35438c5f492c8d93cda59aa',
    'coupon_open_date' => '2026-12-26', // キッズパーク営業開始予定日（広告）
    'coupon_close_date' => '',          // 確定後に YYYY-MM-DD を設定してください。空欄では自動終了しません。
    'registration_limit_per_ip_hour' => 30,
];
