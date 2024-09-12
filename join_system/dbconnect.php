<?php
    try {
        // DSN（データソース名）に `charset=utf8mb4` を指定
        $db = new PDO("mysql:host=127.0.0.1;dbname=mydb;charset=utf8mb4", "root", "fellowstyle1");
    } catch (PDOException $e) {
        echo "データベースエラー: " . $e->getMessage();
    }
?>