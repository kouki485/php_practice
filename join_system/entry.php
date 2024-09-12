<?php
require_once("./dbconnect.php");  // データベース接続用のファイルを読み込み
session_start();  // セッションを開始

// セッションハイジャック対策としてセッションIDを再生成する
session_regenerate_id(true);

// CSRF（クロスサイトリクエストフォージェリ）攻撃を防ぐためにトークンを生成する関数
function generateToken() {
    // トークンがまだ生成されていなければ、新しいトークンを生成する
    if (empty($_SESSION['token'])) {
        // 32バイトのランダムデータを生成し、16進数にエンコード
        $_SESSION['token'] = bin2hex(random_bytes(32));
    }
    // 生成されたトークンを返す
    return $_SESSION['token'];
}

// POSTリクエストのCSRFトークンが正しいかを検証する関数
function validateToken($token) {
    // セッションにトークンが設定されているか確認し、トークンが一致するか確認する
    return isset($_SESSION['token']) && hash_equals($_SESSION['token'], $token);
}

// ユーザーの入力データを検証する関数
function validateInput($data) {
    // エラーを格納する配列を初期化
    $error = [];

    // メールアドレスが空かどうかを確認
    if (empty($data['email'])) {
        $error['email'] = "blank";  // エラーがある場合は "blank" エラーを設定
    }

    // パスワードが空かどうかを確認
    if (empty($data['password'])) {
        $error['password'] = "blank";  // エラーがある場合は "blank" エラーを設定
    }

    // エラーメッセージを返す（エラーがない場合は空の配列を返す）
    return $error;
}

// メールアドレスの重複を確認する関数
function checkDuplicateEmail($email, $db) {
    // SQL文をプリペアドステートメントで作成し、ユーザーのメールアドレスを確認
    $member = $db->prepare('SELECT COUNT(*) as cnt FROM members WHERE email = ?');
    // メールアドレスをプリペアドステートメントにバインドして実行
    $member->execute(array($email));
    // 結果を取得
    $record = $member->fetch();
    // メールアドレスがすでに存在するかを確認（0以上なら重複している）
    return $record['cnt'] > 0;
}

// HTMLエスケープ処理を行う関数
// ユーザー入力データを表示する際にHTMLタグとして解釈されないようにする（XSS対策）
function h($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

// POSTリクエストが送信されたか確認
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRFトークンが正しいかを確認
    if (!validateToken($_POST['token'])) {
        // トークンが無効な場合はエラーメッセージを表示して処理を終了
        die('Invalid CSRF token');
    }

    // ユーザーの入力データにエラーがないか確認
    $error = validateInput($_POST);

    // メールアドレスのエラーがなく、重複チェックを通過しなければ重複エラーを設定
    if (!isset($error['email']) && checkDuplicateEmail($_POST['email'], $db)) {
        $error['email'] = 'duplicate';
    }

    // エラーがない場合、次のページへ進む処理
    if (empty($error)) {
        // セッションにユーザーの入力データを保存する
        $_SESSION['join'] = $_POST;
        // 確認ページ（check.php）にリダイレクト
        header('Location: check.php');
        exit();
    }
}

// フォームに表示するためのCSRFトークンを生成
$token = generateToken();
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0,minimum-scale=1.0">
    <title>アカウント作成</title>
    <link href="https://unpkg.com/sanitize.css" rel="stylesheet"/>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="content">
        <!-- フォームの開始 -->
        <form action="" method="POST">
            <h1>アカウント作成</h1>
            <p>当サービスをご利用するために、次のフォームに必要事項をご記入ください。</p>
            <br>

            <!-- ユーザー名の入力フィールド -->
            <div class="control">
                <label for="name">ユーザー名</label>
                <!-- 入力された値を保持し、HTMLエスケープ処理を行う -->
                <input id="name" type="text" name="name" value="<?= isset($_POST['name']) ? h($_POST['name']) : ''; ?>">
            </div>

            <!-- メールアドレスの入力フィールド -->
            <div class="control">
                <label for="email">メールアドレス<span class="required">必須</span></label>
                <!-- 入力されたメールアドレスを保持し、HTMLエスケープ処理を行う -->
                <input id="email" type="email" name="email" value="<?= isset($_POST['email']) ? h($_POST['email']) : ''; ?>">
                <!-- メールアドレスのエラーメッセージを表示 -->
                <?php if (!empty($error["email"])): ?>
                    <p class="error">
                        <!-- メールアドレスが空の場合のエラーメッセージ -->
                        <?php if ($error['email'] === 'blank'): ?>
                            ＊メールアドレスを入力してください
                        <!-- メールアドレスが重複している場合のエラーメッセージ -->
                        <?php elseif ($error['email'] === 'duplicate'): ?>
                            ＊このメールアドレスはすでに登録済みです
                        <?php endif; ?>
                    </p>
                <?php endif; ?>
            </div>

            <!-- パスワードの入力フィールド -->
            <div class="control">
                <label for="password">パスワード<span class="required">必須</span></label>
                <!-- 入力されたパスワードを保持し、HTMLエスケープ処理を行う -->
                <input id="password" type="password" name="password" value="<?= isset($_POST['password']) ? h($_POST['password']) : ''; ?>">
                <!-- パスワードが空の場合のエラーメッセージを表示 -->
                <?php if (!empty($error["password"])): ?>
                    <p class="error">＊パスワードを入力してください</p>
                <?php endif; ?>
            </div>

            <!-- CSRFトークンをフォームに埋め込む -->
            <input type="hidden" name="token" value="<?= h($token) ?>">

            <!-- フォーム送信ボタン -->
            <div class="control">
                <button type="submit" class="btn">確認する</button>
            </div>
        </form>
    </div>
</body>
</html>
