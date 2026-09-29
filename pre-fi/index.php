<?php
require __DIR__ . '/config.php';

$page = $_GET['page'] ?? 'login';

if (!is_string($page) ||
    !in_array($page, ['login', 'register', 'welcome', 'logout'], true)) {
    redirectTo('login');
}

$error = '';
$name = '';
$email = '';

$notice = $_SESSION['notice'] ?? '';
unset($_SESSION['notice']);

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';

// Validate every submitted secure form, including logout.
if ($isPost && SECURE_MODE) {
    if (!hash_equals($_SESSION['csrf'], postValue('csrf'))) {
        http_response_code(403);
        exit('Form expired or invalid. Go back, reload, and try again.');
    }
}

// Logout must be submitted using the logout form.
if ($page === 'logout') {
    if (!$isPost) {
        redirectTo(isset($_SESSION['user']) ? 'welcome' : 'login');
    }

    clearLogin();
    redirectTo('login');
}

// Protect the welcome page on the server.
if ($page === 'welcome' && !isset($_SESSION['user'])) {
    redirectTo('login');
}

if (isset($_SESSION['user']) &&
    in_array($page, ['login', 'register'], true)) {
    redirectTo('welcome');
}

if ($isPost && $page === 'register') {
    $name = trim(postValue('name'));
    $email = strtolower(trim(postValue('email')));
    $password = postValue('password');
    $confirm = postValue('confirm');

    if ($name === '' || strlen($name) > 100) {
        $error = 'Enter a name between 1 and 100 bytes.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) ||
              strlen($email) > 190) {
        $error = 'Enter a valid email address up to 190 characters.';
    } elseif (strlen($password) < 12 || strlen($password) > 72) {
        $error = 'Use a password between 12 and 72 bytes.';
    } elseif ($password !== $confirm) {
        $error = 'Passwords do not match. Enter them again.';
    } else {
        try {
            if (SECURE_MODE) {
                // SECURE: store a password hash.
                $hash = password_hash($password, PASSWORD_DEFAULT);

                // SECURE: parameters are separate from SQL.
                $statement = $pdo->prepare(
                    "INSERT INTO $table (name, email, password)
                     VALUES (?, ?, ?)"
                );

                $statement->execute([$name, $email, $hash]);
            } else {
                // INTENTIONALLY INSECURE:
                // Plaintext password and raw SQL interpolation.
                $pdo->exec(
                    "INSERT INTO $table (name, email, password)
                     VALUES ('$name', '$email', '$password')"
                );
            }

            $_SESSION['notice'] = 'Account created. You can now log in.';
            redirectTo('login');
        } catch (PDOException $exception) {
            if (($exception->errorInfo[1] ?? 0) === 1062) {
                $error = 'Registration unavailable for this email. Try logging in.';
            } else {
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}

if ($isPost && $page === 'login') {
    $email = strtolower(trim(postValue('email')));
    $password = postValue('password');

    if ($email === '' || $password === '') {
        $error = 'Enter your email and password.';
    } elseif (strlen($email) > 190 || strlen($password) > 72) {
        $error = 'Email or password is incorrect.';
    } else {
        try {
            $user = false;
            $valid = false;

            if (SECURE_MODE) {
                $statement = $pdo->prepare(
                    "SELECT id, name, email, password
                     FROM $table WHERE email = ? LIMIT 1"
                );
                $statement->execute([$email]);
                $user = $statement->fetch();

                // Dummy hash makes missing-account checks less distinct.
                $dummyHash =
                    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';

                $matches = password_verify(
                    $password,
                    $user ? $user['password'] : $dummyHash
                );

                $valid = $user !== false && $matches;
            } else {
                // INTENTIONALLY INSECURE:
                // User input becomes part of the SQL query.
                $statement = $pdo->query(
                    "SELECT id, name, email, password
                     FROM $table
                     WHERE email = '$email'
                     AND password = '$password'
                     LIMIT 1"
                );

                $user = $statement->fetch();
                $valid = $user !== false;
            }

            if ($valid) {
                if (SECURE_MODE) {
                    session_regenerate_id(true);
                    $_SESSION['csrf'] = bin2hex(random_bytes(32));
                }

                // Never store the password in the session.
                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email']
                ];

                $_SESSION['last_activity'] = time();
                redirectTo('welcome');
            }

            $error = 'Email or password is incorrect.';
        } catch (PDOException $exception) {
            $error = 'Login failed. Please try again.';
        }
    }
}

$isRegister = $page === 'register';
$title = $page === 'welcome'
    ? 'Welcome'
    : ($isRegister ? 'Create account' : 'Log in');

$mode = SECURE_MODE ? 'Secure example' : 'Insecure example';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= escape($title) ?> | Member portal</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js" defer></script>
</head>
<body>
<main class="card">
    <header class="brand">
        <span class="brand-mark" aria-hidden="true">M</span>
        <span>Member portal</span>
    </header>

    <p class="mode"><?= escape($mode) ?></p>

    <?php if (!SECURE_MODE): ?>
        <p class="warning">
            Classroom demo only. Use fake accounts and passwords.
        </p>
    <?php endif; ?>

    <?php if ($page === 'welcome'): ?>
        <p class="eyebrow">YOUR ACCOUNT</p>
        <h1>Welcome,
            <?php
            // INSECURE mode deliberately demonstrates unsafe output.
            echo SECURE_MODE
                ? escape($_SESSION['user']['name'])
                : $_SESSION['user']['name'];
            ?>!
        </h1>

        <p class="intro">You are logged in.</p>

        <div class="account">
            <span>Email address</span>
            <strong><?= escape($_SESSION['user']['email']) ?></strong>
        </div>

        <form method="post" action="index.php?page=logout" novalidate>
            <input type="hidden" name="csrf"
                   value="<?= escape($_SESSION['csrf']) ?>">
            <button class="primary" type="submit">Log out</button>
        </form>

    <?php else: ?>
        <h1><?= escape($title) ?></h1>
        <p class="intro">
            <?= $isRegister
                ? 'Enter your details to get started.'
                : 'Enter your details to access your account.' ?>
        </p>

        <div class="feedback" aria-live="polite">
            <?php if ($error !== ''): ?>
                <p class="error" role="alert" tabindex="-1" id="form-error">
                    <?= escape($error) ?>
                </p>
            <?php elseif ($notice !== ''): ?>
                <p class="success"><?= escape($notice) ?></p>
            <?php endif; ?>
        </div>

        <form method="post"
              action="index.php?page=<?= $isRegister ? 'register' : 'login' ?>"
              novalidate>

            <input type="hidden" name="csrf"
                   value="<?= escape($_SESSION['csrf']) ?>">

            <?php if ($isRegister): ?>
                <label for="name">Full name</label>
                <input id="name" name="name" type="text"
                       autocomplete="name" maxlength="100"
                       value="<?= escape($name) ?>" required>
            <?php endif; ?>

            <label for="email">Email address</label>
            <input id="email" name="email" type="email"
                   autocomplete="username" maxlength="190"
                   value="<?= escape($email) ?>" required>

            <label for="password">Password</label>
            <div class="password-row">
                <input id="password" name="password" type="password"
                       autocomplete="<?= $isRegister
                           ? 'new-password' : 'current-password' ?>"
                       <?= $isRegister ? 'aria-describedby="password-help"' : '' ?>
                       required>
                <button type="button" class="toggle"
                        data-toggle="password"
                        aria-controls="password"
                        aria-label="Show password"
                        aria-pressed="false" hidden>Show</button>
            </div>

            <?php if ($isRegister): ?>
                <small id="password-help">
                    Use 12–72 bytes. English letters, numbers, and symbols
                    each count as one byte.
                </small>

                <label for="confirm">Confirm password</label>
                <div class="password-row">
                    <input id="confirm" name="confirm" type="password"
                           autocomplete="new-password" required>
                    <button type="button" class="toggle"
                            data-toggle="confirm"
                            aria-controls="confirm"
                            aria-label="Show confirmation password"
                            aria-pressed="false" hidden>Show</button>
                </div>
            <?php endif; ?>

            <button type="submit" class="primary">
                <?= $isRegister ? 'Create account' : 'Log in' ?>
            </button>
        </form>

        <p class="footer">
            <?php if ($isRegister): ?>
                Already have an account?
                <a href="index.php?page=login">Log in</a>
            <?php else: ?>
                New here?
                <a href="index.php?page=register">Create an account</a>
            <?php endif; ?>
        </p>
    <?php endif; ?>
</main>
</body>
</html>