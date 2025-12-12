<?php
session_start();

// Simple file-based storage for comments
$commentsFile = 'comments.json';

function getComments() {
    global $commentsFile;
    if (file_exists($commentsFile)) {
        return json_decode(file_get_contents($commentsFile), true) ?: [];
    }
    return [];
}

function saveComment($name, $comment) {
    global $commentsFile;
    $comments = getComments();
    $comments[] = [
        'name' => $name,  // VULNERABLE: No sanitization
        'comment' => $comment,  // VULNERABLE: No sanitization
        'date' => date('Y-m-d H:i:s')
    ];
    file_put_contents($commentsFile, json_encode($comments));
}

function resetComments() {
    global $commentsFile;
    file_put_contents($commentsFile, '[]');
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['reset'])) {
        resetComments();
        header('Location: index.php?reset=success');
        exit;
    } elseif (isset($_POST['name']) && isset($_POST['comment'])) {
        saveComment($_POST['name'], $_POST['comment']);
        header('Location: index.php?posted=success');
        exit;
    }
}

$comments = getComments();
$commentCount = count($comments);
$posted = isset($_GET['posted']);
$wasReset = isset($_GET['reset']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community Blog - Share Your Thoughts</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .header h1 { color: #333; margin-bottom: 10px; }
        .header p { color: #666; }
        .nav { margin: 20px 0; }
        .nav a { color: #11998e; text-decoration: none; margin: 0 15px; font-weight: 500; }
        .nav a:hover { text-decoration: underline; }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .card h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #11998e; padding-bottom: 10px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: 500; }
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .form-group textarea { min-height: 100px; resize: vertical; }
        .form-group input:focus, .form-group textarea:focus { border-color: #11998e; outline: none; }
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-right: 10px;
        }
        .btn-primary { background: #11998e; color: white; }
        .btn-primary:hover { background: #0d7a6e; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-info { background: #17a2b8; color: white; text-decoration: none; display: inline-block; }
        .btn-info:hover { background: #138496; }
        .alert {
            padding: 15px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .button-group { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .stats {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .stats-text { color: #666; }
        .stats-count { font-size: 24px; font-weight: bold; color: #11998e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌿 Community Blog</h1>
            <p>Share your thoughts with our community</p>
            <nav class="nav">
                <a href="index.php">✏️ Post Comment</a>
                <a href="comments.php">📖 View Comments</a>
                <a href="about.php">About</a>
                <a href="rules.php">Rules</a>
            </nav>
        </div>

        <?php if ($posted): ?>
            <div class="alert alert-success">
                ✅ Your comment has been posted successfully! <a href="comments.php">View all comments</a>
            </div>
        <?php endif; ?>

        <?php if ($wasReset): ?>
            <div class="alert alert-info">
                🔄 All comments have been reset successfully!
            </div>
        <?php endif; ?>

        <div class="card">
            <h2>💬 Leave a Comment</h2>
            
            <div class="stats">
                <span class="stats-text">Total comments posted:</span>
                <span class="stats-count"><?php echo $commentCount; ?></span>
            </div>

            <form method="POST" action="index.php">
                <div class="form-group">
                    <label for="name">Your Name</label>
                    <input type="text" id="name" name="name" required placeholder="Enter your name">
                </div>
                <div class="form-group">
                    <label for="comment">Your Comment</label>
                    <textarea id="comment" name="comment" required placeholder="Share your thoughts..."></textarea>
                </div>
                <div class="button-group">
                    <button type="submit" class="btn btn-primary">📝 Post Comment</button>
                    <a href="comments.php" class="btn btn-info">📖 View All Comments</a>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>🔧 Admin Controls</h2>
            <p style="color: #666; margin-bottom: 15px;">Reset all comments to start fresh (useful for testing).</p>
            <form method="POST" action="index.php" onsubmit="return confirm('Are you sure you want to delete all comments?');">
                <input type="hidden" name="reset" value="1">
                <button type="submit" class="btn btn-danger">🗑️ Reset All Comments</button>
            </form>
        </div>
    </div>
</body>
</html>
