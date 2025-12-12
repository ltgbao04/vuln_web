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

$comments = getComments();
$commentCount = count($comments);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Comments - Community Blog</title>
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
        .comment {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            border-left: 4px solid #11998e;
        }
        .comment-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .comment-name { font-weight: bold; color: #11998e; }
        .comment-date { color: #999; font-size: 12px; }
        .comment-text { color: #333; line-height: 1.6; }
        .no-comments { text-align: center; color: #999; padding: 40px; }
        .no-comments a { color: #11998e; }
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
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary { background: #11998e; color: white; }
        .btn-primary:hover { background: #0d7a6e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌿 Community Blog</h1>
            <p>Read what our community has to say</p>
            <nav class="nav">
                <a href="index.php">✏️ Post Comment</a>
                <a href="comments.php">📖 View Comments</a>
                <a href="about.php">About</a>
                <a href="rules.php">Rules</a>
            </nav>
        </div>

        <div class="card">
            <h2>📝 All Comments</h2>
            
            <div class="stats">
                <span class="stats-text">Total comments:</span>
                <span class="stats-count"><?php echo $commentCount; ?></span>
            </div>

            <?php if (empty($comments)): ?>
                <div class="no-comments">
                    <p>😔 No comments yet.</p>
                    <p style="margin-top: 10px;"><a href="index.php">Be the first to share your thoughts!</a></p>
                </div>
            <?php else: ?>
                <?php foreach (array_reverse($comments) as $index => $c): ?>
                    <div class="comment">
                        <div class="comment-header">
                            <!-- VULNERABLE: Direct output without escaping - XSS will trigger here -->
                            <span class="comment-name"><?php echo $c['name']; ?></span>
                            <span class="comment-date"><?php echo $c['date']; ?></span>
                        </div>
                        <!-- VULNERABLE: Direct output without escaping - XSS will trigger here -->
                        <div class="comment-text"><?php echo $c['comment']; ?></div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

            <div style="margin-top: 20px; text-align: center;">
                <a href="index.php" class="btn btn-primary">✏️ Post a New Comment</a>
            </div>
        </div>
    </div>
</body>
</html>
