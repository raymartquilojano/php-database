<?php
session_start();

$db = new PDO('sqlite:' . __DIR__ . '/tasks.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


$db->exec("CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task TEXT NOT NULL
)");


if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['task'])) {
    $task = filter_input(INPUT_POST, 'task', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if (!empty($task)) {
        $stmt = $db->prepare("INSERT INTO tasks (task) VALUES (:task)");
        $stmt->bindParam(':task', $task);
        $stmt->execute();
    }

    if (isset($_POST['remember'])) {
        setcookie('remember_user', 'true', time() + (7 * 24 * 60 * 60)); 
    } else {
        setcookie('remember_user', '', time() - 3600);
    }
    header("Location: index.php");
    exit();
}


if (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['id'])) {
    $id = (int) $_GET['id'];
    $stmt = $db->prepare("DELETE FROM tasks WHERE id = :id");
    $stmt->bindParam(':id', $id);
    $stmt->execute();
    header("Location: index.php");
    exit();
}

if (isset($_GET['action']) && $_GET['action'] == 'logout') {
   
    $_SESSION = [];
    
    
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }

   
    session_destroy();
    
    
    setcookie('remember_user', '', time() - 3600, '/');
    
   
    header("Location: index.php");
    exit();
}


$keyword = '';
$filtered_tasks = [];
if (isset($_GET['filter_keyword'])) {
    $keyword = filter_input(INPUT_GET, 'filter_keyword', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if (!empty($keyword)) {
        $stmt = $db->prepare("SELECT * FROM tasks WHERE task LIKE :keyword");
        $stmt->bindValue(':keyword', '%' . $keyword . '%');
    } else {
        $stmt = $db->prepare("SELECT * FROM tasks");
    }
} else {
    $stmt = $db->prepare("SELECT * FROM tasks");
}
$stmt->execute();
$filtered_tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);

$greeting = isset($_COOKIE['remember_user']) ? "Welcome back!" : "Welcome!";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>To-Do List with Cookies and SQLite</title>
    <style>
        table {
            border: 1px solid black;
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            padding: 5px;
        }
    </style>
</head>
<body>
    <h1><?php echo $greeting; ?></h1>
    <h2>My To-Do List</h2>

    <!-- Form to add tasks -->
    <form action="index.php" method="POST">
        <input type="text" name="task" placeholder="Enter a new task" required>
        <input type="checkbox" name="remember" value="1"
            <?php echo isset($_COOKIE['remember_user']) ? 'checked' : ''; ?>> Remember Me<br>
        <input type="submit" value="Add Task">
    </form>

    <!-- Form to filter tasks by keyword -->
    <form action="index.php" method="GET">
        <input type="text" name="filter_keyword" placeholder="Search tasks" 
               value="<?php echo htmlspecialchars($keyword); ?>">
        <input type="submit" value="Filter Tasks">
    </form>

    <!-- Display tasks in a table -->
    <table>
        <tr>
            <th>Task</th>
            <th>Action</th>
        </tr>
        <?php if (!empty($filtered_tasks)): ?>
            <?php foreach ($filtered_tasks as $task): ?>
                <tr>
                    <td><?php echo htmlspecialchars($task['task']); ?></td>
                    <td><a href="index.php?action=delete&id=<?php echo $task['id']; ?>">[Delete]</a></td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr>
                <td colspan="2">No tasks found. Add a new task or adjust your search!</td>
            </tr>
        <?php endif; ?>
    </table>

    <br>
    <!-- Logout link -->
    <a href="index.php?action=logout">Logout</a>
</body>
</html> 
