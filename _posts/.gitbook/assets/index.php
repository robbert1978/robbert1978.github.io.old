<?php
ini_set('max_execution_time', '300');
ini_set('display_errors', 0);
error_reporting(0);

include 'flag.php';

// Sinh ngẫu nhiên $len bytes
function urandom($len) {
    return file_get_contents('/dev/urandom', length: $len);
}

// Khởi tạo users và lưu vào database;
if (!is_file('db/users.db')) {
    $users = array(
        'umaru' => md5('umaru_hates_php'),
        'admin' => md5('admin.' . md5(urandom(3))),
    );
    file_put_contents('db/users.db', serialize($users));
}

// Login check
if (isset($_POST['username']) && isset($_POST['password'])) {
    $users = unserialize(file_get_contents('db/users.db'));

    $username = $_POST['username'];
    $password = $_POST['password'];
    echo $users["admin"];
    echo "\r\n";
    echo md5($password);
    echo "\r\n\r\n";
    while(true){
    	$x='admin.' . md5(urandom(3));
    	if(md5($x) == $users["admin"]){
    		echo "here: ";
    		echo $x;
    		break;
    	}
    }
    if ($users[$username] == md5($password)) {
        if ($username == 'admin') {
            $message = 'Here is your flag: ' . $flag;
        }
        else {
            $message = 'Hello ' . $username;
        }
    }
    else {
        $message = 'Wrong username or password!';
    }
}

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
}
?>
<!DOCTYPE html>
<html>
<head>
   <title>Login</title>
   <link href="static/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container" style="margin-top: 100px">  
        <form action="/index.php" method="POST" class="well" style="width: 240px; margin: 0px auto;"> 
            <img src="static/umaru.jpg" style="width: 100%;">
            <h3>Login</h3>
            <label>Username:</label>
            <input type="text" name="username" style="height: 30px" class="span3"/>
            <label>Password:</label>
            <input type="password" name="password" style="height: 30px" class="span3">
            <button type="submit" style="margin: 15px auto;" class="btn btn-primary">LOGIN</button>
            <?php if (isset($message)) { echo '<h5>' . $message .'</h5>'; } ?>
        </form>
    </div>
</body>
</html>
