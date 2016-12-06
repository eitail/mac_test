<!-- 
----2016-12-6---- 更新
第二次更新！
 -->
<?php
include './include/common.inc.php';
$password = 'lieshimima';
$username = 'lieshiadmin';
$password = md5(PASSWORD_KEY.$password);
$db->query("UPDATE ".DB_PRE."member SET password = '$password' WHERE username = '$username'");
$db->query("UPDATE ".DB_PRE."member_cache SET password = '$password' WHERE username = '$username'");
echo 'ok';
echo "aaaabbbbcccc";
?>