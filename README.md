# os-experiment-4
## 实验概述
* 本实验运用 CVE-2016-5195 漏洞（COW）漏洞，实现普通用户提权，并在根目录下留下root用户所创建的`success`文件。

 ## 操作流程
 * 直接 `./run.sh` 输入两次`mypassword`后会得到攻击后的根目录列表，若成功的话可看到`success` 文件。若偶遇不成功请重新来过。

 ## 大致原理
* 参考了dirtycow与FireFart的思路，运用`mmap`的`MAP_PRIVATE`特性，在两个线程竞态对Dirty页的创建和写时触发漏洞，使copy页还没产生时，另一个线程就往原本没有权限写的地方写了东西。
* 运用此原理修改`/etc/passwd`下root用户的密码，从而可以用`su -c`输入准备好的密码，作为超级用户完成一系列指令。
* 为了安全起见，在攻击开始时，将原本的`/etc/passwd`备份到`/tmp/passwd.bak`，并在创建完success文件后还原备份。

## 注意事项
* 在`4.4.25-exploit`版本的x86裸金属上测试过多次，除去少数一次失败（由于需要race来触发漏洞，所以并不保证一定能触发。），其余几次都能很快成功攻击操作系统，留下文件，并将系统恢复原样。

