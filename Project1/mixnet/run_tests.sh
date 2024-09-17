#/bin/bash

# Hosts 0 to 7
Hosts='ec2-54-204-80-46.compute-1.amazonaws.com ec2-52-55-243-158.compute-1.amazonaws.com ec2-3-83-189-213.compute-1.amazonaws.com ec2-54-221-159-198.compute-1.amazonaws.com ec2-3-208-19-12.compute-1.amazonaws.com ec2-3-94-128-29.compute-1.amazonaws.com ec2-44-202-152-202.compute-1.amazonaws.com ec2-44-204-80-24.compute-1.amazonaws.com'

key="Networks_SSH_Key.pem"
touch filename

run_the_test() {
        host_idx=0;
        for host in $Hosts
        do
                cmd="cd ~/15641_Project1/build; ./bin/node $1 9107 $host_idx $2 > ~/tmp.txt";
                ssh -i $key -f ubuntu@$host $cmd
                echo $cmd
                ((host_idx++))
        done
}

get_the_data() {
        cmd_recv=" cat ~/tmp.txt";
        for host in $Hosts
        do
                ssh -i $key ubuntu@$host $cmd_recv
                echo $cmd_recv
        done
}


sync_the_code() {
        cmd="cd ~/15641_Project1/build; git pull; make;";
        for host in $Hosts
        do
                ssh -i $key ubuntu@$host $cmd
                echo $cmd
        done
}