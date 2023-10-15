#  Jira 漏洞分析

##  1.安装

- 下载jira

- 注册的信息

  atlassian 官网注册信息，获取临时license

  wangsz052@126.com   AtlShine289463

  - 通过容器的方式下载jira

  ```txt
   docker pull atlassian/jira-software:8.13.17
   
   docker run -d -p 900:8080 -p 8000:8000 --name jira-software -v /etc/localtime:/etc/localtime -e JVM_SUPPORT_RECOMMENDED_ARGS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000"  cptactionhank/atlassian-jira-software:8.13.17 
   
   -e JVM_SUPPORT_RECOMMENDED_ARGS="-agentlib:jdwp=transport=dt_socket,server=y,s
  uspend=n,address=*:8000"
  ```

- 下载mysql 数据库以及初始化

  ```
  docker pull mysql:5.7
  初始化docker
  docker run --name mysql-jira --restart always -p 3366:3306 -e MYSQL_ROOT_PASSWORD=3er4#ER$ -e MYSQL_DATABASE=jira -e MYSQL_USER=jira -e MYSQL_PASSWORD=3er4#ER$ -d mysql:5.7
  初始化数据库
  CREATE DATABASE jira CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
  	GRANT ALL on jira.* TO 'jira'@'%' IDENTIFIED BY '3er4#ER$';
  	flush privileges;
  ```

