# Providing database servers via Docker

Breakableflask can provide an SQL injection test bed using a number of different database engines (with only one engine being active for any one running iteration of the program).

The database servers can be setup in a normal way if you prefer, but its also possible to quickly spin up workable servers using docker, using the instructions below.

## Setup a PostgreSQL server

You can use Docker to create a suitable PostgreSQL server like so, using the official Docker image.

    docker run -d --name postgres -e POSTGRES_PASSWORD=password -p 127.0.0.1:5432:5432 postgres

You can now connect to the server using the credentials `postgres:password` on port `5432` at `127.0.0.1`.

Use the following to run the server after the initial launch. 

    docker start postgres


## Setup a MySQL server

You can use Docker to create a suitable MySQL server like so, using the official Docker image.

    docker run -d --name mysql -p 127.0.0.1:3306:3306 mysql/mysql-server

On first run you will need to perform a few steps to make the database usable.

First, run the following to get the temporary root password for the database, which you will need to immediately change.

    docker logs mysql 2>&1 | grep GENERATED | cut -d' ' -f 5

Now, run the `mysql` command within the container. Provide the password obtained in the previous step once prompted. 

    docker exec -it mysql mysql -uroot -p

Once in the mysql shell, enter the following commands to change the root password and create a new `mysql` user with a password of `password`.

    ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';
    CREATE USER 'mysql'@'%' IDENTIFIED BY 'password';
    grant all on *.* to 'mysql'@'%';
    quit

The server is now ready to use with your new credentials and is contactable using the new credentials on port `3306` at `127.0.0.1`.

Use the following to run the server after the initial launch. 

    docker start mysql


## Setup a MSSQL server

You can use Docker to create a suitable MSSQL server like so, using the official Docker image.

    docker run -d --name mssql -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=Password1!' -p 127.0.0.1:1433:1433 mcr.microsoft.com/mssql/server:2019-latest

You can now connect to the server using the credentials `sa:Password1!` on port `1433` at `127.0.0.1`.

Use the following to run the server after the initial launch. 

    docker start mssql
