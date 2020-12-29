# Node.js Security Guide

The one thing that developers tend to considers at the end of the development cycle is the “security” of the application. A secure application is not a luxury, it’s a necessity. You should consider the security of your application at every phase of the development such as architecture, design, code, and finally the deployment.

In this tutorial, we are going to learn ways to secure our Node.js application. Let’s dive in.

## Data Validation – Never Trust Your Users

You must always validate or sanitize the data coming from the user or other entity of the system. The bad validation or no validation at all is a threat to the working system and can lead to a security exploit. You should also escape the output. Let's learn how to validate the incoming data in Node.js. You can use a node module called **[validator](https://www.npmjs.com/package/validator)** to perform the data validation. For example.

```javascript
const validator = require('validator');
validator.isEmail('foo@bar.com'); //=> true
validator.isEmail('bar.com'); //=> false
```

You can also use a module called **[joi](https://www.npmjs.com/package/joi)** (recommended by Codeforgeek) to perform the data/schema validation. For example.

```javascript
  const joi = require('joi');
  try {
    const schema = joi.object().keys({
      name: joi.string().min(3).max(45).required(),
      email: joi.string().email().required(),
      password: joi.string().min(6).max(20).required()
    });

    const dataToValidate = {
        name: "Shahid",
        email: "abc.com",
        password: "123456",
    }
    const result = schema.validate(dataToValidate);
    if (result.error) {
      throw result.error.details[0].message;
    }    
  } catch (e) {
      console.log(e);
  }
```

## SQL Injection Attack
SQL injection is an exploit where malicious users can pass unexpected data and change the SQL queries. Let's understand with the example. Assume your SQL query looks like this: 

```sql
UPDATE users
    SET first_name="' + req.body.first_name +  '" WHERE id=1332;
```
In a normal scenario, you would expect that this query will look like this:
```sql
UPDATE users
    SET first_name = "John" WHERE id = 1332;
```
Now, if someone passes the first_name as the value shown below:
```
John", last_name="Wick"; --
```
Then, your SQL query will look like this:
```sql
UPDATE users
    SET first_name="John", last_name="Wick"; --" WHERE id=1001;
```
If you observe, the WHERE condition is commented out and now the query will update the users table and sets every user’s first name as “John” and last name as “Wick”. This will eventually lead to system failure and if your database has no backup, then you’re doomed.

### How to prevent SQL Injection attack
The most useful way to prevent SQL injection attacks is to sanitize input data. You can either validate every single input or validate using parameter binding. Parameter binding is mostly used by the developers as it offers efficiency and security. If you are using a popular ORM such as sequelize, hibernate, etc then they already provide the functions to validate and sanitize your data. If you are using database modules other than ORM such as [mysql for Node](https://codeforgeek.com/nodejs-mysql-tutorial/), you can use the escaping methods provided by the module. Let's learn by example. The codebase shown below is using **mysql** module for Node.

```javascript
var mysql = require('mysql');
var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'me',
  password : 'secret',
  database : 'my_db'
});
 
connection.connect();

connection.query(
    'UPDATE users SET ?? = ? WHERE ?? = ?',
    ['first_name',req.body.first_name, ,'id',1001],
    function(err, result) {
    //...
});
```
The double question mark is replaced with the field name and the single question mark is replaced with the value. This will make sure that input is safe. You can also use a stored procedure to increase the level of security but due to lack of maintainability developers tend to avoid using stored procedures. You should also perform the server-side data validation. I do not recommend you to validate each field manually, you can use modules like **[joi](https://www.npmjs.com/package/joi)**.


