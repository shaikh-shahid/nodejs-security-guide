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

### Typecasting
JavaScript is a dynamic typed language i.e a value can be of any type. You can use the typecasting method to verify the type of data so that only the intended type of value should go into the database. For example, a user ID can only accept the number, there should be typecasting to ensure that the user ID should only be a number. For example, let's refer to the code we shown above.

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
    ['first_name',req.body.first_name, ,'id',Number(req.body.ID)],
    function(err, result) {
    //...
});
```
Did you notice the change? We used **Number(req.body.ID)** to ensure that ID is always the number. You can refer to [this beautiful](https://flaviocopes.com/javascript-casting/) article by a fellow blogger to understand typecasting in depth.

## Application Authentication and Authorization
Sensitive data such as passwords should be stored in the system in a secure way that malicious users don't misuse sensitive information. In this section, we will learn how to store and manage passwords which are quite generic, and pretty much every application has passwords in some way in their system.

### Password Hashing
Hashing is a function that generates a fixed-size string from input. The output from the hashing function cannot be decrypted hence it's "one-way" in nature. For data such as passwords, you must always use hashing algorithms to generate a hash version of the input password string which is a plaintext string. 

You might be wondering that if the hash is a one-way string then how come attackers gain access to passwords? 

Well, as I mentioned above, hashing takes an input string and generates a fixed-length output. So attackers take a reverse approach and they generate the hashes from the general password list, then they compare the hash with the hashes in your system to find the password. This attack is called **lookup tables** attack. 

This is the reason why you as an architect of the system must not allow generic used passwords in your system. To overcome this attack, you can something called **"salt"**. Salt is attached to the password hash to make it unique irrespective of the input. Salt has to be generated securely and randomly so that it is not predictable. The Hashing algorithm we suggest you is **BCrypt**. At the time of writing this article, Bcrypt has not been exploited and considered cryptographically secure. In Node.js, you can use **bcyrpt** node module to perform the hashing. 

Please refer to the example code below.

```javascript
const bcrypt = require('bcrypt');

const saltRounds = 10;
const password = "Some-Password@2020";

bcrypt.hash(
    password,
    saltRounds,
    (err, passwordHash) => {

    //we will just print it to the console for now
    //you should store it somewhere and never logs or print it
   
    console.log("Hashed Password:", passwordHash);
});
```
The **SaltRounds** function is the cost of the hash function. The higher the cost, the more secure hash would be generated. You should decide the salt based on the computing power of your server. Once the hash is generated for a password, the password entered by the user will be compared to the hash stored in the database. Refer to the code below for reference.

```javascript
const bcrypt = require('bcrypt');

const incomingPassword = "Some-Password@2020";
const existingHash = "some-hash-previously-generated"

bcrypt.compare(
    incomingPassword,
    existingHash,
    (err, res) => {
        if(res && res === true) {
            return console.log("Valid Password");
        }
        //invalid password handling here
        else {
            console.log("Invalid Password");
        }
});
```
### Password Storage

Whether you use the database, files to store passwords, you must not store a plain text version. As we studied above, you should generate the hash and store the hash in the system. I generally recommend using **varchar(255)** data type in case of a password. You can opt for an unlimited length field as well. If you are using **bcrypt** then you can use **varchar(60)** field because **bcrypt** will generate fixed size 60 character hashes.

### Authorization

A system with proper user roles and permission prevents malicious users to act outside of their permission. To achieve a proper authorization process, proper roles and permissions are assigned to each user so that they can do certain tasks and nothing more. In Node.js, you can use a famous module called [ACL](https://www.npmjs.com/package/acl2) to develop access control lists based authorization in your system. 

```javascript
const ACL = require('acl2');
const acl = new ACL(new ACL.memoryBackend());
// guest is allowed to view blogs
acl.allow('guest', 'blogs', 'view')
// check if the permission is granted
acl.isAllowed('joed', 'blogs', 'view', (err, res) => {
    if(res){
        console.log("User joed is allowed to view blogs");
    }
});
```
Checkout the acl2 documentation for more information and example code.
