# Attendance System

This repo contains backend code for an Online Attendance System developed as my personal project. This project aims to solve the problem of taking attendance in online mode during this covid era.

### How to run server

- Go to main directory and run `npm install`
- Install Nodemon by using the following command `npm i -g nodemon`
- Run Server by `nodemon app.js`

### Database Connection

- Create `.env` file in main directory
- Create a variable DATABASE and initiate it with your MongoDB connection uri string
  `DATABASE=<Your_MongoDB_Connection_URI>`  
  and port number  
  `PORT=<Port number>`

## Folder Structure

    .
    ├── controllers
    │   └── auth.js
    ├── models
    │   └── user.js
    |── node_modules
    |── routes
    |   └── auth.js
    ├── .env
    ├── .gitignore
    ├── app.js
    ├── package-lock.json
    ├── package.json
    |── Procfile
    └── README.md
