**Enterprise Authentication Service**
A production-ready authentication service built with Node.js, Express, and PostgreSQL, designed to handle user management and provide robust, enterprise-grade security features for integration into any microservices architecture.


**Features**
* JWT Authentication: Secure access and refresh token management for stateless authentication
* Email Verification: User account activation via tokenised email links
* Secure Password Reset: Robust flow for forgotten passwords
* Role-Based Access Control (RBAC): Foundation for managing user permissions
* Rate Limiting: Prevents abuse and brute-force attacks
* Input Validation & Sanitisation: Ensures data integrity and security for all incoming requests
* Centralised Error Handling: Consistent and clear error responses across the API
* PostgreSQL with Prisma (ORM): Reliable and scalable data storage
* Environment-based Configuration: Easy management of settings for different environments
* Production Deployment Ready: Designed for cloud deployment (Railway/Render)



**Tech Stack**
* Backend: Node.js, Express.js
* Database: PostgreSQL
* Authentication: JWT (Access & Refresh Tokens), bcrypt (password hashing)
* Validation: express-validator
* Rate Limiting: express-rate-limit
* Email: Nodemailer
* ORM: Prisma
* Deployment: Railway/Render



**🚀 Quick Start**
Prerequisites
* Node.js (LTS version recommended)
* npm or Yarn
* PostgreSQL database instance


**Installation**
1. Clone the repository:git clone [YOUR_REPOSITORY_URL_HERE]
    cd enterprise-auth-service

2. Install dependencies:npm install
    yarn install

3. Set up Environment Variables: Create a .env file in the root of your project:PORT=3000
    DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DATABASE?schema=public"

    ACCESS_TOKEN_SECRET="YOUR_VERY_LONG_AND_RANDOM_ACCESS_TOKEN_SECRET"
    REFRESH_TOKEN_SECRET="YOUR_VERY_LONG_AND_RANDOM_REFRESH_TOKEN_SECRET"
    REFRESH_TOKEN_TTL_DAYS=30

    Email Service (for verification/password reset)
    EMAIL_HOST="smtp.example.com"
    EMAIL_PORT=587
    EMAIL_USER="your-email@example.com"
    EMAIL_PASS="your-email-password"
    EMAIL_FROM="no-reply@yourdomain.com"

    Frontend URL for email links
    FRONTEND_URL="http://localhost:5173"


**⚠️ Security Notes:**
ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET should be very long, random strings
Generate secrets using: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
Never commit your .env file to version control

4. Database Setup:# Run Prisma migrations
    npx prisma migrate dev --name init

    (Optional) Seed database
    npx prisma db seed

5. Start the Server:
    npm start or yarn start


The server will be running at http://localhost:3000 


**Quick Test**
Test your setup with a simple registration:
curl -X POST http://localhost:3000/api/auth/register \
-H "Content-Type: application/json" \
-d '{"email":"test@example.com","password":"TestPassword123!","fullname":"Test User"}'



**📚 API Documentation**
Base URL: http://localhost:3000/api/auth (development)
Authentication Flow
1. Register → POST /register → Get user account
2. Login → POST /login → Receive access + refresh tokens
3. Access Protected Routes → Include Authorization: Bearer <accesstoken> header
4. Refresh Token → POST /token → Get new access token when expired
5. Logout → DELETE /logout → Invalidate refresh token



**Endpoints**
1. Register User
POST /api/auth/register
Request Body:
{
  "email": "user@example.com",
  "password": "StrongPassword123!",
  "fullname": "John Doe"
}
Responses:
* 201 Created - Registration successful {  "message": "User registered successfully",  "user": {    "id": 1,    "email": "user@example.com",    "fullname": "John Doe"  }}
* 400 Bad Request - Invalid input or user exists
* 500 Internal Server Error - Server error


2. User Login
POST /api/auth/login
Request Body:
{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
Responses:
* 200 OK - Login successful {  "accesstoken": "eyJhbGciOiJIUzI...",  "refreshtoken": "eyJhbGciOiJIUzI...",  "message": "Login successful",  "user": {    "id": 1,    "email": "user@example.com",    "fullname": "John Doe"  }}
* 
* 401 Unauthorized - Invalid credentials
* 400 Bad Request - Missing required fields
* 500 Internal Server Error - Server error


3. Refresh Token
POST /api/auth/token
Request Body:
{
  "token": "eyJhbGciOiJIUzI..."
}
Responses:
* 200 OK - Tokens refreshed {  "accesstoken": "eyJhbGciOiJIUzI...",  "refreshtoken": "eyJhbGciOiJIUzI...",  "message": "Tokens refreshed successfully"}
* 401 Unauthorized - No refresh token provided
* 403 Forbidden - Invalid/expired refresh token
* 500 Internal Server Error - Server error


4. User Logout
DELETE /api/auth/logout
Request Body:
{
  "token": "eyJhbGciOiJIUzI..."
}
Responses:
* 200 OK - Logout successful {  "message": "Logout successful"}
* 
* 401 Unauthorized - No refresh token provided
* 403 Forbidden - Invalid token
* 500 Internal Server Error - Server error


5. User Logout From All Devices
DELETE /api/auth/logoutall

Responses:
* 200 OK - Logout successful {  "message": "Logged out from all devices"}
* 401 Unauthorized - No access token provided or token invalid
* 403 Forbidden - Invalid or expired access token
* 500 Internal Server Error - Server error



6. Protected Route Example
GET /api/auth/posts
Authorization: Bearer <accesstoken>
Responses:
* 200 OK - Access granted [  { "id": 1, "title": "My first post", "email": "user@example.com" },  { "id": 2, "title": "Another post", "email": "user@example.com" }]
* 401 Unauthorized - No token provided
* 403 Forbidden - Invalid or expired token
* 500 Internal Server Error - Server error



**🔐 Authentication Guide**
Using Access Tokens
Include the access token in the Authorization header for all protected requests:
// Example with fetch
fetch('http://localhost:3000/api/auth/posts', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  }
})


**Token Refresh Pattern**
Access tokens are short-lived. Implement this refresh pattern in your client:
// Pseudo-code for token refresh
if (response.status === 401) {
  // Try to refresh token
  const newTokens = await refreshAccessToken(refreshToken);
  if (newTokens) {
    // Retry original request with new token
    return retryRequest(originalRequest, newTokens.accesstoken);
  } else {
    // Refresh failed, redirect to login
    redirectToLogin();
  }
}

**🤝 Contributing**
1. Fork the repository
2. Create a feature branch: git checkout -b feature/amazing-feature
3. Make your changes and add tests
4. Commit your changes: git commit -m 'Add amazing feature'
5. Push to the branch: git push origin feature/amazing-feature
6. Open a Pull Request

**📄 License**
This project is licensed under the MIT License - see the LICENSE file for details.

**🆘 Troubleshooting**
Database connection issues:
* Ensure PostgreSQL is running
* Check your DATABASE_URL in .env
* Verify database exists and credentials are correct
Token errors:
* Ensure your token secrets are properly set in .env
* Check token hasn't expired
* Verify proper Authorization header format
Email service issues:
* Verify SMTP credentials in .env
* Check if less secure app access is enabled (Gmail)
* Test email connectivity separately
