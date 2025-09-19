# OFFICE-HUB
Integrated-Workplace-Service-Portal

A full-stack workplace management system built with Node.js, Express, MongoDB, and Socket.IO, designed to manage IT tickets, cleaning requests, canteen orders, and employee interactions in real-time.

This project includes:

Role-based dashboards for Employees, Admins, IT staff, Cleaning staff, and Canteen staff.

Real-time updates using Socket.IO for chat, notifications, and live order/ticket updates.

Secure authentication & session handling using express-session and bcryptjs.

Admin management tools for users, reports, analytics, and historical tracking.

Features

Authentication & Roles
Secure registration and login with hashed passwords.

Five predefined roles:

Employee

IT

Cleaning

Canteen

Admin

Role-based route protection and dashboard redirection.

IT Support Ticket Management
Employees can:

Submit IT issue tickets.

Track status (Pending, In Progress, Resolved).

Chat with IT staff for ticket resolution.

Provide ratings and reviews after completion.

IT Staff can:

Manage tickets in real-time.

Update ticket statuses.

Resolve tickets with notes.

Monitor ticket summary and analytics.

Cleaning Request Management
Employees can:

Submit cleaning requests (with desk/floor details).

Track live status and chat with cleaning staff.

Rate and review completed requests.

Cleaning staff can:

View, update, and complete requests.

Access resolved history and performance metrics.

Canteen Order Management
Employees can:

Place beverage/food orders.

Track order progress.

Canteen staff can:

View pending orders.

Mark orders as completed in real-time.

Monitor daily summary and history.

Admin Panel
Admins can:

Manage all users (create, edit, delete, view histories).

View global system analytics:

Live feed of latest activities (tickets, cleaning, orders).

Summary counts of active tasks and completed orders.

Track employee-specific histories:

Tickets submitted.

Cleaning requests.

Canteen orders & spend analytics.

Real-Time Features
Chat system for both IT tickets and cleaning requests.

Socket.IO-based notifications:

New ticket submission alerts.

Cleaning request notifications.

Order updates.

Live feed for Admin dashboard.

Tech Stack Category Technology Backend Framework Node.js, Express.js Database MongoDB (Mongoose ORM) Real-Time Updates Socket.IO Authentication express-session, bcryptjs Session Storage connect-mongo Frontend HTML, CSS, JS (served statically) Deployment Ready .env configuration support Installation & Setup

Clone the Repository

Install Dependencies npm install

Configure Environment Variables

Create a .env file in the project root:

PORT=3000 MONGO_URI=mongodb://localhost:27017/jc_nexus_hub

Run the Server npm start
The server will run at:

http://localhost:3000

Folder Structure JC-Nexus-Hub/ │ ├── index.html # Landing page ├── register.html # Registration page ├── employee-dashboard.html # Employee role dashboard ├── it-dashboard.html # IT staff dashboard ├── cleaning-dashboard.html # Cleaning staff dashboard ├── canteen-dashboard.html # Canteen staff dashboard ├── admin-dashboard.html # Admin dashboard │ ├── server.js # Main backend file (this file) ├── package.json ├── .env # Environment variables └── README.md

API Endpoints Authentication Method Endpoint Description POST /api/register Register new user POST /api/login Login user GET /api/user-info Get logged-in user's info GET /logout Logout user Employee Method Endpoint Description GET /api/employee/my-requests Get logged-in employee's requests POST /api/tickets Create new IT ticket POST /api/beverage/orders Place a canteen order POST /api/cleaning/requests Submit cleaning request IT Staff Method Endpoint Description GET /api/it/summary Get ticket summary GET /api/tickets/:status Fetch tickets by status POST /api/tickets/update-status Update ticket status POST /api/tickets/resolve Resolve ticket with note Cleaning Staff Method Endpoint Description GET /api/cleaning/summary Get cleaning summary GET /api/cleaning/list/:status Fetch cleaning requests by status POST /api/cleaning/update-status Update cleaning request status Canteen Staff Method Endpoint Description GET /api/canteen/summary Get order summary GET /api/canteen/orders/:status Fetch orders by status POST /api/canteen/orders/update-status Update order status Admin Method Endpoint Description GET /api/admin/users List all users POST /api/admin/users Create new user PUT /api/admin/users/:id Update user DELETE /api/admin/users/:id Delete user GET /api/admin/summary Global analytics summary Real-Time Events Socket.IO Events Event Name Description new-ticket Broadcast when new IT ticket is created ticket-updated Notify all clients of ticket status updates new-cleaning Broadcast when new cleaning request is submitted cleaning-updated Notify all clients of cleaning request updates new-order Notify canteen staff of new order canteen-updated Notify all clients of order updates send-chat-message Send IT ticket chat messages send-cleaning-message Send cleaning request chat messages Security

Password hashing: Using bcryptjs.

Session management: Using express-session with connect-mongo for persistence.

Role-based access control: Routes protected by middleware.

Prevents:

Unauthorized access.

Duplicate email or employee ID registration.

Admin self-deletion.

Future Improvements

Replace static frontend with React or Next.js for dynamic UI.

Implement email notifications for ticket and order updates.

Add report generation for admins (PDF/CSV exports).

Integrate payment gateway for canteen orders.

License

This project is licensed under the MIT License.

Author

Developed by Devraj Nayak,Piyush Khaneja

Integrated-Workplace-Service-Portal – Workplace Management System.
