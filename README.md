Login
1.	User enters their username and password on the login page.
2.	The login request is sent to the API endpoint to verify credentials.
3.	If credentials are valid, a JWT (JSON Web Token) is generated and sent back to the user.
4.	If credentials are invalid, an error message is returned.
Accessing Protected Resources
1.	User uses the JWT to access protected resources.
2.	The API verifies the JWT.
3.	If the JWT is valid, the requested resource (like home page) is returned.
4.	If the JWT is invalid, an error message is returned.
Logout
1.	User clicks the logout button.
2.	The logout request is sent to the API endpoint to invalidate the JWT and destroy session tokens.
3.	The user is redirected to the login page.
 

Explanation of the Flowchart
1.	Login Flow:
o	User sends login request:
	URL: /api/login
	Method: POST
	DB Interaction: Check username and password
o	API verifies credentials:
	If valid:
	Generate SecurityToken
	Generate SessionIdentifier
	Generate JWT
	Return JWT to User
	If invalid:
	Return error

2.	Accessing Protected Resource:
o	User sends request to access resource:
	URL: /api/resource
	Method: GET
	Includes: JWT in Authorization header
o	API verifies JWT:
	DB Interaction: Check JWT validity
	If valid:
	Return requested resource
	If invalid:
	Return error

3.	Logout Flow:
o	User clicks logout button
o	JavaScript sends logout request:
	URL: /api/logout
	Method: POST
	Includes: JWT in Authorization header, loginName in body
o	API verifies JWT:
	DB Interaction: Check JWT validity
	If valid:
	Nullify SecurityToken
	Nullify SessionIdentifier
	Return success message
	Redirect user to login page
	If invalid:
	Return error
