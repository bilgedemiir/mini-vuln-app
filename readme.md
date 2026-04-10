# Secure Branch

This branch contains the fixed version of the application.

## Security improvements
- Parameterized SQL queries
- Output escaping (no `|safe`)
- Role-based access control for admin
- CSRF protection on POST forms
- Password hashing with bcrypt
- Secret key from environment

  ## Branches

- vulnerable: Contains intentionally vulnerable code for demonstration
- secure: Includes fixed and secure implementations
- master: Base version of the project
