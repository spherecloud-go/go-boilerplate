# Go Gin API Boilerplate Generator

This script automates the creation of a boilerplate Go project for building REST APIs using the Gin framework. It sets up a scalable project structure with common features like:

*   **Gin Framework:** For HTTP routing and request handling.
*   **GORM:** For ORM and database interaction (defaults to PostgreSQL).
*   **JWT Authentication:** For securing API endpoints.
*   **Request Validation:** Using `go-playground/validator`.
*   **Database Migrations:** Using `golang-migrate/migrate`.
*   **Environment Configuration:** Using `.env` files via `godotenv`.
*   **Makefile:** For common development tasks (build, run, migrate, etc.).
*   **Scalable Project Structure:** Organizes code into `cmd`, `internal` (with sub-packages like `api`, `auth`, `config`, `database`, `models`, `repositories`, `services`).
*   **Basic CRUD Example:** Includes a "Resource" model with CRUD operations.

## Prerequisites

Before running the script, ensure you have the following installed:

1.  **Go:** Version 1.18 or higher.
2.  **Git:** For version control (optional but recommended).
3.  **Bash Shell:** The script is written for Bash.
4.  **(Optional but Recommended for `make migrate-*` commands) `migrate` CLI:**
    ```bash
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
    ```
    Ensure `$GOPATH/bin` (or `$GOBIN`) is in your system's `PATH`.

## How to Use the Generator Script

1.  **Download the Script:**
    Save the script content (from the previous response) to a file, for example, `create-go-gin-api.sh`.

2.  **Make it Executable:**
    ```bash
    chmod +x create-go-gin-api.sh
    ```

3.  **Run the Script:**
    ```bash
    ./create-go-gin-api.sh
    ```
    The script will prompt you to enter a project name (which will also be used as the Go module name). For example:
    *   `my-awesome-api` (for a local project)
    *   `github.com/yourusername/my-awesome-api` (if you plan to host it on GitHub)

    The script will then:
    *   Create a new directory with the base name of your project.
    *   Initialize a Go module.
    *   Create the entire project directory structure.
    *   Generate all necessary Go files, `Makefile`, `.gitignore`, `.env.example`, and initial migration files.
    *   Fetch Go module dependencies.

## Project Structure

The generated project will have the following structure:
```bash
your-project-name/
├── cmd/
│ └── api/
│ └── main.go # Application entry point
├── internal/
│ ├── api/
│ │ ├── handlers/ # HTTP handlers
│ │ ├── middleware/ # Custom middleware (e.g., auth)
│ │ ├── routes/ # Route definitions
│ ├── auth/ # Authentication logic (JWT, password hashing)
│ ├── config/ # Configuration loading
│ ├── database/ # Database connection, GORM setup, migration runner
│ ├── models/ # GORM models and request/response DTOs
│ ├── repositories/ # Data access layer
│ └── services/ # Business logic layer
├── migrations/ # SQL migration files (e.g., 000001_create_users_table.up.sql)
├── .env.example # Example environment variables
├── .gitignore
├── go.mod
├── go.sum
└── Makefile
```

## Getting Started with the Generated Project

After the script successfully creates your project:

1.  **Navigate to the Project Directory:**
    ```bash
    cd your-project-name
    ```

2.  **Configure Environment Variables:**
    Copy the example environment file and edit it with your actual settings:
    ```bash
    cp .env.example .env
    nano .env  # Or use your preferred editor
    ```
    Pay close attention to `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, and `JWT_SECRET_KEY`.

3.  **Set up Your Database:**
    Ensure you have a PostgreSQL database server running. Create a database and user that match the credentials you specified in your `.env` file.

4.  **Run Database Migrations:**
    The `Makefile` provides a convenient way to run migrations using the `migrate` CLI.
    *   **Important:** The `migrate` CLI needs a database connection string (`DB_URL`). The Makefile attempts to construct this. For it to work correctly, ensure your `.env` file is properly configured. You might need to `export` the variables from your `.env` file into your current shell session before running `make migrate-up` if your `.env` file doesn't use the `export VAR=value` format:
        ```bash
        # Example of sourcing .env variables (adjust if your .env has comments or empty lines)
        export $(grep -v '^#' .env | xargs)

        # Then run migrations
        make migrate-up
        ```
    *   If you encounter issues, ensure the `DB_URL` in the `Makefile` (or your environment) is correct for the `migrate` CLI format (e.g., `postgres://user:password@host:port/dbname?sslmode=disable`).

5.  **Run the Application:**
    ```bash
    make run
    ```
    The API server will start, typically on `http://localhost:8080` (or the port specified in `.env`).

## Makefile Commands

The generated `Makefile` includes several useful commands:

*   `make run`: Runs the application using `go run`.
*   `make build`: Builds the application binary.
*   `make clean`: Removes the built binary.
*   `make test`: Runs tests (you'll need to write them!).
*   `make migrate-up`: Applies all pending "up" migrations.
*   `make migrate-down`: Rolls back the last applied migration.
*   `make migrate-create NAME=<migration_name>`: Creates new up/down migration SQL files (e.g., `make migrate-create NAME=add_new_feature_table`).
*   `make help`: Displays a list of available commands and important notes.

## Key Features and Design Choices

*   **Dependency Injection (Manual):** Dependencies (like repositories and services) are typically instantiated in `routes.go` or `main.go` and passed down.
*   **Layered Architecture:**
    *   **Handlers:** Process HTTP requests and responses.
    *   **Services:** Contain business logic, orchestrate repository calls.
    *   **Repositories:** Abstract database interactions.
*   **DTOs (Data Transfer Objects):** Defined in `internal/models/` for request binding and response structuring (e.g., `UserRegisterRequest`, `CreateResourceRequest`).
*   **Validation:** Struct tags (`binding:"required"`) are used with Gin's built-in validator.
*   **JWT:** Stored in an `Authorization: Bearer <token>` header. Middleware validates it and makes claims available in the Gin context.
*   **GORM Soft Deletes:** Models include `gorm.DeletedAt` for enabling soft delete functionality.
*   **CORS:** A basic permissive CORS middleware is included in `routes.go`. Adjust as needed for your security requirements.

## Customization and Further Development

*   **Database Driver:** While PostgreSQL is the default, you can adapt GORM and `golang-migrate` to use other databases (MySQL, SQLite, etc.) by changing the drivers and DSNs.
*   **Add More Models/CRUDs:** Follow the pattern of `User` and `Resource` to add more entities to your API.
*   **Implement Tests:** Write unit and integration tests for your handlers, services, and repositories.
*   **Logging:** Enhance logging with a structured logging library (e.g., `zerolog`, `logrus`).
*   **Error Handling:** Implement more sophisticated global error handling and consistent error responses.
*   **Swagger/OpenAPI:** The `main.go` and handler files include `godoc` comments that can be used with `swaggo/swag` to generate OpenAPI documentation. Uncomment the Swagger-related lines in `routes.go` and run `swag init` after installing the `swag` CLI.
*   **Containerization:** Add a `Dockerfile` to containerize your application.

## Troubleshooting

*   **`migrate` CLI issues:**
    *   Ensure the `migrate` CLI is installed and in your `PATH`.
    *   Verify that `DB_URL` is correctly set in your environment or that the Makefile can derive it from your `.env` file. The `DB_URL` format is specific to the `migrate` tool.
    *   Check database connectivity and permissions for the user defined in `.env`.
*   **Go module path issues:** If you use a simple project name (e.g., `myapi`) and later want to push it to a VCS like GitHub, you might need to update the module path in `go.mod` and all import statements. It's often easier to start with the full module path (e.g., `github.com/username/myapi`) if you intend to host it.
*   **`.env` not loading:** The Go application uses `godotenv` to load `.env`. The `Makefile`'s `migrate-*` commands rely on `DB_URL` being in the environment; you might need to `source` your `.env` file manually for `make` if it doesn't use `export`.

---

**Note: This generator scripts does not format the code during initial setup, so you might have to manually format all the files yourself.**

This generator provides a starting point. Feel free to modify and extend it to fit your specific project needs!