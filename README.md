To launch the project:

1. Copy `docker-compose.override-example.yaml` to `docker-compose.override.yaml` and edit as necessary.
2. Open a shell and change to the project directory.
3. Run `docker-compose up -d postgres` to start the database server.
4. Run `docker-compose up ops-web` to start the application server.
5. Browser to `localhost:8080` to view the application.

After making changes to the code, to see your changes:

1. In the shell where the application server is running, shut down the application by pressing `Ctrl+C`.
2. Run `docker-compose up ops-web` to restart the application.

To clean up containers at the end of the day:

1. If the application server is running, shut it down by pressing `Ctrl+C`.
2. Run `docker-compose down` to remove all containers for the project.

To publish a new version:

1. Update the value for `APP_VERSION` in `Dockerfile`.
2. Push all changes to GitHub.
3. Create a new release on GitHub for that version.
4. GitHub Actions will build a new container image.
