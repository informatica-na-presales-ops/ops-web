To launch the project:

1. Copy `docker-compose.override-example.yml` to `docker-compose.override.yml` and edit as necessary.
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

1. Update the value for `org.opencontainers.image.version` in `Dockerfile`.
2. Run `docker-compose build` to build the image.
3. Run `docker image tag informaticanapresalesops.azurecr.io/ops-web:latest
   informaticanapresalesops.azurecr.io/ops-web:<version>` to apply the new version tag to the image.
4. Run `docker image push informaticanapresalesops.azurecr.io/ops-web:<version>` to push the new image to the registry.
