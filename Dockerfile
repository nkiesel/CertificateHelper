# Use an appropriate base image for Java 21 JRE
FROM eclipse-temurin:21-jre-jammy

# Set a working directory
WORKDIR /app

# Copy the application JAR from the build output into the image
# The uberJar task produces a JAR with the 'uber' classifier.
# Example: certificate-helper-3.0.1-uber.jar
# Using a wildcard to match the version and project name.
COPY build/libs/*-uber.jar /app/app.jar

# Expose port 8080 (the port used by WebServer.kt)
EXPOSE 8080

# Specify the CMD to run the application's web server mode
CMD ["java", "-jar", "/app/app.jar", "serve"]
