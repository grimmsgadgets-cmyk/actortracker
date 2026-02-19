# Actor Tracker

A lightweight threat actor lookup tool that turns reporting into a clear
starting point for defensive review.

![App Screenshot](screenshots/updatedscreenshot.png)

------------------------------------------------------------------------

## Overview

Actor Tracker is a small web application that helps you:

-   Look up a known threat actor
-   See a concise summary of who they are
-   Review recent reporting highlights
-   Get a short list of practical defensive checks to start with

It is intended to provide an at-a-glance reference, not a full CTI
platform.

------------------------------------------------------------------------

## Requirements

Before starting, ensure you have:

-   A computer running Windows, macOS, or Linux
-   **Docker Desktop** installed and running\
    https://www.docker.com/products/docker-desktop

To verify Docker is installed:

    docker --version

If a version number appears, Docker is ready.

------------------------------------------------------------------------

## Setup Instructions

### 1. Clone the Repository

Using Git:

    git clone https://github.com/grimmsgadgets-cmyk/actortracker.git
    cd actortracker

Or download the ZIP from GitHub and open a terminal inside the extracted
folder.

------------------------------------------------------------------------

### 2. Build and Start the Application

From inside the project folder:

    docker compose up --build

This will:

-   Build the Docker image
-   Install dependencies inside the container
-   Start the web application

The first run may take a few minutes.

------------------------------------------------------------------------

### 3. Access the Application

Once the container is running, open your browser and go to:

    http://localhost:8000

If that does not load, check the terminal output for the correct port
number.

------------------------------------------------------------------------

## Stopping the Application

Press:

    CTRL + C

Then optionally clean up containers:

    docker compose down

------------------------------------------------------------------------

## Minimal Troubleshooting Checklist

If something does not work, check the following:

-   **Docker running?**\
    Ensure Docker Desktop is open and running.

-   **Port already in use?**\
    If you see a port error, another application may be using port 8000.

-   **Changes not appearing?**\
    Rebuild the container: docker compose down docker compose up --build

-   **Build failed?**\
    Scroll up in the terminal to read the exact error message.

------------------------------------------------------------------------

## Project Status

Early-stage and evolving.\
Expect iterative improvements and UI changes.
