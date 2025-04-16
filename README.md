# Unquantifiable Uncertainty Opinion Platform

A web platform for gathering and discussing opinions on issues related to "Unquantifiable Uncertainty".

## Features

- User authentication via Google OAuth
- Add new opinion entries
- Upvote/downvote existing entries
- Admin panel for content moderation
- Responsive, modern UI

## Deployment on Render

This application is configured for easy deployment on Render:

1. Push this repository to GitHub
2. Sign up for a [Render](https://render.com/) account
3. Create a new Web Service and select your GitHub repository
4. Render will automatically detect the configuration in `render.yaml`
5. Set the following environment variables in the Render dashboard:
   - `GOOGLE_CLIENT_ID`: Your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET`: Your Google OAuth client secret
   - `ADMIN_PASSWORD`: Password for the admin account
   - `SECRET_KEY`: A secure random string for session encryption
6. After deployment, add your Render domain (e.g., `https://your-app-name.onrender.com/login/google/callback`) to the authorized redirect URIs in your Google Cloud Console project

## Local Development Setup

1. Clone this repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Set up environment variables in a `.env` file (see `.env.example`)
6. Initialize the database: visit `http://127.0.0.1:5000/init-db` after starting the app
7. Run the application: `flask run`

## Environment Variables

Create a `.env` file with the following variables for local development:

```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_admin_password
```

For Google OAuth, you'll need to create credentials in the [Google Cloud Console](https://console.cloud.google.com/) and add `http://127.0.0.1:5000/login/google/callback` as an authorized redirect URI.
