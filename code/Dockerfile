# Use the official NGINX image as a base
FROM nginx:alpine

# Set your name as an environment variable
ENV NAME="Ruslan"

# Copy custom HTML file to the default NGINX static files directory
COPY index.html /usr/share/nginx/html/index.html
COPY COMMITLogo.png /usr/share/nginx/html/CommitLogo.png

# Expose port 80 for web access
EXPOSE 80

# Start NGINX (logging is enabled by default in NGINX)
CMD ["nginx", "-g", "daemon off;"]