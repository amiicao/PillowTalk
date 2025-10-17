# Use an official Node.js runtime as the base image
FROM node:22-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install production dependencies
RUN npm install --production

# Copy the rest of the app source code
COPY . .

# Expose port 3001 to the outside world
EXPOSE 3001

# Start the app
CMD ["npm", "start"]
