#!/bin/bash

# Create initial admin user with proper error handling
log_info "Creating admin user..."
cat > $PROJECT_DIR/create-admin.js << ADMINEOF
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createAdmin() {
  try {
    const hash = await bcrypt.hash(process.argv[2], 12);
    const user = await prisma.user.upsert({
      where: { username: '$ADMIN_USER' },
      update: {
        password: hash
      },
      create: {
        username: '$ADMIN_USER',
        password: hash,
        role: 'admin'
      }
    });
    console.log('Admin user created/updated successfully');
  } catch (error) {
    console.error('Error creating admin user:', error);
    process.exit(1);
  } finally {
    await prisma.\$disconnect();
  }
}

createAdmin();
ADMINEOF

cd $PROJECT_DIR && node create-admin.js "$ADMIN_PASSWORD" || log_error "Failed to create admin user"
rm $PROJECT_DIR/create-admin.js

# Install dependencies and build
log_info "Installing production dependencies..."
cd "$PROJECT_DIR" || log_error "Failed to enter project directory: $PROJECT_DIR"
npm ci --production=false

log_info "Building Next.js app..."
export NODE_OPTIONS="--max-old-space-size=1536"
npm run build